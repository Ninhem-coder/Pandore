"""Routes Vanitas — /api/vanitas/* (agents, commandes, terminal, conformité, EOL, alertes,
groupes, installeurs, paquets agent, source GitHub, journal d'activité). Proxy vers le serveur
Vanitas (vanitas/client.py). Les profils (/api/vanitas/profiles) vivent dans routers/auth.py
(gestion de permissions, admin-only) ; /api/vanitas/cve-avis dans routers/defender.py (module
defender/anssi.py). Déplacé de api_server.py le 2026-09-12."""
import io

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from pydantic import BaseModel

from api_common import IdPath, VANITAS_ALERT_STALE_HOURS
from auth import require_vanitas_any, require_vanitas_read, require_vanitas_write
from common import history
from common.config import VANITAS_AGENT_SERVER_URL, VANITAS_SERVER_URL
from device_overview import get_device_overview
from vanitas import alert_state as vanitas_alert_state
from vanitas import client as vanitas_client
from vanitas import eol as vanitas_eol
from vanitas import github_installer as vanitas_github_installer

router = APIRouter()


class QueueCommandBody(BaseModel):
    command_type: str
    installer_id: str | None = None
    agent_package_id: str | None = None
    # Journal d'événements Windows à la demande (2026-09-16) — dict libre transmis tel quel au
    # serveur Vanitas, qui porte seul la validation réelle (canaux connus, période cohérente,
    # plafond d'événements) ; Pandore ne fait ici que relayer.
    event_log_query: dict | None = None
    # Jalon "confinement" (2026-09-17) — référence l'alerte "activité suspecte" déclenchante,
    # requise pour "kill_process", optionnelle pour "isolate_network" ; Pandore ne fait que
    # relayer, l'extraction PID/nom de process vit côté serveur Vanitas.
    event_id: str | None = None


@router.get("/api/vanitas/agents")
def vanitas_agents(_perm: None = Depends(require_vanitas_read("postes"))):
    return vanitas_client.list_agents()


@router.get("/api/vanitas/agents/{agent_id}")
def vanitas_agent_inventory(
    agent_id: str = IdPath("Identifiant de l'agent Vanitas"),
    _perm: None = Depends(require_vanitas_read("postes")),
):
    return vanitas_client.get_agent_inventory(agent_id=agent_id)


@router.get("/api/vanitas/agents/{agent_id}/vulnerabilities")
def vanitas_agent_vulnerabilities(
    agent_id: str = IdPath("Identifiant de l'agent Vanitas"),
    _perm: None = Depends(require_vanitas_read("postes")),
):
    return vanitas_client.get_agent_vulnerabilities(agent_id=agent_id)


@router.get("/api/vanitas/agents/{agent_id}/commands")
def vanitas_agent_commands(
    agent_id: str = IdPath("Identifiant de l'agent Vanitas"),
    _perm: None = Depends(require_vanitas_read("postes")),
):
    return vanitas_client.get_agent_commands(agent_id=agent_id)


@router.post("/api/vanitas/agents/{agent_id}/commands")
def vanitas_queue_command(
    body: QueueCommandBody, request: Request, agent_id: str = IdPath("Identifiant de l'agent Vanitas")
):
    # Mettre en file N'IMPORTE QUELLE commande cible un poste et mute son état : exige "postes"
    # en écriture. Les commandes à blast radius supérieur exigent EN PLUS le module qui les
    # possède conceptuellement (vérifié ICI, pas via un Depends() séparé, car seuls quelques
    # types sont concernés). Durci par l'audit du 2026-09-17 (finding #2) : `fetch_event_log` et
    # `uninstall_agent` restaient au seul niveau "postes:write" alors qu'ils exfiltrent le journal
    # Security / suppriment l'agent — désormais alignés sur le module qui les possède.
    require_vanitas_write("postes")(request)
    if body.command_type == "start_shell_session":
        # PowerShell interactif SYSTEM — le module "terminal" lui est dédié.
        require_vanitas_write("terminal")(request)
    elif body.command_type in ("install_application", "update_agent", "uninstall_agent"):
        # Cycle de vie du binaire agent + installeurs arbitraires SYSTEM — module "applications".
        # `uninstall_agent` (retrait total de l'agent = perte de gestion ET de visibilité sécurité
        # du poste) rejoint ses jumeaux `install_application`/`update_agent` plutôt que de rester
        # au niveau "postes:write" de base (audit 2026-09-17, finding #2).
        require_vanitas_write("applications")(request)
    # Confinement (tuer un process / couper le réseau) ET extraction du journal Security à la
    # demande : domaine "Activités suspectes" (investigation sécurité) — `fetch_event_log` y est
    # rattaché car il exfiltre le journal Security d'un poste, une capacité d'investigation, pas
    # un simple geste d'inventaire (audit 2026-09-17, finding #2).
    elif body.command_type in ("kill_process", "isolate_network", "lift_isolation", "fetch_event_log"):
        require_vanitas_write("activites_suspectes")(request)
    # `force_reboot` reste au seul niveau "postes:write" VOLONTAIREMENT : son unique déclencheur
    # UI est le bouton "Forcer le redémarrage" de la page "Mises à jour Vanitas", elle-même une
    # page du module "postes" — l'y rattacher est cohérent, l'élever casserait ce parcours. Le
    # redémarrage est par ailleurs per-poste (une commande par agent_id), pas une action
    # fleet-wide en un appel.
    return vanitas_client.queue_command(
        agent_id=agent_id,
        command_type=body.command_type,
        installer_id=body.installer_id,
        agent_package_id=body.agent_package_id,
        event_log_query=body.event_log_query,
        event_id=body.event_id,
        actor=request.state.user["username"],
    )


@router.get("/api/vanitas/commands")
def vanitas_commands(_perm: None = Depends(require_vanitas_read("postes"))):
    return vanitas_client.list_commands()


@router.get("/api/vanitas/vulnerabilities/top")
def vanitas_top_vulnerabilities(limit: int = 5, _perm: None = Depends(require_vanitas_any)):
    return vanitas_client.get_top_vulnerabilities(limit=limit)


@router.get("/api/vanitas/history")
def vanitas_history(_perm: None = Depends(require_vanitas_any)):
    """Tendance quotidienne du parc Vanitas (jalon 2026-09-17) — même fichier d'historique que
    `/api/history` (calculé par `api_server.py::_take_history_snapshot`, domaine `vanitas`), mais
    on ne renvoie ICI que la date + le point Vanitas : un profil scopé Vanitas n'a pas à recevoir
    les agrégats Intune/Defender. `require_vanitas_any` (widget d'overview, comme
    `/vulnerabilities/top` juste au-dessus). Les jours antérieurs à ce jalon n'ont pas de point
    `vanitas` (valeur `None`) — un trou en début de courbe, géré côté frontend."""
    return [{"date": e.get("date"), "vanitas": e.get("vanitas")} for e in history.get_history()]


@router.delete("/api/vanitas/agents/{agent_id}")
def vanitas_remove_agent(
    request: Request,
    agent_id: str = IdPath("Identifiant de l'agent Vanitas"),
    _perm: None = Depends(require_vanitas_write("postes")),
):
    return vanitas_client.remove_agent(agent_id=agent_id, actor=request.state.user["username"])


# ── "Ajouter un poste" (2026-09-11) — génère un token d'enrôlement. Même tier que
# `vanitas_remove_agent` (module "postes" en écriture) : générer un token permet d'enrôler
# n'importe quel poste avec un agent SYSTEM.
@router.post("/api/vanitas/enrollment-tokens")
def vanitas_create_enrollment_token(
    request: Request,
    _perm: None = Depends(require_vanitas_write("postes")),
):
    return vanitas_client.create_enrollment_token(actor=request.state.user["username"])


# Route de LECTURE (donc `require_vanitas_read`) : deux valeurs pour pré-remplir le champ URL
# de la page dès l'ouverture — `server_url` (VANITAS_AGENT_SERVER_URL, poste distant, si
# configuré) et `same_machine_url` (VANITAS_SERVER_URL, toujours connue, cas le plus fréquent).
@router.get("/api/vanitas/enrollment-defaults")
def vanitas_enrollment_defaults(_perm: None = Depends(require_vanitas_read("postes"))):
    return {"server_url": VANITAS_AGENT_SERVER_URL, "same_machine_url": VANITAS_SERVER_URL}


# ── Terminal PowerShell interactif (jalon 9) — relaie les routes "dashboard" du serveur Vanitas
# (X-Shell-Token attaché par vanitas/client.py). Consultation → "terminal" en lecture ;
# piloter (input/stop) → écriture.
class ShellInputBody(BaseModel):
    line: str


@router.get("/api/vanitas/agents/{agent_id}/shell/sessions/latest")
def vanitas_shell_latest_session(
    agent_id: str = IdPath("Identifiant de l'agent Vanitas"),
    _perm: None = Depends(require_vanitas_read("terminal")),
):
    return vanitas_client.get_latest_shell_session(agent_id=agent_id)


@router.get("/api/vanitas/shell/sessions/{session_id}")
def vanitas_shell_session(
    session_id: str = IdPath("Identifiant de session de terminal"),
    _perm: None = Depends(require_vanitas_read("terminal")),
):
    return vanitas_client.get_shell_session(session_id=session_id)


@router.get("/api/vanitas/shell/sessions/{session_id}/events")
def vanitas_shell_session_events(
    session_id: str = IdPath("Identifiant de session de terminal"),
    since_id: int = 0,
    _perm: None = Depends(require_vanitas_read("terminal")),
):
    return vanitas_client.get_shell_session_events(session_id=session_id, since_id=since_id)


@router.post("/api/vanitas/shell/sessions/{session_id}/input")
def vanitas_shell_send_input(
    body: ShellInputBody,
    session_id: str = IdPath("Identifiant de session de terminal"),
    _perm: None = Depends(require_vanitas_write("terminal")),
):
    return vanitas_client.send_shell_input(session_id=session_id, line=body.line)


@router.post("/api/vanitas/shell/sessions/{session_id}/stop")
def vanitas_shell_stop(
    session_id: str = IdPath("Identifiant de session de terminal"),
    _perm: None = Depends(require_vanitas_write("terminal")),
):
    return vanitas_client.stop_shell_session(session_id=session_id)


# ── Conformité (jalon 11) — le CATALOGUE COMPLET (avec `script_content`, du code exécuté en
# SYSTEM) exige "conformite" en ÉCRITURE même en lecture ; le résumé (sans script) exige la
# lecture.
class CreateComplianceRuleBody(BaseModel):
    name: str
    script_content: str


class UpdateComplianceRuleBody(BaseModel):
    name: str | None = None
    script_content: str | None = None
    enabled: bool | None = None


@router.get("/api/vanitas/compliance/rules/summary")
def vanitas_compliance_rules_summary(_perm: None = Depends(require_vanitas_read("conformite"))):
    return vanitas_client.list_compliance_rules_summary()


@router.get("/api/vanitas/compliance/rules")
def vanitas_compliance_rules(_perm: None = Depends(require_vanitas_write("conformite"))):
    return vanitas_client.list_compliance_rules()


@router.post("/api/vanitas/compliance/rules")
def vanitas_compliance_create_rule(
    body: CreateComplianceRuleBody, request: Request, _perm: None = Depends(require_vanitas_write("conformite"))
):
    return vanitas_client.create_compliance_rule(
        name=body.name, script_content=body.script_content, actor=request.state.user["username"]
    )


@router.put("/api/vanitas/compliance/rules/{rule_id}")
def vanitas_compliance_update_rule(
    body: UpdateComplianceRuleBody,
    request: Request,
    rule_id: str = IdPath("Identifiant de la règle de conformité"),
    _perm: None = Depends(require_vanitas_write("conformite")),
):
    return vanitas_client.update_compliance_rule(
        rule_id=rule_id,
        name=body.name,
        script_content=body.script_content,
        enabled=body.enabled,
        actor=request.state.user["username"],
    )


@router.delete("/api/vanitas/compliance/rules/{rule_id}")
def vanitas_compliance_delete_rule(
    request: Request,
    rule_id: str = IdPath("Identifiant de la règle de conformité"),
    _perm: None = Depends(require_vanitas_write("conformite")),
):
    return vanitas_client.delete_compliance_rule(rule_id=rule_id, actor=request.state.user["username"])


@router.get("/api/vanitas/agents/{agent_id}/compliance")
def vanitas_agent_compliance(
    agent_id: str = IdPath("Identifiant de l'agent Vanitas"),
    _perm: None = Depends(require_vanitas_read("conformite")),
):
    return vanitas_client.get_agent_compliance(agent_id=agent_id)


@router.get("/api/vanitas/compliance/summary")
def vanitas_compliance_summary(_perm: None = Depends(require_vanitas_read("conformite"))):
    return vanitas_client.get_compliance_summary()


# ── Logiciels/OS obsolètes — EOL (2026-09-08). Réutilise l'inventaire déjà exposé par
# get_agent_inventory — aucune nouvelle route côté serveur Vanitas.
@router.get("/api/vanitas/agents/{agent_id}/eol")
def vanitas_agent_eol(
    agent_id: str = IdPath("Identifiant de l'agent Vanitas"),
    _perm: None = Depends(require_vanitas_read("postes")),
):
    inventory = vanitas_client.get_agent_inventory(agent_id=agent_id)
    if isinstance(inventory, dict) and inventory.get("error"):
        return inventory
    return vanitas_eol.detect_eol(inventory)


# ── Alertes (2026-09-08) — journal des alertes déclenchées par les boucles de fond. Agrégat
# fleet-wide : exige seulement qu'UN profil quelconque soit assigné.
@router.get("/api/vanitas/alerts/recent")
def vanitas_recent_alerts(limit: int = 20, _perm: None = Depends(require_vanitas_any)):
    # `stale_threshold_hours` voyage avec le journal pour que "Vue d'ensemble" reste une SEULE
    # source de vérité avec la boucle de fond.
    return {
        "recent": vanitas_alert_state.list_recent(limit=limit),
        "stale_threshold_hours": VANITAS_ALERT_STALE_HOURS,
    }


# ── Groupes de postes (2026-09-08) — lecture/écriture du module "groupes".
class GroupRuleConditionBody(BaseModel):
    field: str
    operator: str
    value: str


class GroupRulesBody(BaseModel):
    combinator: str = "all"
    conditions: list[GroupRuleConditionBody] = []


class CreateGroupBody(BaseModel):
    name: str
    rules: GroupRulesBody | None = None


class UpdateGroupBody(BaseModel):
    name: str | None = None
    rules: GroupRulesBody | None = None
    clear_rules: bool = False


@router.get("/api/vanitas/groups")
def vanitas_groups(_perm: None = Depends(require_vanitas_read("groupes"))):
    return vanitas_client.list_groups()


@router.get("/api/vanitas/patch-status")
def vanitas_patch_status(_perm: None = Depends(require_vanitas_read("postes"))):
    return vanitas_client.get_patch_status()


class UpdatePatchPolicyBody(BaseModel):
    enabled: bool
    window_start: str | None = None
    window_end: str | None = None
    grace_days: int = 5


@router.put("/api/vanitas/groups/{group_id}/patch-policy")
def vanitas_update_patch_policy(
    body: UpdatePatchPolicyBody,
    request: Request,
    group_id: str = IdPath("Identifiant du groupe"),
    _perm: None = Depends(require_vanitas_write("groupes")),
):
    return vanitas_client.update_patch_policy(
        group_id=group_id,
        enabled=body.enabled,
        window_start=body.window_start,
        window_end=body.window_end,
        grace_days=body.grace_days,
        actor=request.state.user["username"],
    )


@router.get("/api/vanitas/groups/{group_id}/members")
def vanitas_group_members(
    group_id: str = IdPath("Identifiant du groupe"), _perm: None = Depends(require_vanitas_read("groupes"))
):
    return vanitas_client.get_group_members(group_id=group_id)


@router.post("/api/vanitas/groups")
def vanitas_create_group(
    body: CreateGroupBody, request: Request, _perm: None = Depends(require_vanitas_write("groupes"))
):
    return vanitas_client.create_group(
        name=body.name,
        rules=body.rules.model_dump() if body.rules else None,
        actor=request.state.user["username"],
    )


@router.put("/api/vanitas/groups/{group_id}")
def vanitas_update_group(
    body: UpdateGroupBody,
    request: Request,
    group_id: str = IdPath("Identifiant du groupe"),
    _perm: None = Depends(require_vanitas_write("groupes")),
):
    return vanitas_client.update_group(
        group_id=group_id,
        name=body.name,
        rules=body.rules.model_dump() if body.rules else None,
        clear_rules=body.clear_rules,
        actor=request.state.user["username"],
    )


@router.delete("/api/vanitas/groups/{group_id}")
def vanitas_delete_group(
    request: Request,
    group_id: str = IdPath("Identifiant du groupe"),
    _perm: None = Depends(require_vanitas_write("groupes")),
):
    return vanitas_client.delete_group(group_id=group_id, actor=request.state.user["username"])


@router.post("/api/vanitas/agents/{agent_id}/groups/{group_id}")
def vanitas_add_agent_to_group(
    request: Request,
    agent_id: str = IdPath("Identifiant de l'agent Vanitas"),
    group_id: str = IdPath("Identifiant du groupe"),
    _perm: None = Depends(require_vanitas_write("groupes")),
):
    return vanitas_client.add_agent_to_group(
        agent_id=agent_id, group_id=group_id, actor=request.state.user["username"]
    )


@router.delete("/api/vanitas/agents/{agent_id}/groups/{group_id}")
def vanitas_remove_agent_from_group(
    request: Request,
    agent_id: str = IdPath("Identifiant de l'agent Vanitas"),
    group_id: str = IdPath("Identifiant du groupe"),
    _perm: None = Depends(require_vanitas_write("groupes")),
):
    return vanitas_client.remove_agent_from_group(
        agent_id=agent_id, group_id=group_id, actor=request.state.user["username"]
    )


# Groupes imbriqués (2026-09-10) — résolution récursive + contrôle de cycle côté serveur Vanitas.
@router.post("/api/vanitas/groups/{parent_id}/children/{child_id}")
def vanitas_add_child_group(
    request: Request,
    parent_id: str = IdPath("Identifiant du groupe parent"),
    child_id: str = IdPath("Identifiant du groupe enfant"),
    _perm: None = Depends(require_vanitas_write("groupes")),
):
    return vanitas_client.add_child_group(
        parent_id=parent_id, child_id=child_id, actor=request.state.user["username"]
    )


@router.delete("/api/vanitas/groups/{parent_id}/children/{child_id}")
def vanitas_remove_child_group(
    request: Request,
    parent_id: str = IdPath("Identifiant du groupe parent"),
    child_id: str = IdPath("Identifiant du groupe enfant"),
    _perm: None = Depends(require_vanitas_write("groupes")),
):
    return vanitas_client.remove_child_group(
        parent_id=parent_id, child_id=child_id, actor=request.state.user["username"]
    )


# ── Catalogue d'installeurs applicatifs (2026-09-08) — lecture/écriture du module "applications".
class UpdateInstallerBody(BaseModel):
    name: str
    version: str = ""
    install_command: str


@router.get("/api/vanitas/installers")
def vanitas_installers(_perm: None = Depends(require_vanitas_read("applications"))):
    return vanitas_client.list_installers()


@router.get("/api/vanitas/installer-deployments")
def vanitas_installer_deployments(_perm: None = Depends(require_vanitas_read("applications"))):
    return vanitas_client.list_installer_deployments()


@router.post("/api/vanitas/installers")
def vanitas_upload_installer(
    request: Request,
    name: str = Form(...),
    version: str = Form(""),
    install_command: str = Form(...),
    file: UploadFile = File(...),
    _perm: None = Depends(require_vanitas_write("applications")),
):
    return vanitas_client.upload_installer(
        name=name,
        version=version,
        install_command=install_command,
        filename=file.filename,
        fileobj=file.file,
        content_type=file.content_type,
        actor=request.state.user["username"],
    )


@router.put("/api/vanitas/installers/{installer_id}")
def vanitas_update_installer(
    body: UpdateInstallerBody,
    request: Request,
    installer_id: str = IdPath("Identifiant de l'installeur"),
    _perm: None = Depends(require_vanitas_write("applications")),
):
    return vanitas_client.update_installer(
        installer_id=installer_id,
        name=body.name,
        version=body.version,
        install_command=body.install_command,
        actor=request.state.user["username"],
    )


@router.delete("/api/vanitas/installers/{installer_id}")
def vanitas_delete_installer(
    request: Request,
    installer_id: str = IdPath("Identifiant de l'installeur"),
    _perm: None = Depends(require_vanitas_write("applications")),
):
    return vanitas_client.delete_installer(installer_id=installer_id, actor=request.state.user["username"])


class PushInstallBody(BaseModel):
    installer_id: str


@router.post("/api/vanitas/groups/{group_id}/push-install")
def vanitas_push_install_to_group(
    body: PushInstallBody,
    request: Request,
    group_id: str = IdPath("Identifiant du groupe"),
    _perm: None = Depends(require_vanitas_write("applications")),
):
    return vanitas_client.push_install_to_group(
        group_id=group_id, installer_id=body.installer_id, actor=request.state.user["username"]
    )


# ── Source GitHub pour un installeur (2026-09-11) — l'asset choisi est téléchargé en mémoire
# côté serveur puis relayé vers upload_installer dans la MÊME requête (jamais de round-trip par
# le navigateur).
@router.get("/api/vanitas/installers/github-releases")
def vanitas_installer_github_releases(
    owner: str,
    repo: str,
    _perm: None = Depends(require_vanitas_write("applications")),
):
    return vanitas_github_installer.list_releases(owner, repo)


@router.get("/api/vanitas/installers/github-release")
def vanitas_installer_github_release(
    owner: str,
    repo: str,
    tag: str | None = None,
    _perm: None = Depends(require_vanitas_write("applications")),
):
    return vanitas_github_installer.lookup_release(owner, repo, tag)


class GithubInstallerBody(BaseModel):
    owner: str
    repo: str
    download_url: str
    asset_name: str
    name: str
    version: str = ""
    install_command: str


@router.post("/api/vanitas/installers/github")
def vanitas_installer_from_github(
    body: GithubInstallerBody,
    request: Request,
    _perm: None = Depends(require_vanitas_write("applications")),
):
    fetched = vanitas_github_installer.download_asset(body.download_url, body.asset_name)
    if fetched.get("error"):
        return fetched
    return vanitas_client.upload_installer(
        name=body.name,
        version=body.version,
        install_command=body.install_command,
        filename=fetched["filename"],
        fileobj=io.BytesIO(fetched["content"]),
        content_type=None,
        actor=request.state.user["username"],
    )


# ── Mise à jour de l'agent lui-même (2026-09-11) — même tier de permission que le catalogue
# d'installeurs (module "applications").
@router.get("/api/vanitas/agent-packages")
def vanitas_agent_packages(_perm: None = Depends(require_vanitas_read("applications"))):
    return vanitas_client.list_agent_packages()


@router.get("/api/vanitas/agent-packages/latest")
def vanitas_agent_package_latest(_perm: None = Depends(require_vanitas_read("applications"))):
    return vanitas_client.get_latest_agent_package()


@router.post("/api/vanitas/agent-packages")
def vanitas_upload_agent_package(
    request: Request,
    version: str = Form(...),
    file: UploadFile = File(...),
    _perm: None = Depends(require_vanitas_write("applications")),
):
    return vanitas_client.upload_agent_package(
        version=version,
        filename=file.filename,
        fileobj=file.file,
        content_type=file.content_type,
        actor=request.state.user["username"],
    )


@router.delete("/api/vanitas/agent-packages/{package_id}")
def vanitas_delete_agent_package(
    request: Request,
    package_id: str = IdPath("Identifiant du paquet agent"),
    _perm: None = Depends(require_vanitas_write("applications")),
):
    return vanitas_client.delete_agent_package(package_id=package_id, actor=request.state.user["username"])


class PushUpdateBody(BaseModel):
    agent_package_id: str


@router.post("/api/vanitas/groups/{group_id}/push-update")
def vanitas_push_update_to_group(
    body: PushUpdateBody,
    request: Request,
    group_id: str = IdPath("Identifiant du groupe"),
    _perm: None = Depends(require_vanitas_write("applications")),
):
    return vanitas_client.push_update_to_group(
        group_id=group_id, agent_package_id=body.agent_package_id, actor=request.state.user["username"]
    )


# ── Journal d'activité (2026-09-09) — agrégat fleet-wide, exige seulement qu'UN profil soit assigné.
@router.get("/api/vanitas/activity-log")
def vanitas_activity_log(_perm: None = Depends(require_vanitas_any)):
    return vanitas_client.list_activity_log()


# ── Activités suspectes (jalon "détection d'activités suspectes sur les postes") — télémétrie
# comportementale native de l'agent Vanitas (processus/journal d'événements/réseau/USB), filtrée
# localement côté agent avant remontée, voir vanitas/client.py pour le détail du contrat. Nouveau
# module de permission "activites_suspectes" (auth/vanitas_profiles.py::MODULES) : lecture large,
# écriture réservée au triage (transition de statut).
#
# ⚠️ `summary` DOIT rester déclarée AVANT `/{event_id}` : `IdPath` (pattern alphanumérique)
# accepterait "summary" comme un `event_id` valide — FastAPI/Starlette matchent les routes dans
# leur ORDRE DE DÉCLARATION quand deux chemins de même arité se chevauchent, donc la route la
# plus spécifique doit être vue en premier.
class UpdateSuspiciousEventBody(BaseModel):
    status: str
    note: str | None = None


@router.get("/api/vanitas/suspicious-events/summary")
def vanitas_suspicious_events_summary(_perm: None = Depends(require_vanitas_read("activites_suspectes"))):
    return vanitas_client.get_suspicious_events_summary()


@router.get("/api/vanitas/suspicious-events")
def vanitas_suspicious_events(
    agent_id: str | None = None,
    signal_type: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    since: str | None = None,
    until: str | None = None,
    _perm: None = Depends(require_vanitas_read("activites_suspectes")),
):
    return vanitas_client.list_suspicious_events(
        agent_id=agent_id, signal_type=signal_type, severity=severity, status=status, since=since, until=until
    )


@router.get("/api/vanitas/suspicious-events/{event_id}")
def vanitas_suspicious_event_detail(
    event_id: str = IdPath("Identifiant de l'événement suspect"),
    _perm: None = Depends(require_vanitas_read("activites_suspectes")),
):
    return vanitas_client.get_suspicious_event(event_id=event_id)


@router.put("/api/vanitas/suspicious-events/{event_id}")
def vanitas_suspicious_event_update(
    body: UpdateSuspiciousEventBody,
    request: Request,
    event_id: str = IdPath("Identifiant de l'événement suspect"),
    _perm: None = Depends(require_vanitas_write("activites_suspectes")),
):
    return vanitas_client.update_suspicious_event_status(
        event_id=event_id, status=body.status, note=body.note, actor=request.state.user["username"]
    )


# Corrélation Defender (2026-09-14) — PAS un proxy Vanitas : route Pandore NATIVE qui réutilise
# telle quelle `device_overview.py::get_device_overview` (déjà la jointure hostname/AAD device id
# entre Intune/Defender, déjà utilisée par la Vue Appareil 360°) plutôt que de réinventer un
# rapprochement. Même exigence de lecture que le reste du module — consulter la corrélation d'un
# événement suspect n'est pas une action plus sensible que consulter l'événement lui-même.
@router.get("/api/vanitas/suspicious-events/{event_id}/correlation")
def vanitas_suspicious_event_correlation(
    event_id: str = IdPath("Identifiant de l'événement suspect"),
    _perm: None = Depends(require_vanitas_read("activites_suspectes")),
):
    event = vanitas_client.get_suspicious_event(event_id=event_id)
    if isinstance(event, dict) and event.get("error"):
        return event
    return get_device_overview(device_name=event.get("hostname") or "")
