"""Client vers le serveur Vanitas (projet personnel séparé `endpoint-agent/`, jalon 5).

"Vanitas" est le nom donné à cette intégration précise CÔTÉ DASHBOARD ("Pandore" étant déjà le
nom/la marque du dashboard lui-même — logo `pandore-logo.svg` dans Sidebar.jsx, et le nom
générique des installeurs packagés par l'assistant Win32, `Pandore.msi`) — le projet
`endpoint-agent/` lui-même garde son propre nom technique, ce module est juste le point d'entrée
dashboard vers lui.

Jamais d'appel direct navigateur → serveur Vanitas : son certificat TLS est signé par une CA
auto-signée que le navigateur ne connaît pas. Ce module est le SEUL point de contact,
serveur → serveur, et valide explicitement ce certificat contre le fichier `ca.pem` de cette
CA (`VANITAS_CA_CERT_PATH`) — jamais `verify=False`.

Toutes les fonctions sont décorées `@handle_tool_errors` (même convention que
`intune/*.py`/`defender/*.py`) : un serveur Vanitas éteint, une CA introuvable, ou un agent
inconnu remonte comme une erreur métier `{"error": True, ...}`, jamais un crash de route.
Aucune de ces routes serveur Vanitas n'exige de certificat mTLS client (elles sont pensées
pour un admin via ce dashboard, pas pour un agent) — un simple client HTTPS suffit.
"""
import httpx

from common import config
from common.http_client import handle_tool_errors, validate_graph_id

_client: httpx.Client | None = None


def _get_client() -> httpx.Client:
    global _client
    if _client is None:
        # Jalon 9 (terminal PowerShell interactif) — `X-Shell-Token` attaché par défaut à
        # CHAQUE requête de ce client, jamais seulement aux routes qui le vérifient : les
        # routes qui n'en ont pas besoin (agents, commandes classiques) l'ignorent simplement.
        # Le navigateur ne connaît jamais ce secret, seul ce backend l'attache.
        headers = {}
        if config.VANITAS_SHELL_TOKEN:
            headers["X-Shell-Token"] = config.VANITAS_SHELL_TOKEN
        _client = httpx.Client(
            base_url=config.VANITAS_SERVER_URL,
            verify=config.VANITAS_CA_CERT_PATH,
            timeout=30,
            headers=headers,
        )
    return _client


def _actor_headers(actor: str | None) -> dict:
    """Journal d'activité (2026-09-09) — Vanitas n'a lui-même aucune notion de compte (juste
    `X-Shell-Token`, un secret partagé) : c'est CE backend, qui connaît le compte connecté via
    sa propre session (`request.state.user`), qui transmet le nom dans l'en-tête `X-Actor` à
    chaque appel de mutation. Fusionné par `httpx` avec les en-têtes par défaut du client
    partagé (`X-Shell-Token`), jamais un client recréé pour ce seul besoin."""
    return {"X-Actor": actor} if actor else {}


@handle_tool_errors
def list_agents() -> list[dict]:
    resp = _get_client().get("/agents")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_agent_inventory(agent_id: str) -> dict:
    validate_graph_id(agent_id, "agent_id")
    resp = _get_client().get(f"/agents/{agent_id}/inventory")
    resp.raise_for_status()
    return resp.json()


# Enrôlement d'un nouveau poste (2026-09-11, demande de Nicolas — "que se soit plus simple à
# mettre en place via une page sur Vanitas directement") — remplace l'usage courant du script
# CLI `create_enrollment_token.py` par un bouton du dashboard. Le token en clair ne transite
# QUE dans cette réponse (jamais relu après coup, même côté serveur Vanitas — voir
# `routes/enrollment_tokens.py`), donc jamais mis en cache côté frontend non plus.


@handle_tool_errors
def create_enrollment_token(actor: str | None = None) -> dict:
    resp = _get_client().post("/enrollment-tokens", headers=_actor_headers(actor))
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_agent_vulnerabilities(agent_id: str) -> list[dict]:
    validate_graph_id(agent_id, "agent_id")
    resp = _get_client().get(f"/agents/{agent_id}/vulnerabilities")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_agent_commands(agent_id: str) -> list[dict]:
    validate_graph_id(agent_id, "agent_id")
    resp = _get_client().get(f"/agents/{agent_id}/commands")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def list_commands() -> list[dict]:
    resp = _get_client().get("/commands")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_top_vulnerabilities(limit: int = 5) -> list[dict]:
    """CVE les plus répandues sur le parc (comptées par nombre d'agents distincts affectés) —
    "Vue d'ensemble" (2026-09-06). Fleet-wide, pas de `agent_id` — endpoint dédié côté serveur
    Vanitas (`GET /vulnerabilities/top`), calculé à la demande sur le dernier snapshot de
    chaque agent."""
    resp = _get_client().get("/vulnerabilities/top", params={"limit": limit})
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def queue_command(
    agent_id: str,
    command_type: str,
    installer_id: str | None = None,
    agent_package_id: str | None = None,
    event_log_query: dict | None = None,
    event_id: str | None = None,
    actor: str | None = None,
) -> dict:
    """`installer_id` — requis quand `command_type == "install_application"` (2026-09-08),
    ignoré pour tout autre type. `agent_package_id` (2026-09-11, jalon "mise à jour de l'agent
    via Vanitas") — même principe, requis pour `command_type == "update_agent"`. `event_log_query`
    (2026-09-16, jalon "Journal d'événements Windows à la demande") — requis pour
    `command_type == "fetch_event_log"`, transmis tel quel (déjà un dict JSON-sérialisable
    construit par l'appelant HTTP) : la validation réelle (canaux connus, période cohérente,
    plafond d'événements) vit côté serveur Vanitas (`commands_catalog.build_event_log_
    parameters`), jamais dupliquée ici. `event_id` (jalon "confinement", 2026-09-17) — référence
    l'alerte "activité suspecte" déclenchante, requis pour `command_type == "kill_process"`
    (le serveur Vanitas en extrait le PID/nom de process, jamais transmis en clair depuis le
    dashboard), optionnel pour `"isolate_network"`. `actor` (journal d'activité, 2026-09-09) —
    voir `_actor_headers`."""
    validate_graph_id(agent_id, "agent_id")
    body = {"command_type": command_type}
    if installer_id is not None:
        validate_graph_id(installer_id, "installer_id")
        body["installer_id"] = installer_id
    if agent_package_id is not None:
        validate_graph_id(agent_package_id, "agent_package_id")
        body["agent_package_id"] = agent_package_id
    if event_log_query is not None:
        body["event_log_query"] = event_log_query
    if event_id is not None:
        validate_graph_id(event_id, "event_id")
        body["event_id"] = event_id
    resp = _get_client().post(f"/agents/{agent_id}/commands", json=body, headers=_actor_headers(actor))
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_latest_shell_session(agent_id: str) -> dict | None:
    """`None` (renvoyé tel quel par le serveur Vanitas) tant que l'agent n'a pas encore
    récupéré/exécuté "start_shell_session" — le dashboard repolle cette route jusqu'à obtenir
    autre chose que `None` plutôt que de connaître l'id de session à l'avance."""
    validate_graph_id(agent_id, "agent_id")
    resp = _get_client().get(f"/agents/{agent_id}/shell/sessions/latest")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_shell_session(session_id: str) -> dict:
    """Statut d'une session de terminal (jalon 9) — inclut `is_stale` calculé côté serveur
    Vanitas (agent probablement disparu sans fermer proprement)."""
    validate_graph_id(session_id, "session_id")
    resp = _get_client().get(f"/shell/sessions/{session_id}")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_shell_session_events(session_id: str, since_id: int = 0) -> list[dict]:
    validate_graph_id(session_id, "session_id")
    resp = _get_client().get(f"/shell/sessions/{session_id}/events", params={"since_id": since_id})
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def send_shell_input(session_id: str, line: str) -> dict:
    validate_graph_id(session_id, "session_id")
    resp = _get_client().post(f"/shell/sessions/{session_id}/input", json={"line": line})
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def stop_shell_session(session_id: str) -> dict:
    validate_graph_id(session_id, "session_id")
    resp = _get_client().post(f"/shell/sessions/{session_id}/stop", json={})
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def remove_agent(agent_id: str, actor: str | None = None) -> dict:
    """Retrait de l'inventaire (jalon 7) — DELETE renvoie 204 sans corps, pas de `.json()` à
    lire ; un dict de confirmation minimal suffit côté frontend (même contrat que le reste de
    ce module : jamais une réponse vide/None qui obligerait chaque appelant à deviner)."""
    validate_graph_id(agent_id, "agent_id")
    resp = _get_client().delete(f"/agents/{agent_id}", headers=_actor_headers(actor))
    resp.raise_for_status()
    return {"removed": True}


# Conformité (jalon 11) — règles PowerShell fournies par Nicolas, PAS codées en dur. Le
# contenu complet des scripts (`script_content`) est protégé côté serveur Vanitas par
# `require_shell_token` (même secret que le terminal du jalon 9, `X-Shell-Token` déjà attaché
# à CHAQUE requête par `_get_client()` — aucun câblage supplémentaire nécessaire ici) : définir
# du code qui s'exécute en SYSTEM sur tout le parc, sans surveillance, en continu, est au moins
# aussi sensible qu'une session shell observée par un humain.


@handle_tool_errors
def list_compliance_rules_summary() -> list[dict]:
    """Résumé du catalogue (id/nom/état/date), SANS `script_content` — en libre accès, même
    tier que le reste des lectures de ce module."""
    resp = _get_client().get("/compliance/rules/summary")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def list_compliance_rules() -> list[dict]:
    """Catalogue COMPLET (avec `script_content`) — protégé côté serveur par
    `require_shell_token`, nécessaire pour l'éditeur de règles du dashboard."""
    resp = _get_client().get("/compliance/rules")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def create_compliance_rule(name: str, script_content: str, actor: str | None = None) -> dict:
    resp = _get_client().post(
        "/compliance/rules", json={"name": name, "script_content": script_content}, headers=_actor_headers(actor)
    )
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def update_compliance_rule(
    rule_id: str,
    name: str | None = None,
    script_content: str | None = None,
    enabled: bool | None = None,
    actor: str | None = None,
) -> dict:
    validate_graph_id(rule_id, "rule_id")
    payload = {"name": name, "script_content": script_content, "enabled": enabled}
    resp = _get_client().put(
        f"/compliance/rules/{rule_id}", json=payload, headers=_actor_headers(actor)
    )
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def delete_compliance_rule(rule_id: str, actor: str | None = None) -> dict:
    validate_graph_id(rule_id, "rule_id")
    resp = _get_client().delete(f"/compliance/rules/{rule_id}", headers=_actor_headers(actor))
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_agent_compliance(agent_id: str) -> dict:
    validate_graph_id(agent_id, "agent_id")
    resp = _get_client().get(f"/agents/{agent_id}/compliance")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_compliance_summary() -> list[dict]:
    """Agrégat fleet-wide par règle, classé par impact — en libre accès, même tier que le
    reste des lectures de résultats (pas de code, juste des comptes)."""
    resp = _get_client().get("/compliance/summary")
    resp.raise_for_status()
    return resp.json()


# Rétention de l'historique (2026-09-08, demande de Nicolas — "on peut mettre en place le
# filtre de 7j/14j/30j/90j, et au-delà tu supprimes") : la suppression ne peut physiquement se
# faire QUE côté serveur Vanitas (c'est là que vit la base), mais la DÉCISION (quand, à quel
# seuil) est portée par ce backend (voir `_vanitas_purge_loop` dans api_server.py) — cette
# fonction n'est qu'un simple relais vers le mécanisme brut exposé par le serveur.


# Groupes de postes (2026-09-08, demande de Nicolas — "ranger les postes dans des groupes si
# trop de devices et pas organisé") — même motif que les fonctions de conformité ci-dessus.


@handle_tool_errors
def list_groups() -> list[dict]:
    resp = _get_client().get("/groups")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_patch_status() -> list[dict]:
    """Vue fleet-wide du jalon "Mises à jour Vanitas" (2026-09-17) — statut déjà calculé côté
    serveur Vanitas (`routes/patch.py::_display_status`), jamais recalculé ici."""
    resp = _get_client().get("/patch-status")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def create_group(name: str, rules: dict | None = None, actor: str | None = None) -> dict:
    """`rules=None` = groupe STATIQUE (affectation manuelle) ; renseigné = groupe DYNAMIQUE
    (règle multi-critères — `{combinator: "all"|"any", conditions: [{field, operator,
    value}, ...]}`, résolue côté serveur Vanitas, voir `app/group_membership.py`). Remplace
    l'ancien `pattern` (glob sur le hostname seul, 2026-09-08) — révisé le 2026-09-10 suite à
    une revue de la fonctionnalité comparée à Intune/Jamf/Tanium (critère mono-champ, inclusion
    seule)."""
    resp = _get_client().post(
        "/groups", json={"name": name, "rules": rules}, headers=_actor_headers(actor)
    )
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def update_group(
    group_id: str,
    name: str | None = None,
    rules: dict | None = None,
    clear_rules: bool = False,
    actor: str | None = None,
) -> dict:
    """Même convention "3 états" que `intune/app_library.py::update_library_app` (icon/
    remove_icon) : `rules` fourni remplace la règle, `clear_rules=True` la retire (repasse le
    groupe en statique) quel que soit `rules`, ni l'un ni l'autre garde la règle actuelle
    inchangée."""
    validate_graph_id(group_id, "group_id")
    resp = _get_client().put(
        f"/groups/{group_id}",
        json={"name": name, "rules": rules, "clear_rules": clear_rules},
        headers=_actor_headers(actor),
    )
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def delete_group(group_id: str, actor: str | None = None) -> dict:
    validate_graph_id(group_id, "group_id")
    resp = _get_client().delete(f"/groups/{group_id}", headers=_actor_headers(actor))
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def update_patch_policy(
    group_id: str,
    enabled: bool,
    window_start: str | None,
    window_end: str | None,
    grace_days: int,
    actor: str | None = None,
) -> dict:
    """Politique de mise à jour Windows (2026-09-17, jalon "Mises à jour Vanitas") — persistante
    par groupe, distincte de `update_group` (nom/règles) : deux préoccupations, deux routes."""
    validate_graph_id(group_id, "group_id")
    resp = _get_client().put(
        f"/groups/{group_id}/patch-policy",
        json={
            "enabled": enabled,
            "window_start": window_start,
            "window_end": window_end,
            "grace_days": grace_days,
        },
        headers=_actor_headers(actor),
    )
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_group_members(group_id: str) -> list[str]:
    """Hostnames des membres — statiques ou dynamiques selon le type, PLUS ceux des groupes
    enfants imbriqués (2026-09-10) — calcul unique côté serveur Vanitas (voir
    `app/group_membership.py::resolve_group_agents`)."""
    validate_graph_id(group_id, "group_id")
    resp = _get_client().get(f"/groups/{group_id}/members")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def add_agent_to_group(agent_id: str, group_id: str, actor: str | None = None) -> dict:
    """Adhésion STATIQUE (2026-09-08, many-to-many) — un poste peut appartenir à plusieurs
    groupes. Refusé côté serveur (400) si `group_id` désigne un groupe DYNAMIQUE."""
    validate_graph_id(agent_id, "agent_id")
    validate_graph_id(group_id, "group_id")
    resp = _get_client().post(f"/agents/{agent_id}/groups/{group_id}", headers=_actor_headers(actor))
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def remove_agent_from_group(agent_id: str, group_id: str, actor: str | None = None) -> dict:
    validate_graph_id(agent_id, "agent_id")
    validate_graph_id(group_id, "group_id")
    resp = _get_client().delete(f"/agents/{agent_id}/groups/{group_id}", headers=_actor_headers(actor))
    resp.raise_for_status()
    return resp.json()


# Groupes imbriqués (2026-09-10) — "un groupe peut contenir d'autres groupes", voir
# `app/group_membership.py::resolve_group_agents`/`would_create_cycle` côté serveur Vanitas
# (contrôle de cycle fait LÀ-BAS, jamais dupliqué ici).


@handle_tool_errors
def add_child_group(parent_id: str, child_id: str, actor: str | None = None) -> dict:
    validate_graph_id(parent_id, "parent_id")
    validate_graph_id(child_id, "child_id")
    resp = _get_client().post(
        f"/groups/{parent_id}/children/{child_id}", headers=_actor_headers(actor)
    )
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def remove_child_group(parent_id: str, child_id: str, actor: str | None = None) -> dict:
    validate_graph_id(parent_id, "parent_id")
    validate_graph_id(child_id, "child_id")
    resp = _get_client().delete(
        f"/groups/{parent_id}/children/{child_id}", headers=_actor_headers(actor)
    )
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def purge_history(days: int) -> dict:
    """Supprime, côté serveur Vanitas, les lignes de conformité/commandes/inventaire plus
    anciennes que `days` jours (voir `routes/maintenance.py` côté Vanitas pour le détail —
    JAMAIS le journal d'audit des sessions terminal, exclu délibérément là-bas)."""
    resp = _get_client().post("/maintenance/purge-history", json={"days": days})
    resp.raise_for_status()
    return resp.json()


# Catalogue d'installeurs applicatifs (2026-09-08, demande de Nicolas — "un push d'application
# un peu comme dans Pandore, via les groupes"). Contrairement à app_library.py côté Pandore
# (qui ne garde que le .intunewin, un conteneur chiffré propre à Intune), le fichier gardé ici
# est TOUJOURS l'installeur brut : c'est l'agent Vanitas lui-même qui l'exécute.


@handle_tool_errors
def list_installers() -> list[dict]:
    resp = _get_client().get("/installers")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def list_installer_deployments() -> list[dict]:
    """Page "Applications déployées" (2026-09-10) — un élément par installeur ayant déjà été
    poussé au moins une fois, avec les groupes visés et le statut le plus récent par poste."""
    resp = _get_client().get("/installers/deployments")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def upload_installer(
    name: str,
    version: str,
    install_command: str,
    filename: str,
    fileobj,
    content_type: str | None,
    actor: str | None = None,
) -> dict:
    """`fileobj` — flux binaire (ex. `UploadFile.file` de la route Pandore appelante) transmis
    tel quel à `httpx` pour un multipart streamé, jamais chargé entièrement en mémoire ici (un
    installeur peut faire des centaines de Mo). Timeout élargi (contre les 30s par défaut du
    client partagé) : un vrai transfert de fichier, pas un simple appel JSON."""
    data = {"name": name, "version": version or "", "install_command": install_command}
    files = {"file": (filename, fileobj, content_type or "application/octet-stream")}
    resp = _get_client().post(
        "/installers", data=data, files=files, timeout=300, headers=_actor_headers(actor)
    )
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def update_installer(
    installer_id: str, name: str, version: str, install_command: str, actor: str | None = None
) -> dict:
    validate_graph_id(installer_id, "installer_id")
    resp = _get_client().put(
        f"/installers/{installer_id}",
        json={"name": name, "version": version or "", "install_command": install_command},
        headers=_actor_headers(actor),
    )
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def delete_installer(installer_id: str, actor: str | None = None) -> dict:
    validate_graph_id(installer_id, "installer_id")
    resp = _get_client().delete(f"/installers/{installer_id}", headers=_actor_headers(actor))
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def push_install_to_group(group_id: str, installer_id: str, actor: str | None = None) -> dict:
    validate_graph_id(group_id, "group_id")
    validate_graph_id(installer_id, "installer_id")
    resp = _get_client().post(
        f"/groups/{group_id}/push-install", json={"installer_id": installer_id}, headers=_actor_headers(actor)
    )
    resp.raise_for_status()
    return resp.json()


# Mise à jour de l'AGENT lui-même (2026-09-11, jalon "la mise à jour de l'agent via Vanitas
# c'est bien d'actu ?" — réponse : non, jusqu'ici entièrement manuelle). Distinct du catalogue
# d'installeurs applicatifs juste au-dessus : ici c'est Vanitas lui-même qui se met à jour,
# toujours un .msi, toujours via `msiexec /i ... /qn` (commande FIXE, jamais configurable côté
# agent — voir UpdateRunner.cs). Déclenchement TOUJOURS manuel (bouton), jamais automatique —
# voir `_vanitas_agent_update_alert_loop` (api_server.py) pour le volet purement informatif.


@handle_tool_errors
def list_agent_packages() -> list[dict]:
    """Historique complet — le plus récent (`uploaded_at` décroissant, déjà trié côté serveur)
    fait foi comme version "courante" à afficher/pousser."""
    resp = _get_client().get("/agent-package/history")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_latest_agent_package() -> dict | None:
    resp = _get_client().get("/agent-package/latest")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def upload_agent_package(version: str, filename: str, fileobj, content_type: str | None, actor: str | None = None) -> dict:
    """Même motif que `upload_installer` juste au-dessus (flux streamé, jamais chargé en
    mémoire, timeout élargi pour un vrai transfert de fichier) — pas d'`install_command` ici,
    contrairement à un installeur applicatif : la commande de mise à jour de l'agent est fixe."""
    data = {"version": version}
    files = {"file": (filename, fileobj, content_type or "application/octet-stream")}
    resp = _get_client().post(
        "/agent-package", data=data, files=files, timeout=300, headers=_actor_headers(actor)
    )
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def delete_agent_package(package_id: str, actor: str | None = None) -> dict:
    validate_graph_id(package_id, "package_id")
    resp = _get_client().delete(f"/agent-package/{package_id}", headers=_actor_headers(actor))
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def push_update_to_group(group_id: str, agent_package_id: str, actor: str | None = None) -> dict:
    validate_graph_id(group_id, "group_id")
    validate_graph_id(agent_package_id, "agent_package_id")
    resp = _get_client().post(
        f"/groups/{group_id}/push-update", json={"agent_package_id": agent_package_id}, headers=_actor_headers(actor)
    )
    resp.raise_for_status()
    return resp.json()


# Journal d'activité (2026-09-09, demande de Nicolas — "changer Commandes en onglet de Log pour
# chaque action... qui a créé quoi") — fusion côté serveur Vanitas de AgentCommand (commandes
# envoyées à un poste) et AuditEvent (mutations admin sur les catalogues), voir routes/
# activity.py côté Vanitas pour le détail. Lecture seule, pas d'`actor` à transmettre ici.


@handle_tool_errors
def list_activity_log() -> list[dict]:
    resp = _get_client().get("/activity-log")
    resp.raise_for_status()
    return resp.json()


# Activités suspectes (jalon "détection d'activités suspectes sur les postes") — télémétrie
# comportementale NATIVE de l'agent Vanitas (processus/journal d'événements Windows/connexions
# réseau sortantes/support amovible USB), filtrée LOCALEMENT côté agent avant remontée (voir
# `endpoint-agent/agent/EndpointAgent/Detection/`) : contrairement au reste de ce module, ce
# n'est PAS un simple relais de commandes/inventaire, c'est un journal d'audit sécurité qui
# survit à `DELETE /agents/{id}` côté serveur Vanitas (même motif que `ShellSession`, hostname
# dénormalisé à l'ingestion). Protégé par le nouveau module de permission "activites_suspectes"
# (`auth/vanitas_profiles.py::MODULES`) — lecture large, écriture (transition de statut) réservée
# à un profil qui l'accorde explicitement, voir `routers/vanitas.py`.


@handle_tool_errors
def list_suspicious_events(
    agent_id: str | None = None,
    signal_type: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """Triée `occurred_at desc` côté serveur Vanitas. Tous les filtres sont optionnels — un
    appel sans argument renvoie la totalité du journal (échelle "quelques postes", filtrage
    local déjà appliqué en amont par l'agent, jamais un volume qui justifierait une pagination
    ici). `until` (jalon "confinement", 2026-09-17) — borne haute, pour la fenêtre "alertes
    précédentes" du détail d'alerte (voir `routes/suspicious_activity.py`)."""
    if agent_id is not None:
        validate_graph_id(agent_id, "agent_id")
    params = {
        k: v
        for k, v in {
            "agent_id": agent_id,
            "signal_type": signal_type,
            "severity": severity,
            "status": status,
            "since": since,
            "until": until,
        }.items()
        if v is not None
    }
    resp = _get_client().get("/suspicious-events", params=params)
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_suspicious_event(event_id: str) -> dict:
    """Détail complet — `detail` déjà parsé en objet côté serveur Vanitas (JSON structuré propre
    à la catégorie de signal, voir le contrat d'ingestion agent)."""
    validate_graph_id(event_id, "event_id")
    resp = _get_client().get(f"/suspicious-events/{event_id}")
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def update_suspicious_event_status(
    event_id: str, status: str, note: str | None = None, actor: str | None = None
) -> dict:
    """Transition de triage (`new -> {acknowledged, false_positive, escalated}`, validée côté
    serveur Vanitas) — `actor` (même convention que le reste de ce module) journalise QUI a
    traité l'événement, `handled_by`/`handled_at`/`handled_note` dans la réponse mise à jour."""
    validate_graph_id(event_id, "event_id")
    resp = _get_client().put(
        f"/suspicious-events/{event_id}", json={"status": status, "note": note}, headers=_actor_headers(actor)
    )
    resp.raise_for_status()
    return resp.json()


@handle_tool_errors
def get_suspicious_events_summary() -> dict:
    """Comptages par sévérité/statut pour la tuile KPI de l'onglet transverse — voir
    `VanitasSuspiciousActivityTab.jsx`."""
    resp = _get_client().get("/suspicious-events/summary")
    resp.raise_for_status()
    return resp.json()
