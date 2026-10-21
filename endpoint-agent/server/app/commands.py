"""Catalogue fermé des types de commande — jalon 4 — et création partagée — jalon 5.

Validé ICI côté serveur (route de création ET `queue_command.py`), en plus du dispatch fixe
côté agent (`Commands/CommandExecutor.cs`) — les deux bouts doivent rester synchronisés
manuellement (pas de mécanisme de découverte automatique, le catalogue est volontairement
petit et stable). ⚠️ Un TROISIÈME point de synchronisation existe côté dashboard
(`frontend/src/pages/vanitasShared.jsx::COMMAND_LABELS`, le libellé affiché par le bouton
générique "Lancer") — facile à oublier, repéré en concevant le jalon 11.

Jusqu'au jalon 8, aucune commande de ce catalogue n'exécutait de texte/script arbitraire reçu
du serveur — le mTLS authentifiait le canal, l'agent n'avait que des actions fixes à exécuter.
Ce n'est plus vrai depuis : "start_shell_session" (jalon 9) ouvre un vrai shell interactif, et
"compliance_check" (jalon 11) exécute des scripts PowerShell arbitraires DÉFINIS PAR
L'UTILISATEUR (voir `ComplianceRule.script_content`) — décisions prises en connaissance de
cause avec Nicolas dans les deux cas, documentées dans leurs jalons respectifs.
"""
import json

from sqlalchemy.orm import Session

from .models import Agent, AgentCommand, AgentPackage, InstallerPackage, SuspiciousEvent

COMMAND_TYPES: frozenset[str] = frozenset(
    {
        "force_inventory",
        "restart_service",
        "system_diagnostic",
        "check_windows_updates",
        "hardware_inventory",
        "uninstall_agent",
        # Jalon 9 — reste une commande fermée du catalogue comme les six autres : c'est son
        # EFFET qui ouvre un canal interactif (voir app/routes/shell.py), pas la validation
        # elle-même, qui ne change pas de nature.
        "start_shell_session",
        # Jalon 11 — déclenche à la demande la même vérification que le cycle périodique
        # automatique (voir Compliance/ComplianceRunner.cs côté agent), fire-and-forget comme
        # "start_shell_session" pour ne jamais bloquer le canal de commande le temps du contrôle.
        "compliance_check",
        # Push d'application (2026-09-08) — CONTRAIREMENT à "compliance_check"/
        # "start_shell_session", reste SYNCHRONE côté agent (comme "system_diagnostic") : le
        # vrai succès/échec de l'installation est renvoyé directement dans cette ligne
        # `AgentCommand`, sans mécanisme de résultat séparé — installer un logiciel a une durée
        # bornée et déterministe (contrairement à un shell interactif ou un cycle périodique),
        # donc pas besoin de découpler la commande de son résultat.
        "install_application",
        # Mise à jour de l'agent lui-même (2026-09-11) — SYNCHRONE côté agent comme
        # "install_application" pour le téléchargement/la vérification SHA-256, mais le
        # lancement de `msiexec /i ... /qn` est DIFFÉRÉ après le rapport de résultat (même
        # mécanisme `PostReportAction` déjà éprouvé pour "uninstall_agent" — le process courant
        # va être arrêté par sa propre mise à jour, il doit rapporter AVANT que ça n'arrive).
        "update_agent",
        # Journal d'événements Windows à la demande (2026-09-16) — recherche ponctuelle
        # paramétrée par l'utilisateur (canaux, période, ID inclus/exclus), distincte du flux
        # "Activités suspectes" (filtré en continu par l'agent). SYNCHRONE comme
        # "system_diagnostic" : une recherche a une durée bornée, pas besoin de découpler.
        "fetch_event_log",
        # Jalon "Mises à jour Vanitas" (2026-09-17) — redémarrage IMMÉDIAT de la MACHINE (pas le
        # Windows Service, voir "restart_service" plus haut), déclenché depuis le dashboard en
        # dehors de toute fenêtre de maintenance ("Forcer le redémarrage maintenant"). SYNCHRONE
        # comme "install_application" : un `shutdown.exe /r` a un effet déterministe, pas besoin
        # de découpler la commande de son résultat. L'installation elle-même des mises à jour de
        # sécurité et la logique de fenêtre/délai de grâce vivent HORS de ce catalogue — dans
        # `PatchLoop.cs`, une boucle de fond autonome (voir `routes/patch.py`), pas une commande
        # à la demande : le rythme est piloté par la politique du groupe, pas par un clic.
        "force_reboot",
        # Jalon "confinement" (mini-EDR, 2026-09-17) — déclenchées MANUELLEMENT depuis le détail
        # d'une alerte "activité suspecte" (jamais par la détection elle-même). SYNCHRONES comme
        # "force_reboot" : voir ContainmentRunner.cs côté agent — un kill de process ou un
        # changement de politique de pare-feu a un effet déterministe et borné.
        "kill_process",
        "isolate_network",
        "lift_isolation",
    }
)

# Canaux Windows Logs prédéfinis — volontairement PAS l'arbre ouvert "Journaux des applications
# et services" (des centaines de journaux possibles selon ce qui est installé, propre à chaque
# poste) : un sous-ensemble curé, celui de l'Observateur d'événements sous "Journaux Windows".
KNOWN_EVENT_LOG_CHANNELS: frozenset[str] = frozenset(
    {"Security", "System", "Application", "Setup", "ForwardedEvents"}
)

# Plafond dur, jamais fait confiance à la valeur envoyée par le client (voir
# build_event_log_parameters) — même volume que le plafond de page déjà retenu pour ce jalon.
EVENT_LOG_MAX_EVENTS_CAP = 2000


def create_command(
    db: Session, agent: Agent, command_type: str, parameters: str | None = None, actor: str | None = None
) -> AgentCommand:
    """Insère une commande `pending` pour `agent` — factorisé pour n'exister qu'à un seul
    endroit (jalon 5) : appelé par `scripts/queue_command.py` (CLI, accès machine), par
    `POST /agents/{id}/commands` (HTTP, depuis le dashboard DSI) et par
    `POST /groups/{id}/push-install` (une commande par membre du groupe) plutôt que dupliqué.

    `parameters` — JSON brut sérialisé par l'appelant, jamais construit ici (ce module ne
    connaît pas la forme attendue par chaque type de commande) ; existait déjà sur
    `AgentCommand` mais n'était jusqu'ici jamais réellement peuplé par aucun appelant.

    `actor` (journal d'activité, 2026-09-09) — nom d'utilisateur Pandore qui a déclenché cette
    commande, voir `AgentCommand.actor`. `None` pour `scripts/queue_command.py` (accès machine
    directe, pas de session Pandore à attribuer).

    Lève `ValueError` si `command_type` n'est pas dans le catalogue — à charge de l'appelant
    de la transformer en 400/erreur CLI, ce module ne connaît pas le contexte HTTP vs script.
    """
    if command_type not in COMMAND_TYPES:
        raise ValueError(f"Type de commande inconnu : {command_type}")

    command = AgentCommand(agent_id=agent.id, command_type=command_type, parameters=parameters, actor=actor)
    db.add(command)
    db.commit()
    db.refresh(command)
    return command


def build_install_parameters(db: Session, installer_id: str, target_label: str | None = None) -> str:
    """Sérialise les `parameters` d'une commande `install_application` à partir d'un
    `InstallerPackage` du catalogue — un seul endroit, réutilisé par `POST /agents/{id}/
    commands` (push vers un seul poste) ET `POST /groups/{id}/push-install` (un appel par
    membre du groupe), pour ne jamais laisser diverger la forme du payload entre les deux.

    `target_label` (2026-09-10, page "Applications déployées") — nom du GROUPE visé par CE
    push, `None` pour un push direct vers un seul poste (le poste lui-même EST alors la
    cible, pas la peine de la nommer séparément). Stocké dans ce même JSON plutôt que sur une
    nouvelle colonne `AgentCommand` : aucune migration nécessaire (`parameters` est déjà une
    chaîne libre), et ça garde la forme du push (poste isolé vs groupe) attachée à l'endroit
    où elle a été décidée, sans avoir à la reconstruire après coup.

    Lève `ValueError` si l'installeur n'existe pas — traduit en 404 par l'appelant HTTP.
    """
    installer = db.get(InstallerPackage, installer_id)
    if installer is None:
        raise ValueError("Installeur introuvable.")
    return json.dumps(
        {
            "installer_id": installer.id,
            "original_filename": installer.original_filename,
            "install_command": installer.install_command,
            "sha256": installer.sha256,
            "target_label": target_label,
        }
    )


def build_kill_process_parameters(db: Session, agent_id: str, event_id: str) -> str:
    """Sérialise les `parameters` d'une commande `kill_process` à partir du `detail` déjà
    remonté par l'alerte "activité suspecte" déclenchante — jamais des valeurs saisies/transmises
    par le dashboard, qui n'a aucun moyen de les vérifier : `event_id` référence l'alerte, le
    PID/nom de process en sont EXTRAITS ici, côté serveur, à partir de la donnée d'origine.

    Fonctionne aussi bien pour un signal "process" (`process_name` = chemin complet, `pid`
    présent depuis le jalon confinement) que "network" (`process_name` = nom court, `pid` déjà
    présent de longue date sur ce signal) — même clés dans les deux cas, voir
    `SuspiciousActivityRuleEngine.cs`.

    🔧 `agent_id` ajouté (revue de sécurité du 2026-09-17) — RIEN ne garantissait jusqu'ici que
    l'alerte référencée par `event_id` appartienne au poste ciblé par la commande : un appel
    direct au secret partagé (hors du bouton du dashboard, qui passe toujours le bon couple)
    aurait pu tuer un process sur l'agent A en pointant vers une alerte de l'agent B. Vérifié ICI
    plutôt que côté route HTTP, pour que ce soit vrai pour TOUT appelant présent ou futur.

    Lève `ValueError` si l'événement n'existe pas, n'appartient pas à `agent_id`, ou n'a ni PID
    ni nom de process exploitable.
    """
    event = db.get(SuspiciousEvent, event_id)
    if event is None:
        raise ValueError("Alerte introuvable.")
    if event.agent_id != agent_id:
        raise ValueError("Cette alerte n'appartient pas au poste ciblé.")
    detail = json.loads(event.detail) if event.detail else {}
    pid = detail.get("pid")
    process_name = detail.get("process_name")
    if pid is None and not process_name:
        raise ValueError("Cette alerte ne porte ni PID ni nom de process exploitable.")
    return json.dumps({"pid": pid, "process_name": process_name})


def build_isolate_network_parameters(db: Session, agent_id: str, event_id: str | None) -> str | None:
    """Capture un INSTANTANÉ de l'alerte déclenchante pour `isolate_network` — l'agent lui-même
    n'utilise AUCUNE de ces valeurs pour s'isoler (il connaît déjà son propre `ServerUrl`, voir
    `ContainmentRunner.cs`, qui ne lit jamais `command.ParametersJson`) : ce JSON ne sert qu'au
    SERVEUR, relu dans `report_command_result` pour peupler `Agent.network_isolated_reason`/
    `network_isolated_event_id` quand le résultat revient positif — un instantané plutôt qu'un
    lien vivant vers l'événement, pour rester lisible même si celui-ci disparaît un jour.

    `event_id=None` accepté (isolement manuel sans alerte précise) — renvoie alors `None`,
    l'agent n'a de toute façon rien à en faire. `agent_id` (revue de sécurité du 2026-09-17,
    même raison que `build_kill_process_parameters`) — refuse une alerte qui n'appartient pas au
    poste ciblé plutôt que de laisser `network_isolated_reason` pointer vers un événement sans
    rapport, ce qui induirait l'analyste en erreur en incident réel.
    """
    if event_id is None:
        return None
    event = db.get(SuspiciousEvent, event_id)
    if event is None:
        raise ValueError("Alerte introuvable.")
    if event.agent_id != agent_id:
        raise ValueError("Cette alerte n'appartient pas au poste ciblé.")
    return json.dumps({"reason_event_id": event.id, "reason_summary": event.summary})


def build_update_parameters(db: Session, package_id: str, target_label: str | None = None) -> str:
    """Même rôle que `build_install_parameters` juste au-dessus, pour "update_agent" —
    volontairement PAS d'`install_command` ici : contrairement à un installeur applicatif
    classique (commande libre, choisie par l'admin à l'upload), la commande de mise à jour de
    l'agent est FIXE (`msiexec /i <fichier> /qn /norestart`, voir `UpdateRunner.cs`), jamais
    configurable — un agent ne devrait jamais s'installer avec des options surprenantes."""
    pkg = db.get(AgentPackage, package_id)
    if pkg is None:
        raise ValueError("Paquet de mise à jour introuvable.")
    return json.dumps(
        {
            "package_id": pkg.id,
            "original_filename": pkg.original_filename,
            "sha256": pkg.sha256,
            "target_label": target_label,
        }
    )


def build_event_log_parameters(
    *,
    channels: list[str],
    since: str,
    until: str,
    event_ids_include: list[int] | None = None,
    event_ids_exclude: list[int] | None = None,
    levels: list[str] | None = None,
    after_record_id: int | None = None,
    max_events: int | None = None,
) -> str:
    """Valide et sérialise les paramètres de "fetch_event_log" — CONTRAIREMENT à
    `build_install_parameters`/`build_update_parameters` (qui résolvent une référence vers un
    catalogue déjà connu du serveur), ces paramètres viennent directement d'une saisie
    utilisateur (période, canaux, ID) : cette validation est le seul garde-fou avant que l'agent
    ne les interprète en requête XPath sur le poste. Prend des primitives (pas le modèle Pydantic
    de la route) pour éviter un import circulaire avec `routes/commands.py`, même motif que les
    deux fonctions `build_*_parameters` juste au-dessus.

    `max_events` est plafonné ICI à `EVENT_LOG_MAX_EVENTS_CAP`, jamais fait confiance à la valeur
    demandée par le client — sinon rien n'empêcherait une requête de demander un plafond
    arbitrairement haut et de transformer une recherche ponctuelle en export complet du journal.
    """
    if not channels:
        raise ValueError("Sélectionne au moins un canal.")
    unknown = set(channels) - KNOWN_EVENT_LOG_CHANNELS
    if unknown:
        raise ValueError(f"Canal inconnu : {', '.join(sorted(unknown))}.")
    if since >= until:
        raise ValueError("La date de début doit précéder la date de fin.")
    return json.dumps(
        {
            "channels": channels,
            "since": since,
            "until": until,
            "event_ids_include": event_ids_include or [],
            "event_ids_exclude": event_ids_exclude or [],
            "levels": levels or [],
            "after_record_id": after_record_id,
            "max_events": min(max_events or EVENT_LOG_MAX_EVENTS_CAP, EVENT_LOG_MAX_EVENTS_CAP),
        }
    )
