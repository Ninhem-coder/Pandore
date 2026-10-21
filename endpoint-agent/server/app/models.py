"""Modèles SQLAlchemy — agents enrôlés, tokens d'enrôlement, inventaire applicatif.

Depuis le jalon 3 (mTLS), l'identité d'un agent est prouvée par certificat (voir ca.py/
security.py), plus par un token API partagé — `EnrollmentToken` reste le mécanisme de
bootstrap de confiance initial (à usage unique, jamais stocké en clair), inchangé sur ce point.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from .db import Base


def _uuid_hex() -> str:
    return uuid.uuid4().hex


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """`DateTime(timezone=True)` perd son fuseau au retour de lecture sur SQLite — confirmé en
    conditions réelles (jalon 5) : une valeur écrite via `_utcnow()` (aware, UTC) revient
    `tzinfo=None` après un aller-retour DB, alors même que la colonne demande
    `timezone=True`. SQLite ne stocke les dates que comme du texte ISO, sans vraie notion de
    fuseau — un défaut connu de son dialecte SQLAlchemy, pas un bug de notre code d'écriture.

    Conséquence concrète repérée en testant : le frontend calcule "il y a Xh" via
    `new Date(iso)` — sans suffixe `Z`/`+00:00`, le navigateur interprète la chaîne comme
    une heure LOCALE, décalant chaque calcul de l'offset UTC du poste (ex. +2h en France l'été)
    — une commande tout juste créée s'affichait "il y a 2h". Corrigé une seule fois ici, au
    niveau colonne, plutôt que dans chaque route/schéma Pydantic qui renvoie une date.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid_hex)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    enrolled_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    # Visibilité opérationnelle minimale sur le certificat courant de l'agent (pas une vraie
    # liste de révocation — voir le plan du jalon 3). Mis à jour à chaque enrôlement/renouvellement.
    cert_serial: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cert_not_after: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    # Traçabilité de version (2026-09-08) — `<Version>` du .csproj de l'agent, renvoyée à
    # CHAQUE inventaire (comme `last_seen`, jamais un historique séparé : c'est un simple fait
    # courant sur l'agent, pas un événement daté). `None` pour tout agent qui n'a pas encore
    # renvoyé d'inventaire depuis ce jalon. AJOUTÉE par migration manuelle (voir
    # `scripts/migrate_add_agent_version_column.py`, `Base.metadata.create_all()` ne touche
    # jamais une table existante).
    agent_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Groupes (2026-09-08) — v1 avait une colonne `group_id` unique (une seule affectation par
    # poste), remplacée LE MÊME SOIR par une vraie relation many-to-many (`AgentGroupMembership`
    # ci-dessous) suite à la demande de Nicolas ("un poste peut appartenir à plusieurs groupes").
    # La colonne physique `group_id` reste en base (aucun `DROP COLUMN` n'a jamais été fait dans
    # ce projet, uniquement des `ADD COLUMN`) mais n'est plus mappée ici — confirmée `None` pour
    # le seul agent réel au moment de la bascule, rien n'en dépend plus.

    snapshots: Mapped[list["InventorySnapshot"]] = relationship(
        back_populates="agent", cascade="all, delete-orphan"
    )
    # Jalon 7 ("Retirer de l'inventaire") — supprimer un agent supprime aussi tout son
    # historique de commandes, pas seulement son inventaire applicatif (déjà cascadé via
    # `snapshots` ci-dessus, qui cascade lui-même vers InstalledApp). Pas de `back_populates`
    # nécessaire : rien n'a besoin de naviguer d'AgentCommand vers Agent aujourd'hui.
    commands: Mapped[list["AgentCommand"]] = relationship(cascade="all, delete-orphan")
    # Jalon 11 (conformité) — donnée OPÉRATIONNELLE comme l'inventaire (cascade avec l'agent),
    # PAS un audit comme ShellSession/ShellSessionEvent (voir leur docstring) : retirer un
    # agent décommissionné doit purger son historique de conformité, contrairement à l'audit
    # d'un shell qui doit lui survivre. Raison différente, mécanisme identique à `snapshots`.
    compliance_snapshots: Mapped[list["ComplianceSnapshot"]] = relationship(
        back_populates="agent", cascade="all, delete-orphan"
    )

    # Confinement (jalon "mini-EDR", 2026-09-17) — état COURANT sur l'agent, pas un historique
    # séparé : un poste est isolé ou ne l'est pas, comme `last_seen`/`cert_not_after` juste
    # au-dessus. `network_isolated_reason`/`network_isolated_event_id` capturent un INSTANTANÉ
    # du résumé de l'alerte déclenchante (jamais une vraie FK vers `suspicious_events` — même
    # précédent que `AgentCommand`/`ComplianceResult.rule_id` : si l'événement est un jour purgé,
    # l'onglet "Postes isolés" doit continuer à afficher la raison plutôt que de la perdre).
    # Peuplé UNIQUEMENT sur le RETOUR de résultat de la commande côté agent (jamais à la simple
    # mise en file) — un isolement affiché avant confirmation réelle serait trompeur si l'agent
    # est hors ligne ou que la commande échoue.
    network_isolated: Mapped[bool] = mapped_column(Boolean, default=False)
    network_isolated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    network_isolated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    network_isolated_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    network_isolated_event_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class EnrollmentToken(Base):
    """Token d'enrôlement à usage unique. `used_at` non nul = déjà consommé, rejeu refusé."""

    __tablename__ = "enrollment_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    used_by_agent_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("agents.id"), nullable=True
    )


class RevokedCertificate(Base):
    """Liste de révocation minimale (2026-09-08, revue de sécurité) — `DELETE /agents/{id}`
    retirait la ligne `Agent` (cascade sur son historique) mais ne gardait AUCUNE trace du
    certificat mTLS associé : celui-ci restait cryptographiquement valide (chaîne jusqu'à la CA
    pinnée) jusqu'à expiration naturelle (90 jours), même pour un poste décommissionné/compromis.
    Table SÉPARÉE de `Agent` (pas une colonne dessus) précisément PARCE QUE `Agent` est supprimé
    à la révocation — un flag sur une ligne qui va disparaître ne survivrait pas à l'action
    même qui doit le déclencher. `cert_serial` en minuscules hex, même format que
    `Agent.cert_serial` (`format(cert.serial_number, "x")`, enrollment.py/renew.py)."""

    __tablename__ = "revoked_certificates"

    cert_serial: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(32))
    hostname: Mapped[str] = mapped_column(String(255))
    revoked_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)


class InventorySnapshot(Base):
    """Un envoi d'inventaire par un agent. Le dernier snapshot d'un agent fait foi."""

    __tablename__ = "inventory_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(32), ForeignKey("agents.id"), index=True)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    # OS (jalon "logiciels/OS obsolètes (EOL)", 2026-09-08, `OsInfoCollector.cs` côté agent) —
    # les 3 colonnes sont NULLABLE : un agent pas encore mis à jour (ou dont la collecte WMI a
    # échoué sur ce poste précis) continue de pousser un inventaire normal, simplement sans ces
    # 3 champs. AJOUTÉES par migration manuelle (`ALTER TABLE`, `Base.metadata.create_all()` ne
    # touche jamais une table déjà existante) — voir `scripts/migrate_add_os_columns.py`.
    os_caption: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    os_build_number: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Panneau "Système d'exploitation" (2026-09-11, retour de Nicolas — "possible d'avoir plus
    # d'information ?") — AJOUTÉES par migration manuelle (`scripts/migrate_add_os_detail_columns.py`),
    # même raisonnement que les 3 colonnes ci-dessus.
    os_architecture: Mapped[str | None] = mapped_column(String(20), nullable=True)
    os_registered_user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_install_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    os_utc_offset: Mapped[str | None] = mapped_column(String(10), nullable=True)

    agent: Mapped["Agent"] = relationship(back_populates="snapshots")
    apps: Mapped[list["InstalledApp"]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )


class InstalledApp(Base):
    __tablename__ = "installed_apps"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("inventory_snapshots.id"), index=True
    )
    name: Mapped[str] = mapped_column(String(500))
    version: Mapped[str | None] = mapped_column(String(200), nullable=True)
    publisher: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Chaîne brute (ex. "20260315"), pas un vrai type date : c'est le format renvoyé par la
    # clé de registre InstallDate côté Windows, pas toujours présent ni valide.
    install_date: Mapped[str | None] = mapped_column(String(20), nullable=True)

    snapshot: Mapped["InventorySnapshot"] = relationship(back_populates="apps")


class ProductCpeMatch(Base):
    """Cache du rapprochement nom de produit (tel que vu dans le registre) → CPE NVD.

    `cpe_vendor`/`cpe_product` nuls = déjà cherché, aucune correspondance fiable trouvée —
    mis en cache quand même pour ne pas retenter à chaque cycle, mais retenté périodiquement
    par le rafraîchissement automatique (voir cve_matching.py) au cas où NVD référence le
    produit plus tard.
    """

    __tablename__ = "product_cpe_matches"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    product_name: Mapped[str] = mapped_column(String(500), unique=True, index=True)
    cpe_vendor: Mapped[str | None] = mapped_column(String(200), nullable=True)
    cpe_product: Mapped[str | None] = mapped_column(String(200), nullable=True)
    matched_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)


class AgentCommand(Base):
    """Une commande demandée à un agent — jalon 4 (canal de commande).

    `command_type` est validé contre le catalogue fixe `app/commands.py::COMMAND_TYPES` au
    moment de la création (route ET script `queue_command.py`), jamais un texte libre —
    l'agent lui-même ne connaît qu'un nombre fixe de handlers, ce champ doit rester cohérent
    avec les deux côtés à la fois.

    Cycle de vie : `pending` (créée, pas encore récupérée) → `running` (servie à l'agent via
    GET .../commands/pending) → `completed`/`failed` (résultat rapporté). Une commande qui
    reste `running` indéfiniment signale un agent qui a planté entre la récupération et le
    rapport — visible dans l'audit, pas de retry automatique dans ce jalon.
    """

    __tablename__ = "agent_commands"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(32), ForeignKey("agents.id"), index=True)
    command_type: Mapped[str] = mapped_column(String(50))
    # JSON brut sérialisé par l'appelant (queue_command.py) — pas de colonne par paramètre,
    # aucune commande de ce catalogue n'a besoin de plus qu'une poignée de valeurs simples.
    parameters: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    # `Text` (non bornée) plutôt qu'un `String(N)` (jalon 6) : un premier élargissement à 8000
    # (depuis 4000 à l'origine) s'est avéré encore limite en testant "hardware_inventory" avec
    # les périphériques PCI inclus (7336 caractères sur CE poste, un poste avec plus de
    # barrettes RAM/disques/périphériques PCI dépasserait facilement) — plutôt que de rejouer
    # indéfiniment "encore un peu plus large", `Text` retire la question : SQLite n'impose de
    # toute façon aucune limite réelle sur une colonne texte (la taille déclarée d'un
    # `String(N)` n'est qu'indicative pour le fichier .db, jamais appliquée). Aucune migration
    # nécessaire pour ce changement non plus.
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # Journal d'activité (2026-09-09) — nom d'utilisateur Pandore qui a mis la commande en
    # file (`None` pour toute commande créée AVANT ce jalon, ou si l'en-tête `X-Actor` n'a pas
    # été transmis — jamais une erreur, l'acteur affiché retombe alors sur "inconnu" côté
    # dashboard). Vanitas n'a lui-même AUCUNE notion de compte (juste `require_shell_token`,
    # un secret partagé) — c'est Pandore, qui connaît le compte connecté via sa propre session,
    # qui transmet ce nom à chaque appel de mutation. AJOUTÉE par migration manuelle (voir
    # `scripts/migrate_add_actor_columns.py`, table déjà existante avec de vraies lignes).
    actor: Mapped[str | None] = mapped_column(String(100), nullable=True)


class ShellSession(Base):
    """Une session de terminal PowerShell interactif — jalon 9.

    Volontairement SANS `ForeignKey`/relation vers `Agent` (contrairement à `AgentCommand`
    ci-dessus, qui cascade avec l'agent) : ces deux tables (avec `ShellSessionEvent`) sont le
    journal d'audit de tout ce qui a été exécuté en shell niveau SYSTEM sur ce poste — retirer
    un agent décommissionné de l'inventaire (jalon 7, `DELETE /agents/{id}`) ne doit JAMAIS
    effacer cette trace. Même raisonnement déjà accepté sur `EnrollmentToken.used_by_agent_id`
    (SQLite n'applique de toute façon aucune FK sans `PRAGMA foreign_keys=ON`, jamais activé
    dans `db.py`) — `agent_id` reste une colonne indexée nue, pas une vraie FK.

    Cycle de vie : `active` (créée par l'agent) → `closed` (fin propre, stop demandé ou
    inactivité côté agent) → `timed_out` (l'agent a lui-même détecté l'inactivité). Une session
    restée `active` alors que `last_activity_at` est ancien signale un agent disparu en pleine
    session (crash, redémarrage Windows Update) SANS avoir pu fermer proprement — calculé à la
    volée côté lecture (`is_stale`), jamais une tâche de fond dédiée (aucune n'existe ailleurs
    dans ce serveur pour ce genre de ménage).
    """

    __tablename__ = "shell_sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid_hex)
    agent_id: Mapped[str] = mapped_column(String(32), index=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    last_activity_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    stop_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    # Curseur de livraison — le prochain `poll-input` de l'agent ne renvoie que les
    # `ShellSessionEvent` de type "input" dont l'id dépasse celui-ci, puis l'avance. Une seule
    # table sert donc à la fois de file de relais ET de journal d'audit complet (voir
    # `ShellSessionEvent` ci-dessous) — pas de structure de file séparée.
    last_delivered_input_id: Mapped[int] = mapped_column(default=0)


class ShellSessionEvent(Base):
    """Une ligne tapée par l'admin OU un fragment de sortie du process PowerShell — jalon 9.

    `direction="input"` : une ligne envoyée par le dashboard (`content` = la commande telle que
    tapée, jamais le marqueur de fin injecté côté agent avant écriture sur stdin — ce marqueur
    est un détail d'implémentation de `ShellSessionRunner`, pas quelque chose que l'admin a tapé).
    `direction="output"` : un fragment de sortie du process (une "commande" peut produire
    plusieurs lignes, regroupées en un seul événement par l'agent entre deux marqueurs de fin).
    `source` (`"stdout"`/`"stderr"`, `NULL` pour un événement `input`) permet au terminal
    d'afficher les erreurs différemment sans dupliquer la table.
    """

    __tablename__ = "shell_session_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(32), index=True)
    direction: Mapped[str] = mapped_column(String(10))
    source: Mapped[str | None] = mapped_column(String(10), nullable=True)
    # `Text` (non bornée) d'emblée, pas un `String(N)` — leçon déjà tirée sur
    # `AgentCommand.result` (jalon 6) plutôt que de rejouer la même progression 4000→8000→Text.
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)


class ComplianceRule(Base):
    """Une règle de conformité — jalon 11 — définie par un script PowerShell fourni par
    Nicolas depuis le dashboard, PAS codée en dur (contrairement à une politique Intune, qui
    vérifie des réglages connus à l'avance). Contrat volontairement le plus simple possible,
    sans schéma JSON structuré : le script se termine par `exit 0` (conforme) ou tout code non
    nul (non conforme) — voir `ComplianceRunner` côté agent pour le piège PowerShell réel sur
    ce contrat, précisé EN TESTANT (`--compliance-diag`) : une exception NON interceptée
    (`throw`) échoue déjà correctement sur PowerShell 5.1 ; le vrai piège est une erreur NON
    TERMINANTE (`Write-Error` sans `-ErrorAction Stop`) qui reste CONFORME à tort sans un
    `exit` explicite.

    `enabled` par défaut à `False` — contrairement à une session shell (jalon 9, un humain tape
    et regarde en direct), une règle s'exécute SANS surveillance, périodiquement, sur tout le
    parc enrôlé : une règle fraîchement créée/éditée reste inactive tant qu'un second geste
    explicite ("Activer") n'a pas été fait, garde-fou bon marché contre une règle mal écrite
    qui partirait en direct sur tout le parc à la moindre faute de frappe.
    """

    __tablename__ = "compliance_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid_hex)
    name: Mapped[str] = mapped_column(String(255))
    script_content: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)


class DeviceGroup(Base):
    """Un groupe de postes (2026-09-08, demande de Nicolas — "ranger les postes dans des
    groupes si trop de devices et pas organisé", étendu le même soir avec les groupes
    dynamiques ; règles multi-critères + imbrication ajoutées le 2026-09-10 suite à une revue
    de la fonctionnalité comparée à Intune/Jamf/Tanium). Table STANDALONE, même motif que
    `ComplianceRule` (entité nommée simple) — AUCUNE relation ORM vers `Agent` : supprimer un
    groupe ne doit jamais supprimer les postes eux-mêmes.

    `rules` distingue les deux types de groupe :
    - `None` → groupe STATIQUE, membres = lignes `AgentGroupMembership` (affectation manuelle,
      un poste peut appartenir à plusieurs groupes statiques).
    - JSON `{"combinator": "all"|"any", "conditions": [{"field", "operator", "value"}, ...]}`
      → groupe DYNAMIQUE, membres calculés à la volée (voir `app/group_membership.py`) —
      AUCUNE affectation manuelle possible dessus (`routes/agents.py` refuse un
      `POST .../groups/{id}` vers un groupe dynamique).
    Les DEUX types peuvent en plus contenir des groupes ENFANTS (`DeviceGroupLink`) — leurs
    membres résolus s'ajoutent toujours à l'union, indépendamment de statique/dynamique.

    `pattern` (motif glob sur le nom, v1 du 2026-09-08) reste une colonne PHYSIQUE — jamais de
    `DROP COLUMN` dans ce projet — mais n'est plus lue nulle part : `scripts/
    migrate_add_group_rules_column.py` traduit tout `pattern` existant en une règle `rules`
    équivalente à un seul critère `{field: "hostname", operator: "glob", value: pattern}` au
    moment de l'ajout de la colonne `rules`."""

    __tablename__ = "device_groups"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid_hex)
    name: Mapped[str] = mapped_column(String(255))
    pattern: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # JSON sérialisé en texte, même convention que `AgentCommand.parameters` — parsé/sérialisé
    # au niveau de `routes/groups.py`, jamais un type JSON natif (portabilité SQLite simple).
    rules: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)

    # Politique de mise à jour Windows (2026-09-17, jalon "Mises à jour Vanitas" — maquette
    # validée par Nicolas). PERSISTANTE par groupe (contrairement à un push ponctuel type
    # "Pousser une application") : colonnes directement sur `DeviceGroup` plutôt qu'une table
    # séparée — relation 1:1 stricte, pas de raison d'un join pour ça. `patch_enabled=False`
    # par défaut, même garde-fou que `ComplianceRule.enabled` : un groupe fraîchement créé ne
    # patche jamais tant qu'un second geste explicite ("Activer") n'a pas eu lieu.
    patch_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # "HH:MM" en heure LOCALE du poste (jamais UTC — la fenêtre a un sens humain, "20h-6h",
    # comparée par l'agent à son horloge locale). Nullable : un groupe jamais configuré n'a pas
    # de fenêtre par défaut arbitraire, l'UI en impose une avant la première activation.
    patch_window_start: Mapped[str | None] = mapped_column(String(5), nullable=True)
    patch_window_end: Mapped[str | None] = mapped_column(String(5), nullable=True)
    # Délai de grâce (jours) avant redémarrage forcé si la fenêtre n'a jamais été atteinte (ex.
    # poste éteint chaque soir) — voir `PatchStatus.installed_at`, qui sert d'horloge de départ.
    patch_grace_days: Mapped[int] = mapped_column(default=5)


class AgentGroupMembership(Base):
    """Adhésion d'un poste à un groupe STATIQUE (2026-09-08) — table de jointure many-to-many,
    jamais une ligne pour un groupe dynamique (ses membres ne sont jamais stockés, voir
    `DeviceGroup.rules`). Table NEUVE → aucune migration nécessaire (`Base.metadata.
    create_all()` la crée seule, même précédent que `RevokedCertificate`/`DeviceGroup`
    elle-même). Clé composite plutôt qu'un id auto-incrémenté séparé : une paire (agent, groupe)
    ne peut exister qu'une fois, l'unicité est structurelle plutôt que vérifiée en code."""

    __tablename__ = "agent_group_memberships"

    agent_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    group_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)


class DeviceGroupLink(Base):
    """Groupes IMBRIQUÉS (2026-09-10) — un groupe PARENT contient un groupe ENFANT ; les
    membres résolus de l'enfant s'ajoutent aux membres propres du parent (règle et/ou adhésions
    manuelles), voir `app/group_membership.py::resolve_group_agents`. Table NEUVE → aucune
    migration nécessaire. Clé composite (comme `AgentGroupMembership`) : un même couple
    (parent, enfant) ne peut être lié qu'une fois. Aucune contrainte de cycle au niveau base —
    vérifiée en code avant toute écriture (`group_membership.py::would_create_cycle`), une
    contrainte SQL ne peut pas exprimer "pas de cycle transitif" simplement."""

    __tablename__ = "device_group_links"

    parent_group_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    child_group_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)


class PatchStatus(Base):
    """Dernier état connu du cycle de mise à jour Windows d'UN agent (2026-09-17, jalon "Mises
    à jour Vanitas") — le dernier envoi fait foi, même motif que `InventorySnapshot`/
    `ComplianceSnapshot` (pas un historique ligne par ligne, un seul upsert par agent).

    Les 4 listes (`available_json`/`todo_json`/`in_progress_json`/`installed_json`, JSON texte —
    même convention que `AgentCommand.parameters`/`DeviceGroup.rules`) reflètent le cycle de vie
    RÉEL d'une mise à jour côté agent (voir `PatchRunner.cs`, filtre `MsrcSeverity` Critical/
    Important de l'API COM Windows Update) :
      available   — détectée mais HORS périmètre (non sécurité, ou politique du groupe désactivée).
      todo        — sécurité, ciblée par une politique active, en file (prochain cycle).
      in_progress — téléchargement/pose en cours À CE MOMENT PRÉCIS sur le poste.
      installed   — posée sur le disque, il ne reste que le redémarrage.

    `installed_at` — posé la PREMIÈRE fois que l'agent rapporte `reboot_pending=true` (signal
    natif Windows, `RebootPending`/`Auto Update\\RebootRequired`, PAS une valeur inventée par
    ce serveur) ; sert d'horloge de départ pour le délai de grâce (`DeviceGroup.patch_grace_days`)
    — comparé côté SERVEUR (`routes/patch.py::_display_status`) pour rester la SEULE source de
    vérité du calcul, jamais recalculé différemment côté agent ou côté frontend. Remis à `None`
    dès que l'agent rapporte `reboot_pending=false` (poste réellement redémarré, nouveau cycle).
    `forced_at` — horodatage du moment où le délai de grâce a été dépassé pour la PREMIÈRE fois
    (visible dans le journal du poste), jamais réinitialisé avant le prochain redémarrage réel.

    Pas de `ForeignKey` vers `Agent` — même raisonnement que `ShellSession`/`ComplianceResult` :
    une trace de "on a dû forcer ce poste" doit survivre à un retrait de l'inventaire, pas
    disparaître silencieusement avec l'agent."""

    __tablename__ = "patch_status"

    agent_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    available_json: Mapped[str] = mapped_column(Text, default="[]")
    todo_json: Mapped[str] = mapped_column(Text, default="[]")
    in_progress_json: Mapped[str] = mapped_column(Text, default="[]")
    installed_json: Mapped[str] = mapped_column(Text, default="[]")
    installed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    forced_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow, onupdate=_utcnow)


class ComplianceSnapshot(Base):
    """Un envoi de résultats de conformité par un agent — jalon 11, même motif que
    `InventorySnapshot` (le dernier snapshot d'un agent fait foi). Créé par l'agent, que ce
    soit via son cycle périodique (`ComplianceLoop`) ou la commande à la demande
    ("compliance_check") — les deux appellent le même `ComplianceRunner.RunNowAsync`."""

    __tablename__ = "compliance_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(32), ForeignKey("agents.id"), index=True)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)

    agent: Mapped["Agent"] = relationship(back_populates="compliance_snapshots")
    results: Mapped[list["ComplianceResult"]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )


class ComplianceResult(Base):
    """Le résultat d'UNE règle pour UN snapshot — jalon 11.

    `rule_id` est volontairement une simple colonne indexée, PAS une `ForeignKey` vers
    `ComplianceRule` — raison DIFFÉRENTE de l'absence de FK sur `ShellSessionEvent` (qui, elle,
    survit à la suppression de l'AGENT) : ici, l'historique déjà posté doit survivre à
    l'édition/suppression ultérieure de la RÈGLE elle-même, sans quoi renommer ou retirer une
    règle du catalogue corromprait ou ferait disparaître les résultats déjà enregistrés.
    `rule_name` est donc dénormalisé (capturé au moment du contrôle), même motif que
    `CveFinding` qui fige ses données plutôt que de dépendre d'une jointure live.

    `compliant` est un booléen NULLABLE (tri-état), pas un simple booléen : `None` signale une
    ERREUR D'EXÉCUTION (timeout, échec de lancement de PowerShell...), distincte d'un VRAI
    contrôle qui a tourné et trouvé un problème (`False`) — les confondre fausserait le
    classement "règles en échec par impact" de la vue d'ensemble. `detail` porte la preuve
    (sortie du script) ou la raison de l'erreur dans les deux cas."""

    __tablename__ = "compliance_results"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("compliance_snapshots.id"), index=True
    )
    rule_id: Mapped[str] = mapped_column(String(32))
    rule_name: Mapped[str] = mapped_column(String(255))
    compliant: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    snapshot: Mapped["ComplianceSnapshot"] = relationship(back_populates="results")


class AuditEvent(Base):
    """Journal d'activité (2026-09-09, demande de Nicolas — "changer Commandes en onglet de
    Log pour chaque action... un identifiant sur ce qu'il touche, filtrable, qui a créé quoi").

    Couvre les mutations admin qui n'étaient enregistrées NULLE PART avant ce jalon : créer/
    modifier/supprimer/activer une règle de conformité, ajouter/supprimer un installeur,
    pousser vers un groupe, créer/modifier/supprimer un groupe, ajouter/retirer un poste d'un
    groupe, retirer un poste de l'inventaire. Les commandes envoyées à un poste
    (`AgentCommand`, déjà journalisées depuis le jalon 4) restent dans leur propre table —
    `GET /activity-log` (routes/activity.py) fusionne les deux à la lecture plutôt que de les
    dupliquer dans un même schéma, chacune gardant son propre contrat de champs.

    `category` — un des 4 identifiants filtrables demandés : "poste"/"application"/
    "conformite"/"groupe". `target_label` dénormalisé (nom au moment de l'action, pas une FK)
    — même raisonnement que `ComplianceResult.rule_name` : supprimer la cible plus tard ne doit
    jamais corrompre ou faire disparaître l'historique déjà enregistré. `actor` — voir
    `AgentCommand.actor` pour pourquoi c'est Pandore, jamais ce serveur, qui connaît ce nom.

    Table NEUVE → aucune migration nécessaire (`Base.metadata.create_all()` la crée seule)."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow, index=True)
    category: Mapped[str] = mapped_column(String(20), index=True)
    action: Mapped[str] = mapped_column(String(30))
    target_label: Mapped[str] = mapped_column(String(255))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[str | None] = mapped_column(String(100), nullable=True)


class InstallerPackage(Base):
    """Un installeur applicatif prêt à être poussé sur le parc (2026-09-08, demande de
    Nicolas — "un push d'application un peu comme dans Pandore, via les groupes"). Table
    NEUVE → aucune migration nécessaire (`Base.metadata.create_all()` la crée seule, même
    précédent que `DeviceGroup`/`AgentGroupMembership`/`RevokedCertificate`).

    Contrairement à la bibliothèque d'application de Pandore (qui ne garde jamais que le
    `.intunewin` — conteneur chiffré propre à l'agent Intune, inutilisable ici), le fichier
    stocké est TOUJOURS l'installeur brut (`.msi`/`.exe`/`.ps1`) : c'est l'agent Vanitas
    lui-même qui l'exécute, pas Intune. Fichier sur disque à
    `server/data/installers/<id>/<original_filename>`.

    `install_command` est une chaîne littérale déjà entièrement calculée (ex. `msiexec /i
    "7z2602-x64.msi" /qn /norestart`) — référence `original_filename` tel quel, jamais un
    template à substituer côté agent : l'agent télécharge le fichier SOUS CE NOM EXACT dans
    son répertoire de travail puis lance `install_command` avec ce répertoire comme
    `WorkingDirectory`, exactement le motif déjà validé côté Pandore (`Pandore.msi` +
    `msiexec /i Pandore.msi ...`).

    `sha256` calculé à l'upload, vérifié côté agent AVANT exécution — défense en profondeur
    contre une corruption de transport (le canal mTLS, durci EKU/SAN le 2026-09-08, protège
    déjà contre un serveur usurpé ; ceci ne couvre qu'un octet corrompu en cours de route)."""

    __tablename__ = "installer_packages"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid_hex)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    install_command: Mapped[str] = mapped_column(String(1000))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column()
    uploaded_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)


class AgentPackage(Base):
    """Un paquet de mise à jour de l'AGENT lui-même (2026-09-11, jalon "mise à jour de l'agent
    via Vanitas") — distinct d'`InstallerPackage` (installeurs APPLICATIFS poussés sur un
    poste) : ici c'est le binaire de Vanitas lui-même. Table NEUVE, aucune migration nécessaire.

    Toujours un `.msi` produit par `endpoint-agent/agent/Installer` (jamais un `.exe`/`.ps1`
    comme le catalogue d'installeurs) — le mécanisme `<MajorUpgrade>` déjà configuré dans
    `Product.wxs` (UpgradeCode stable) gère tout seul l'arrêt de l'ancienne version, le
    remplacement des fichiers et le redémarrage du service dès qu'on lui présente un `.msi`
    dont le `Package Version` est strictement supérieur à celui déjà installé — l'agent n'a
    donc qu'à lancer `msiexec /i <fichier> /qn /norestart`, jamais besoin de retrouver et
    désinstaller l'ancien ProductCode à la main (contrairement à `uninstall_agent`, dont le
    handler cherche explicitement ce ProductCode faute d'une telle mécanique).

    PLUSIEURS lignes conservées dans le temps (historique, jamais supprimées automatiquement à
    un nouvel upload) — seule la plus RÉCENTE (`uploaded_at` décroissant) compte comme version
    "courante" à pousser/comparer, même convention que le reste de ce projet pour ce genre de
    "dernier en date fait foi" (ex. `InstallerPackage` du catalogue applicatif, qui grossit
    lui aussi sans purge automatique — limitation déjà connue, pas un oubli).

    `version` est LIBRE (saisie par l'admin à l'upload) — pas déduite automatiquement du
    fichier MSI lui-même (lire le Package Version d'un .msi nécessite de le parser comme un
    fichier OLE structuré, hors de portée raisonnable pour ce jalon) ; à charge de l'admin de
    la faire correspondre au `<Package Version>` réel qu'il vient de builder, pour que la
    comparaison de version (alerte automatique, §"vanitas_alert_state") reste cohérente.

    Fichier sur disque à `server/data/agent_packages/<id>/<original_filename>`."""

    __tablename__ = "agent_packages"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid_hex)
    version: Mapped[str] = mapped_column(String(100))
    original_filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column()
    uploaded_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)


class CveFinding(Base):
    """Une CVE applicable à un produit, pour une plage de version donnée.

    Une ligne par (produit, CVE, condition de version) — un même couple (produit, CVE) peut
    avoir plusieurs lignes si NVD liste plusieurs plages disjointes. Remplacées en bloc à
    chaque rafraîchissement du produit concerné (delete+recreate), pas de mise à jour ligne à
    ligne — cohérent avec l'échelle visée par ce projet.
    """

    __tablename__ = "cve_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    product_name: Mapped[str] = mapped_column(String(500), index=True)
    cve_id: Mapped[str] = mapped_column(String(30), index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    published: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    version_start_including: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version_start_excluding: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version_end_including: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version_end_excluding: Mapped[str | None] = mapped_column(String(100), nullable=True)
    exact_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)


class SuspiciousEvent(Base):
    """Un événement de détection comportementale remonté par un agent — jalon "Activités
    suspectes". Filtrage fait CÔTÉ AGENT (`Detection/SuspiciousActivityRuleEngine.cs`) : seuls
    les événements qui matchent déjà une règle atteignent cette table, jamais un firehose brut.

    Volontairement SANS `ForeignKey`/relation vers `Agent`, même motif que `ShellSession`
    ci-dessus (docstring l.234-251) : c'est un journal d'audit sécurité (quel poste a déclenché
    quelle détection, quand) qui doit survivre à `DELETE /agents/{id}` — un poste retiré de
    l'inventaire (compromis, décommissionné) ne doit jamais effacer les preuves déjà remontées
    à son sujet. `hostname` est en plus DÉNORMALISÉ à l'ingestion (contrairement à `ShellSession`,
    qui n'a pas cette colonne et perd l'info du poste une fois l'agent supprimé) : nécessaire
    pour que la vue de triage reste filtrable/lisible par nom de poste après un retrait
    d'inventaire, pas seulement par l'`agent_id` opaque.

    `signal_type` — `"process"|"event_log"|"network"|"usb"`, un des 4 signaux du jalon.
    `severity` — `"low"|"med"|"high"`, vocabulaire aligné sur les tokens CSS `--low/--med/--high`
    déjà "sacrés" du design system (voir `docs/internal/ARCHITECTURE.md` §6), PAS le vocabulaire Defender.
    `matched_rule` — identifiant STABLE de règle (ex. "process-lolbin-certutil-decode"), jamais
    du texte libre, à l'image de `command_type`/`rule_id` ailleurs dans ce fichier. `detail`
    (JSON sérialisé en texte, même convention que `AgentCommand.parameters`/`DeviceGroup.rules`)
    porte les champs structurés propres à la catégorie (ex. ligne de commande complète, PID,
    port distant) — jamais typé en colonnes dédiées, un signal réseau et un signal USB n'ont pas
    la même forme de preuve.

    Idempotence : `local_event_id` est un GUID généré par l'agent à l'enfilage dans son buffer
    local — indispensable pour qu'un replay du même lot après un timeout réseau (l'agent ne
    retire un événement de son buffer qu'après un POST 2xx réussi, voir le plan) ne duplique
    rien côté serveur. La contrainte unique porte sur `(agent_id, local_event_id)` et non sur
    `local_event_id` seul : un GUID est déjà globalement unique par construction, mais scoper la
    contrainte à l'agent documente explicitement que l'idempotence est une propriété PAR AGENT
    (deux agents ne partagent jamais d'espace d'id), pas une coïncidence de génération de GUID.

    Cycle de vie de `status` : `new` (posé à l'ingestion) → `acknowledged`/`false_positive`/
    `escalated` (triage) ; `acknowledged` → `false_positive`/`escalated` (un événement accusé
    réception peut encore être requalifié). Toute autre transition est refusée par la route
    (`routes/suspicious_activity.py`) — `false_positive`/`escalated` sont des états terminaux.
    `handled_by`/`handled_at`/`handled_note` — même raisonnement que `AgentCommand.actor` : ce
    serveur n'a lui-même aucune notion de compte (`require_shell_token`, un secret partagé),
    c'est Pandore qui connaît l'utilisateur connecté et transmet son nom à chaque triage.

    Exclu de la purge de rétention (`routes/maintenance.py`) — même traitement que
    `shell_sessions`/`shell_session_events` : c'est un journal d'audit sécurité, pas une donnée
    opérationnelle qui grossit sans être relue (le volume reste bas par construction, le
    filtrage étant déjà fait côté agent avant l'envoi)."""

    __tablename__ = "suspicious_events"
    __table_args__ = (
        UniqueConstraint("agent_id", "local_event_id", name="uq_suspicious_events_agent_local_event"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid_hex)
    agent_id: Mapped[str] = mapped_column(String(32), index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    signal_type: Mapped[str] = mapped_column(String(20), index=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    matched_rule: Mapped[str] = mapped_column(String(100))
    summary: Mapped[str] = mapped_column(String(500))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    local_event_id: Mapped[str] = mapped_column(String(64), index=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    handled_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    handled_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    handled_note: Mapped[str | None] = mapped_column(Text, nullable=True)
