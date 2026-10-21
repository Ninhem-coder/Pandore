"""
API REST locale (FastAPI) exposant les outils Defender + Intune au dashboard React.

Ce n'est pas le protocole MCP à proprement parler (les serveurs MCP stdio sont dans
defender/mcp_server.py et intune/mcp_server.py, pour Claude Desktop) : c'est une couche
HTTP simple par-dessus les mêmes fonctions Python (sous-modules par domaine de
defender/ et intune/ — voir defender/mcp_server.py et intune/mcp_server.py pour la
liste), pour que le frontend React puisse les appeler avec un `fetch()` classique.

Lancer : python api_server.py   (écoute sur http://localhost:8000)
"""
import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Après le découpage en routers (2026-09-12), ce fichier ne garde que l'infrastructure (app,
# middleware, lifespan, boucles de fond, health) — les imports ci-dessous sont donc réduits à
# ce que CES éléments utilisent (les tools des routes sont importés par chaque router). Les
# boucles de fond (_take_history_snapshot / _vanitas_*_loop) consomment defender/intune/vanitas.
from auth import store as auth_store
from common import history, notify
from common.config import CORS_ORIGIN
from defender import machines as defender_machines_tools
from defender import vulnerabilities as defender_vulnerabilities_tools
from defender import watchlist as defender_watchlist
from intune import devices as intune_devices_tools
from vanitas import alert_state as vanitas_alert_state
from vanitas import client as vanitas_client
from vanitas import eol as vanitas_eol

# Symboles partagés + routers par domaine (voir api_common.py / backend/routers/*). Chaque
# router expose un `APIRouter` inclus plus bas (`app.include_router(...)`).
from api_common import SESSION_COOKIE_NAME, VANITAS_ALERT_STALE_HOURS
from routers import auth as auth_router
from routers import defender as defender_router
from routers import intune as intune_router
from routers import vanitas as vanitas_router

# Fréquence de re-vérification automatique des CVE suivies ("Suivi CVE", voir
# defender/watchlist.py) — configurable via backend/.env pour le debug (ex.
# WATCHLIST_REFRESH_SECONDS=60 pour observer un cycle sans attendre 1h). 3600s (1h) par
# défaut : compromis entre fraîcheur et volume d'appels Advanced Hunting + catalogue CVE
# (un appel Graph par CVE suivie en plus de la requête KQL, voir search_vulnerabilities)
# sur un parc de cette taille (~1 000 appareils).
WATCHLIST_REFRESH_SECONDS = int(os.environ.get("WATCHLIST_REFRESH_SECONDS", "3600"))


async def _watchlist_refresh_loop():
    """Boucle de fond, démarrée une seule fois au lancement du process (voir `lifespan`
    ci-dessous). Attend un premier cycle complet avant de rafraîchir : `add_watched_cve`
    (defender/watchlist.py) vérifie déjà immédiatement toute CVE nouvellement ajoutée, donc
    ce n'est qu'à partir du DEUXIÈME rafraîchissement que cette boucle apporte quelque chose
    — pas de vérification en double au démarrage."""
    while True:
        await asyncio.sleep(WATCHLIST_REFRESH_SECONDS)
        try:
            # search_vulnerabilities fait des appels httpx *synchrones* (voir
            # defender/client.py) — `to_thread` évite de bloquer la boucle asyncio (donc
            # TOUTES les requêtes HTTP de l'API, y compris celles d'autres onglets) pendant
            # potentiellement plusieurs secondes par CVE suivie.
            await asyncio.to_thread(defender_watchlist.refresh_all_watched_cves)
        except Exception:
            # Ne doit JAMAIS interrompre définitivement la boucle : une erreur (réseau,
            # auth MDE expirée…) sur un cycle ne doit pas empêcher le suivant, 1h plus tard,
            # de retenter.
            logging.getLogger(__name__).exception("Échec du rafraîchissement de fond des CVE suivies")


# Fréquence de VÉRIFICATION (pas de prise de snapshot elle-même — voir common/history.py) :
# un point d'historique n'est calculé qu'une fois par jour calendaire au maximum
# (`has_snapshot_today`), donc ce délai n'a besoin d'être ni précis ni court — il borne
# juste combien de temps après minuit le point du jour peut apparaître si le backend tourne
# en continu. Volontairement plus fréquent que WATCHLIST_REFRESH_SECONDS (pas le même besoin :
# ici on veut surtout ne pas rater le jour si le backend est redémarré souvent).
HISTORY_SNAPSHOT_CHECK_SECONDS = int(os.environ.get("HISTORY_SNAPSHOT_CHECK_SECONDS", "3600"))


def _take_history_snapshot() -> None:
    """Calcule le point du jour à partir des résumés Intune/Defender déjà exposés par le
    dashboard (aucun nouvel appel Graph/MDE dédié) et l'enregistre via
    `common.history.record_snapshot`.

    Chaque domaine (Intune, Defender) est calculé indépendamment et défensivement : si l'un
    échoue (permission manquante, tenant indisponible), l'autre est quand même enregistré —
    voir `common.history.record_snapshot`, qui accepte `None` pour un domaine en erreur.
    """
    intune_point = None
    try:
        summary = intune_devices_tools.get_intune_summary()
        if not (isinstance(summary, dict) and summary.get("error")):
            total = summary.get("totalDevices") or 0
            compliant = summary.get("compliantCount") or 0
            intune_point = {
                "totalDevices": total,
                "nonCompliantCount": summary.get("nonCompliantCount") or 0,
                # Même formule STRICTE que get_intune_summary (compliantCount / total, voir sa
                # docstring), recalculée en nombre plutôt que de parser la chaîne "85.5%"
                # d'affichage — None si le parc est vide.
                "complianceRate": round(compliant / total * 100, 1) if total else None,
                # Marqueur de formule (2026-10-21) : common/history.py::get_history écarte le
                # taux des points antérieurs (formule "total - noncompliant", plus indulgente)
                # pour ne pas fabriquer une fausse baisse dans les tendances 7/30 j.
                "complianceRateRule": history.COMPLIANCE_RATE_RULE,
            }
    except Exception:
        logging.getLogger(__name__).exception("Échec du calcul du point d'historique Intune")

    defender_point = None
    try:
        summary = defender_machines_tools.get_defender_summary()
        exposure = defender_vulnerabilities_tools.get_exposure_score()
        non_onboarded = defender_machines_tools.list_non_onboarded_machines()
        if not (isinstance(summary, dict) and summary.get("error")):
            defender_point = {
                "totalMachines": summary.get("totalMachines"),
                "exposureScore": exposure.get("score") if isinstance(exposure, dict) and not exposure.get("error") else None,
                "nonOnboardedCount": len(non_onboarded) if isinstance(non_onboarded, list) and not (non_onboarded and isinstance(non_onboarded[0], dict) and non_onboarded[0].get("error")) else None,
            }
    except Exception:
        logging.getLogger(__name__).exception("Échec du calcul du point d'historique Defender")

    vanitas_point = _compute_vanitas_history_point()

    history.record_snapshot(intune_point, defender_point, vanitas_point)


def _compute_vanitas_history_point() -> dict | None:
    """Point d'historique quotidien du parc Vanitas (jalon "tendances Vanitas", 2026-09-17) —
    calculé à partir des résumés fleet-wide DÉJÀ exposés par le serveur Vanitas (aucun nouvel
    endpoint dédié), au même titre que les points Intune/Defender. Renvoie `None` si le serveur
    Vanitas est injoignable/non configuré (un point sans domaine Vanitas ce jour-là, pas de crash).

    Chaque sous-métrique est défensive : une brique en erreur (ex. EOL, qui dépend de l'API
    externe endoflife.date) retombe sur `None` pour ce champ sans faire échouer tout le point.
    Le taux de conformité reprend EXACTEMENT la formule de la tuile KPI de l'overview Vanitas
    (`VanitasOverviewTab.jsx` : évaluations conformes / total, toutes règles confondues) pour que
    la courbe et l'instantané ne divergent jamais."""
    agents = vanitas_client.list_agents()
    if not isinstance(agents, list) or (agents and isinstance(agents[0], dict) and agents[0].get("error")):
        return None

    now = datetime.now(timezone.utc)

    def _is_online(agent: dict) -> bool:
        raw = agent.get("last_seen")
        if not raw:
            return False
        try:
            seen = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return False
        return (now - seen).total_seconds() <= 24 * 3600  # même seuil que isOnline (frontend)

    point: dict = {
        "totalAgents": len(agents),
        "onlineAgents": sum(1 for a in agents if _is_online(a)),
        "complianceRate": None,
        "patchOk": None,
        "patchPending": None,
        "patchOff": None,
        "suspiciousNew": None,
        "suspiciousHigh": None,
        "eolOccurrences": None,
    }

    try:
        rows = vanitas_client.get_compliance_summary()
        if isinstance(rows, list) and not (rows and isinstance(rows[0], dict) and rows[0].get("error")):
            ok = sum(r.get("compliant_count", 0) for r in rows)
            total = sum(
                r.get("compliant_count", 0) + r.get("non_compliant_count", 0) + r.get("error_count", 0)
                for r in rows
            )
            point["complianceRate"] = round(ok / total * 100, 1) if total else None
    except Exception:
        logging.getLogger(__name__).exception("Point d'historique Vanitas : conformité")

    try:
        patch = vanitas_client.get_patch_status()
        if isinstance(patch, list) and not (patch and isinstance(patch[0], dict) and patch[0].get("error")):
            point["patchOff"] = sum(1 for e in patch if e.get("status") == "off")
            point["patchOk"] = sum(1 for e in patch if e.get("status") == "ok")
            # Tout ce qui n'est ni "à jour" ni "hors politique" = un patch en cours de cycle
            # (attente d'installation/fenêtre, installation, forcé).
            point["patchPending"] = sum(
                1 for e in patch if e.get("status") not in ("off", "ok")
            )
    except Exception:
        logging.getLogger(__name__).exception("Point d'historique Vanitas : patch")

    try:
        susp = vanitas_client.get_suspicious_events_summary()
        if isinstance(susp, dict) and not susp.get("error"):
            point["suspiciousNew"] = (susp.get("by_status") or {}).get("new")
            point["suspiciousHigh"] = (susp.get("by_severity") or {}).get("high")
    except Exception:
        logging.getLogger(__name__).exception("Point d'historique Vanitas : activités suspectes")

    # EOL : best-effort, dépend de l'API externe endoflife.date (via vanitas_eol.detect_eol) et
    # nécessite l'inventaire de chaque poste — enveloppé à part, `None` si quoi que ce soit
    # échoue plutôt que de perdre les autres métriques du point.
    try:
        eol_total = 0
        for a in agents:
            inv = vanitas_client.get_agent_inventory(a.get("id"))
            if isinstance(inv, dict) and not inv.get("error"):
                eol_total += sum(1 for f in vanitas_eol.detect_eol(inv) if f.get("is_eol"))
        point["eolOccurrences"] = eol_total
    except Exception:
        logging.getLogger(__name__).exception("Point d'historique Vanitas : EOL")

    return point


async def _history_snapshot_loop():
    """Boucle de fond : vérifie régulièrement si un point d'historique existe déjà pour
    AUJOURD'HUI et, sinon, le calcule — voir common/history.py pour le format et la
    politique de rétention (90 jours). Contrairement à _watchlist_refresh_loop, une
    vérification a lieu DÈS le démarrage (pas seulement après le premier délai) : c'est ce
    qui garantit qu'ouvrir le dashboard au moins une fois par jour suffit à obtenir un
    point, même si le process ne tourne que quelques minutes."""
    while True:
        try:
            # `has_complete_snapshot_today` (2026-10-21) et non plus `has_snapshot_today` : un
            # point du jour PARTIEL (Intune ou Defender en erreur au moment du calcul, ex.
            # démarrage sans identifiants) bloquait la journée entière — le Dashboard est resté
            # figé un mois sur le dernier point complet. Il est désormais retenté à chaque tour.
            if not history.has_complete_snapshot_today():
                await asyncio.to_thread(_take_history_snapshot)
        except Exception:
            logging.getLogger(__name__).exception("Échec de la vérification/prise d'historique quotidienne")
        await asyncio.sleep(HISTORY_SNAPSHOT_CHECK_SECONDS)


# Rétention de l'historique Vanitas (2026-09-08, demande de Nicolas — "le filtre de 7j/14j/
# 30j/90j, et au-delà tu supprimes") : 90 jours par défaut, même ordre de grandeur que
# `common/history.py::RETENTION_DAYS` (déjà 90 jours dans ce projet, pas une valeur inventée
# pour l'occasion). Portée par CE backend (Pandore), pas par une tâche de fond dans le
# codebase Vanitas lui-même — décision explicite de Nicolas : Vanitas n'expose que le
# mécanisme brut (`vanitas_client.purge_history`), la DÉCISION de quand/à quel seuil purger
# vit ici, au même endroit que le reste des boucles de fond de ce dashboard.
VANITAS_PURGE_RETENTION_DAYS = int(os.environ.get("VANITAS_PURGE_RETENTION_DAYS", "90"))
VANITAS_PURGE_CHECK_SECONDS = int(os.environ.get("VANITAS_PURGE_CHECK_SECONDS", str(24 * 3600)))


async def _vanitas_purge_loop():
    """Boucle de fond — purge l'historique Vanitas (conformité/commandes/inventaire, JAMAIS le
    journal d'audit des sessions terminal, exclu côté serveur Vanitas) au-delà de
    `VANITAS_PURGE_RETENTION_DAYS` jours, une fois par `VANITAS_PURGE_CHECK_SECONDS` (1 jour par
    défaut). Contrairement à `_history_snapshot_loop`, la purge est idempotente par nature
    (relancer sur des lignes déjà supprimées ne fait juste rien de plus) : pas besoin d'un
    équivalent `has_snapshot_today`, un simple minuteur suffit. Si le serveur Vanitas n'est pas
    configuré/joignable, `purge_history` (décorée `@handle_tool_errors`) renvoie un dict
    d'erreur plutôt que de lever — jamais de crash de cette boucle pour autant."""
    while True:
        try:
            result = await asyncio.to_thread(vanitas_client.purge_history, VANITAS_PURGE_RETENTION_DAYS)
            if isinstance(result, dict) and result.get("error"):
                logging.getLogger(__name__).warning(
                    "Purge de l'historique Vanitas ignorée (serveur indisponible ou non configuré) : %s",
                    result.get("message"),
                )
        except Exception:
            logging.getLogger(__name__).exception("Échec de la purge de l'historique Vanitas")
        await asyncio.sleep(VANITAS_PURGE_CHECK_SECONDS)


# Alertes Vanitas (2026-09-08, jalons "agent silencieux" + "alertes diff") — voir
# vanitas/alert_state.py pour le format d'état persisté et common/notify.py pour l'envoi.
# Seuil VOLONTAIREMENT plus strict que le seuil "watchlist" de 7 jours déjà utilisé côté
# frontend (vanitasShared.jsx, pour classer un poste "à surveiller" dans "Vue d'ensemble") :
# ici on veut détecter une vraie coupure le jour même (le besoin qui a motivé ce jalon — un
# poste silencieux depuis ~20h découvert seulement à la main), pas un simple poste négligé
# depuis longtemps.
# VANITAS_ALERT_STALE_HOURS est défini dans api_common.py (partagé avec routers/vanitas.py) et
# importé en tête de ce fichier — utilisé ci-dessous par la boucle `_vanitas_agent_health_loop`.
VANITAS_ALERT_CHECK_SECONDS = int(os.environ.get("VANITAS_ALERT_CHECK_SECONDS", "3600"))
# Alerte d'expiration de certificat (2026-09-08) — même seuil que la tuile "Certificat < 30J"
# déjà affichée côté frontend (vanitasShared.jsx::CERT_WARNING_DAYS), reprise ici comme défaut
# cohérent plutôt qu'une valeur inventée pour l'occasion (les deux restent indépendamment
# configurables si Nicolas veut un jour les faire diverger).
VANITAS_ALERT_CERT_WARNING_DAYS = int(os.environ.get("VANITAS_ALERT_CERT_WARNING_DAYS", "30"))


def _parse_agent_version(raw: str | None) -> tuple[int, ...] | None:
    """Convertit "1.2.10" en (1, 2, 10) pour une comparaison NUMÉRIQUE plutôt que lexicographique
    (jalon "mise à jour de l'agent via Vanitas", 2026-09-11) — une comparaison de chaînes brutes
    classerait "1.9.0" > "1.10.0", faux dès la deuxième version à deux chiffres. `None` si le
    format ne ressemble pas à une version dotée d'entiers (jamais planter sur une valeur
    inattendue, juste renoncer à comparer pour cet agent)."""
    if not raw:
        return None
    parts = raw.strip().split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


async def _vanitas_agent_health_loop():
    """Boucle de fond — notifie (email, voir common/notify.py) et journalise
    (vanitas/alert_state.py::record_event) quand un agent ne s'est pas manifesté
    (`last_seen`) depuis plus de VANITAS_ALERT_STALE_HOURS, OU quand son certificat expire
    dans moins de VANITAS_ALERT_CERT_WARNING_DAYS jours. Édge-triggered pour les deux : ne
    notifie QUE sur la transition "pas encore signalé → en alerte" (`stale_alerted`/
    `cert_alerted` en état persisté), jamais à chaque cycle ; réarmé dès que `last_seen`
    progresse à nouveau ou que le certificat est renouvelé (pas de notification de retour à la
    normale — non demandé).

    Mise à jour d'agent (2026-09-11, revu le même jour) : cadrage INITIAL de Nicolas
    ("on peut avoir les deux ?") était bouton manuel + alerte purement informative, JAMAIS de
    push automatique. Nicolas est revenu dessus explicitement ("je veux que ce soit
    automatique") — cette boucle pousse désormais réellement la commande `update_agent` sur
    l'edge où elle alertait déjà auparavant, en plus de journaliser/notifier. Toujours
    édge-triggered sur la VERSION CIBLE (`update_alerted_version`, un seul champ pour les deux
    actions — alerte et push partagent le même déclencheur)."""
    while True:
        try:
            agents = await asyncio.to_thread(vanitas_client.list_agents)
            if isinstance(agents, list) and not (agents and isinstance(agents[0], dict) and agents[0].get("error")):
                # Version cible pour la mise à jour d'agent (2026-09-11) — récupérée UNE FOIS
                # par cycle, pas par agent : c'est le même paquet AgentPackage pour tout le parc.
                latest_package = await asyncio.to_thread(vanitas_client.get_latest_agent_package)
                latest_version = latest_package.get("version") if isinstance(latest_package, dict) and not latest_package.get("error") else None
                latest_package_id = latest_package.get("id") if isinstance(latest_package, dict) and not latest_package.get("error") else None
                latest_version_parsed = _parse_agent_version(latest_version)

                now = datetime.now(timezone.utc)
                for agent in agents:
                    agent_id = agent.get("id")
                    hostname = agent.get("hostname") or agent_id
                    last_seen_raw = agent.get("last_seen")
                    last_seen = None
                    if last_seen_raw:
                        try:
                            last_seen = datetime.fromisoformat(last_seen_raw.replace("Z", "+00:00"))
                        except ValueError:
                            last_seen = None
                    is_stale = last_seen is None or (now - last_seen).total_seconds() > VANITAS_ALERT_STALE_HOURS * 3600
                    state = vanitas_alert_state.get_agent_state(agent_id)
                    if is_stale and not state.get("stale_alerted"):
                        message = (
                            f"« {hostname} » ne s'est pas manifesté depuis "
                            f"{'jamais' if last_seen is None else last_seen.isoformat()} "
                            f"(seuil d'alerte : {VANITAS_ALERT_STALE_HOURS}h)."
                        )
                        notify.send_email(f"[Vanitas] Poste silencieux : {hostname}", message)
                        vanitas_alert_state.record_event("stale", agent_id, hostname, message)
                        vanitas_alert_state.set_agent_state(agent_id, stale_alerted=True)
                    elif not is_stale and state.get("stale_alerted"):
                        vanitas_alert_state.set_agent_state(agent_id, stale_alerted=False)

                    cert_not_after_raw = agent.get("cert_not_after")
                    cert_not_after = None
                    if cert_not_after_raw:
                        try:
                            cert_not_after = datetime.fromisoformat(cert_not_after_raw.replace("Z", "+00:00"))
                        except ValueError:
                            cert_not_after = None
                    days_left = (cert_not_after - now).total_seconds() / 86400 if cert_not_after else None
                    is_cert_expiring = days_left is not None and days_left < VANITAS_ALERT_CERT_WARNING_DAYS
                    if is_cert_expiring and not state.get("cert_alerted"):
                        message = (
                            f"Le certificat de « {hostname} » expire "
                            f"{'dans ' + str(round(days_left)) + ' jour(s)' if days_left >= 0 else 'DÉJÀ (expiré)'} "
                            f"(seuil d'alerte : {VANITAS_ALERT_CERT_WARNING_DAYS}j)."
                        )
                        notify.send_email(f"[Vanitas] Certificat bientôt expiré : {hostname}", message)
                        vanitas_alert_state.record_event("cert_expiring", agent_id, hostname, message)
                        vanitas_alert_state.set_agent_state(agent_id, cert_alerted=True)
                    elif not is_cert_expiring and state.get("cert_alerted"):
                        vanitas_alert_state.set_agent_state(agent_id, cert_alerted=False)

                    # Mise à jour d'agent disponible (2026-09-11) — édge-triggered sur la
                    # VERSION CIBLE, pas un simple booléen (contrairement à stale/cert) : si un
                    # admin uploade un NOUVEAU paquet plus récent pendant qu'un poste est déjà
                    # en retard, l'agent mérite une alerte fraîche pour cette nouvelle cible,
                    # pas un silence parce qu'il avait déjà été signalé pour l'ancienne. Aucune
                    # comparaison possible pour un agent qui n'a jamais remonté `agent_version`
                    # (avant le jalon traçabilité, 2026-09-08) — ignoré silencieusement, pas une
                    # erreur.
                    agent_version_parsed = _parse_agent_version(agent.get("agent_version"))
                    if latest_version_parsed is not None and agent_version_parsed is not None and latest_package_id:
                        is_outdated = agent_version_parsed < latest_version_parsed
                        already_alerted_for = state.get("update_alerted_version")
                        if is_outdated and already_alerted_for != latest_version:
                            # Push RÉEL (2026-09-11, revu) — avant de marquer l'edge comme
                            # traité, on tente d'abord la mise en file de la commande : un
                            # échec (serveur Vanitas injoignable, etc.) ne doit jamais être
                            # confondu avec "déjà géré", sinon ce poste resterait en retard
                            # indéfiniment sans jamais retenter.
                            # 🔧 Revue de sécurité du 2026-09-17 : cet appel passait ses arguments
                            # en POSITION alors que `queue_command` a gagné 2 paramètres
                            # (`event_log_query` le 2026-09-16, `event_id` le 2026-09-17) sans que
                            # ce site d'appel soit mis à jour — "auto-update" atterrissait dans
                            # `event_log_query` (jamais dans `actor`), que le serveur Vanitas
                            # rejette (422, `EventLogQueryIn` attend un objet, pas une chaîne),
                            # faisant échouer SILENCIEUSEMENT toute mise à jour automatique depuis
                            # le 2026-09-16. Corrigé en mots-clés — seul appelant de
                            # `queue_command` hors de `routers/vanitas.py`, donc le seul site
                            # exposé à ce risque de désynchronisation positionnelle.
                            queue_result = await asyncio.to_thread(
                                vanitas_client.queue_command,
                                agent_id,
                                "update_agent",
                                agent_package_id=latest_package_id,
                                actor="auto-update",
                            )
                            if isinstance(queue_result, dict) and queue_result.get("error"):
                                logging.getLogger(__name__).warning(
                                    "Échec de la mise en file automatique de update_agent pour %s : %s",
                                    hostname, queue_result.get("message"),
                                )
                                continue
                            message = (
                                f"« {hostname} » tourne en v{agent.get('agent_version')} — mise à jour vers "
                                f"v{latest_version} automatiquement mise en file (catalogue de mise à jour Vanitas)."
                            )
                            notify.send_email(f"[Vanitas] Mise à jour d'agent lancée : {hostname}", message)
                            vanitas_alert_state.record_event("agent_update_available", agent_id, hostname, message)
                            vanitas_alert_state.set_agent_state(agent_id, update_alerted_version=latest_version)
                        elif not is_outdated and already_alerted_for is not None:
                            vanitas_alert_state.set_agent_state(agent_id, update_alerted_version=None)
        except Exception:
            logging.getLogger(__name__).exception("Échec de la vérification des agents Vanitas silencieux")
        await asyncio.sleep(VANITAS_ALERT_CHECK_SECONDS)


async def _vanitas_diff_alert_loop():
    """Boucle de fond — notifie/journalise UNIQUEMENT sur une NOUVELLE vulnérabilité CRITICAL,
    un NOUVEL échec de conformité, OU une NOUVELLE occurrence EOL (2026-09-10, revue
    comparative — point 4 : "brancher l'EOL sur l'infra d'alertes déjà existante") par agent
    (jamais un rappel sur ce qui est déjà connu), en comparant l'ensemble courant à l'état
    persisté (vanitas/alert_state.py). Aucune route serveur Vanitas dédiée n'est nécessaire :
    `get_agent_vulnerabilities`/`get_agent_compliance`/`get_agent_inventory` (déjà utilisées
    ailleurs dans ce dashboard) suffisent, le "diff" vit entièrement ici."""
    while True:
        try:
            agents = await asyncio.to_thread(vanitas_client.list_agents)
            if isinstance(agents, list) and not (agents and isinstance(agents[0], dict) and agents[0].get("error")):
                for agent in agents:
                    agent_id = agent.get("id")
                    hostname = agent.get("hostname") or agent_id
                    state = vanitas_alert_state.get_agent_state(agent_id)

                    vulns = await asyncio.to_thread(vanitas_client.get_agent_vulnerabilities, agent_id)
                    if isinstance(vulns, list) and not (vulns and isinstance(vulns[0], dict) and vulns[0].get("error")):
                        current_critical = {
                            v.get("cve_id") for v in vulns if (v.get("severity") or "").upper() == "CRITICAL" and v.get("cve_id")
                        }
                        known_critical = set(state.get("known_critical_cves") or [])
                        for cve_id in current_critical - known_critical:
                            message = f"Nouvelle vulnérabilité critique sur « {hostname} » : {cve_id}."
                            notify.send_email(f"[Vanitas] Vulnérabilité critique : {hostname}", message)
                            vanitas_alert_state.record_event("new_critical_vuln", agent_id, hostname, message)
                        if current_critical != known_critical:
                            vanitas_alert_state.set_agent_state(agent_id, known_critical_cves=sorted(current_critical))

                    compliance = await asyncio.to_thread(vanitas_client.get_agent_compliance, agent_id)
                    if isinstance(compliance, dict) and not compliance.get("error"):
                        current_failing = {
                            r.get("rule_id")
                            for r in compliance.get("results") or []
                            if r.get("compliant") is False and r.get("rule_id")
                        }
                        known_failing = set(state.get("known_failing_rules") or [])
                        rule_names = {r.get("rule_id"): r.get("rule_name") for r in compliance.get("results") or []}
                        for rule_id in current_failing - known_failing:
                            rule_name = rule_names.get(rule_id, rule_id)
                            message = f"Nouvel échec de conformité sur « {hostname} » : {rule_name}."
                            notify.send_email(f"[Vanitas] Échec de conformité : {hostname}", message)
                            vanitas_alert_state.record_event("new_compliance_failure", agent_id, hostname, message)
                        if current_failing != known_failing:
                            vanitas_alert_state.set_agent_state(agent_id, known_failing_rules=sorted(current_failing))

                    # EOL (2026-09-10) — même diff, sur les occurrences renvoyées par
                    # `vanitas_eol.detect_eol` (déjà bornées aux cas "déjà EOL" ou "échéance
                    # proche" côté module, voir eol.py::EOL_UPCOMING_WINDOW_DAYS ; pas de seuil
                    # supplémentaire à répéter ici). Clé de diff = (type, name, version) plutôt
                    # que le message (qui varie de jour en jour, ex. "dans 45 jours" → "dans 44
                    # jours" — sans quoi CE MÊME constat re-déclencherait une notification
                    # chaque nuit).
                    inventory = await asyncio.to_thread(vanitas_client.get_agent_inventory, agent_id)
                    if isinstance(inventory, dict) and not inventory.get("error"):
                        eol_findings = vanitas_eol.detect_eol(inventory)
                        current_eol = {
                            f"{f['type']}::{f['name']}::{f.get('version') or ''}" for f in eol_findings
                        }
                        known_eol = set(state.get("known_eol_findings") or [])
                        findings_by_key = {
                            f"{f['type']}::{f['name']}::{f.get('version') or ''}": f for f in eol_findings
                        }
                        for key in current_eol - known_eol:
                            f = findings_by_key[key]
                            message = f"« {hostname} » — {f['name']} : {f['message']}"
                            notify.send_email(f"[Vanitas] Logiciel/OS bientôt obsolète : {hostname}", message)
                            vanitas_alert_state.record_event("new_eol_finding", agent_id, hostname, message)
                        if current_eol != known_eol:
                            vanitas_alert_state.set_agent_state(agent_id, known_eol_findings=sorted(current_eol))
        except Exception:
            logging.getLogger(__name__).exception("Échec de la vérification des alertes diff Vanitas")
        await asyncio.sleep(VANITAS_ALERT_CHECK_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    tasks = [
        asyncio.create_task(_watchlist_refresh_loop()),
        asyncio.create_task(_history_snapshot_loop()),
        asyncio.create_task(_vanitas_purge_loop()),
        asyncio.create_task(_vanitas_agent_health_loop()),
        asyncio.create_task(_vanitas_diff_alert_loop()),
    ]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()


app = FastAPI(title="Claude DSI Local — API Defender/Intune", lifespan=lifespan)

# ── Authentification multi-comptes (2026-09-07) ─────────────────────────────────────────
# Gate TOUT le dashboard dès le démarrage de l'app — voir backend/auth/ (store.py pour la
# persistance JSON comptes/sessions, __init__.py pour require_admin). Enregistré AVANT
# CORSMiddleware ci-dessous : Starlette empile les middlewares dans l'ordre INVERSE de leur
# enregistrement (le dernier ajouté devient le plus "extérieur", donc le premier à traiter la
# requête et le dernier à voir la réponse) — CORS doit rester le plus extérieur pour gérer les
# préflights OPTIONS et poser ses en-têtes avant que cette vérification de session ne
# s'applique. Court-circuite aussi explicitement tout OPTIONS en filet de sécurité,
# indépendamment de l'ordre réel des middlewares.
# SESSION_COOKIE_NAME importé d'api_common (partagé avec routers/auth.py).
_AUTH_PATH_ALLOWLIST = {"/api/auth/login", "/api/health"}


@app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path in _AUTH_PATH_ALLOWLIST:
        return await call_next(request)
    token = request.cookies.get(SESSION_COOKIE_NAME)
    user = auth_store.get_session(token) if token else None
    if user is None:
        return JSONResponse({"detail": "Authentification requise."}, status_code=status.HTTP_401_UNAUTHORIZED)
    request.state.user = user
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[CORS_ORIGIN],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,  # nécessaire pour que le cookie de session voyage si frontend et
    # backend finissent un jour sur des origines distinctes (transparent aujourd'hui grâce au
    # proxy Vite en dev, qui rend tout appel same-origin du point de vue du navigateur).
)


# En-têtes de sécurité (2026-09-12, durcissement) — enregistré APRÈS CORS, donc le plus
# extérieur : posé sur TOUTES les réponses, y compris les 401 du middleware d'auth. Cette API
# est purement JSON (ne sert pas le SPA — voir `uvicorn.run` en fin de fichier), donc pas de
# CSP ni HSTS ici : une CSP protégerait le HTML (servi par un autre hôte, hors de ce backend),
# et HSTS est sans objet tant que ce backend tourne en HTTP local. On pose les en-têtes
# universellement sûrs pour des réponses JSON — `nosniff` empêche un navigateur de deviner un
# type MIME autre que celui déclaré, `DENY`/`no-referrer` sont de la défense en profondeur
# gratuite sur des réponses qui ne devraient jamais être ni framées ni source d'un Referer.
@app.middleware("http")
async def _security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# ── Routers par domaine (2026-09-12) ────────────────────────────────────────────────────
app.include_router(auth_router.router)
app.include_router(defender_router.router)
app.include_router(intune_router.router)
app.include_router(vanitas_router.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import os

    import uvicorn

    # 127.0.0.1 par défaut. Depuis le 2026-09-07, cette API EXIGE une session valide
    # (comptes gérés via `manage_users.py`, voir backend/auth/) pour toute route sauf
    # `/api/auth/login`/`/api/health` — mais reste par défaut sur 127.0.0.1 : `SESSION_
    # COOKIE_SECURE=false` par défaut (cookie envoyé sur HTTP), donc pas encore sûr de
    # l'exposer tel quel sur 0.0.0.0/un réseau plus large sans revoir ce réglage d'abord.
    # `API_HOST=0.0.0.0` reste possible à activer explicitement si un accès distant est un
    # jour nécessaire.
    host = os.environ.get("API_HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=8000)
