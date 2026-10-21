"""Routes Defender (MDE) — /api/defender/* + /api/vanitas/cve-avis/{cve_id} (même module
`defender/anssi.py`, aucun aller-retour Vanitas). Déplacé de api_server.py le 2026-09-12."""
from typing import Optional

from fastapi import APIRouter, Depends, Query

from api_common import IdPath
from auth import require_admin, require_vanitas_read
from defender import alerts as defender_alerts_tools
from defender import anssi as defender_anssi
from defender import hunting as defender_hunting
from defender import machines as defender_machines_tools
from defender import vulnerabilities as defender_vulnerabilities_tools
from defender import watchlist as defender_watchlist
from pydantic import BaseModel

router = APIRouter()

# Bornes de pagination raisonnables : sans elles, `top` accepte n'importe quel entier (négatif
# ou énorme) et le transmet tel quel à Graph/MDE.
_TOP_DEFAULT_SMALL = Query(50, ge=1, le=1000)


class HuntingQueryBody(BaseModel):
    query: str


class WatchedCveBody(BaseModel):
    cve_code: str


@router.get("/api/defender/summary")
def defender_summary():
    return defender_machines_tools.get_defender_summary()


@router.get("/api/defender/machines")
def defender_machines(filter: Optional[str] = None, top: int = Query(100, ge=0, le=5000)):
    return defender_machines_tools.list_machines(filter=filter, top=top)


@router.get("/api/defender/machines/{machine_id}")
def defender_machine(machine_id: str = IdPath("ID natif Defender de la machine")):
    return defender_machines_tools.get_machine(machine_id=machine_id)


@router.get("/api/defender/alerts")
def defender_alerts(severity: Optional[str] = None, status: Optional[str] = None, top: int = _TOP_DEFAULT_SMALL):
    return defender_alerts_tools.list_alerts(severity=severity, status=status, top=top)


@router.get("/api/defender/machines/{machine_id}/alerts")
def defender_machine_alerts(machine_id: str = IdPath("ID natif Defender de la machine")):
    return defender_alerts_tools.get_machine_alerts(machine_id=machine_id)


@router.get("/api/defender/alerts/{alert_id}")
def defender_alert_detail(alert_id: str = IdPath("ID natif Defender de l'alerte")):
    return defender_alerts_tools.get_alert(alert_id=alert_id)


@router.get("/api/defender/non-onboarded")
def defender_non_onboarded(include_can_be_onboarded: bool = True):
    return defender_machines_tools.list_non_onboarded_machines(include_can_be_onboarded=include_can_be_onboarded)


@router.post("/api/defender/hunting-query")
def defender_hunting_query(body: HuntingQueryBody, _admin: None = Depends(require_admin)):
    # Admin-only (revue de sécurité du 2026-09-07) — passthrough SANS restriction vers Advanced
    # Hunting (n'importe quelle table KQL du tenant : process/réseau/registre/inventaire
    # complet), un accès nettement plus large que toute autre route accessible à un viewer.
    return defender_hunting.run_hunting_query(query=body.query)


# `min_length=2` évite une recherche par nom de logiciel sur 1 caractère ; `max_results` borne
# le nombre de CVE distinctes détaillées (voir docstring de search_vulnerabilities).
@router.get("/api/defender/vulnerabilities")
def defender_vulnerabilities(
    query: str = Query(..., min_length=2, max_length=200, description="CVE (ex. CVE-2024-3400) ou nom de logiciel/éditeur"),
    max_results: int = Query(20, ge=1, le=100),
):
    return defender_vulnerabilities_tools.search_vulnerabilities(query=query, max_results=max_results)


# ── Suivi CVE (CveWatchTab.jsx) — CVE "épinglées" pour re-vérification automatique, voir
# defender/watchlist.py.
@router.get("/api/defender/watched-cves")
def defender_watched_cves():
    return defender_watchlist.list_watched_cves()


# Mutations de la watchlist réservées admin (audit sécurité du 2026-09-17) — mise en cohérence
# avec TOUTES les autres écritures d'état de l'app (packaging/app-library Intune, hunting-query),
# elles aussi admin-only. Un `viewer` pouvait jusqu'ici modifier la watchlist et déclencher des
# cycles Advanced Hunting (écriture d'état + coût de calcul) ; la LECTURE (`GET`) reste ouverte.
@router.post("/api/defender/watched-cves")
def defender_add_watched_cve(body: WatchedCveBody, _admin: None = Depends(require_admin)):
    return defender_watchlist.add_watched_cve(body.cve_code)


@router.delete("/api/defender/watched-cves/{cve_code}")
def defender_remove_watched_cve(
    cve_code: str = IdPath("Identifiant CVE à ne plus suivre (ex. CVE-2024-3400)"),
    _admin: None = Depends(require_admin),
):
    return {"removed": defender_watchlist.remove_watched_cve(cve_code)}


@router.post("/api/defender/watched-cves/{cve_code}/refresh")
def defender_refresh_watched_cve(
    cve_code: str = IdPath("Identifiant CVE à re-vérifier immédiatement"),
    _admin: None = Depends(require_admin),
):
    return defender_watchlist.refresh_one(cve_code)


@router.get("/api/defender/exposure-score")
def defender_exposure_score():
    return defender_vulnerabilities_tools.get_exposure_score()


@router.get("/api/defender/recommendations")
def defender_recommendations(top: int = Query(20, ge=1, le=500)):
    return defender_vulnerabilities_tools.list_recommendations(top=top)


# ── CVE ANSSI/CERT-FR ↔ inventaire logiciel (2026-08-12) — voir defender/anssi.py.
@router.get("/api/defender/anssi-matches")
def defender_anssi_matches(
    window_days: int = Query(14, ge=1, le=60, description="Fenêtre en jours d'avis CERT-FR à considérer"),
    refresh: bool = Query(False, description="Contourne le cache 30 min et re-scrape cert.ssi.gouv.fr"),
):
    return defender_anssi.get_anssi_matches(window_days=window_days, force_refresh=refresh)


# ── CVE → avis CERT-FR (2026-09-10) — page "Vulnérabilités" de Vanitas, recherche directe par
# CVE précise (popup de détail), distincte de `defender_anssi_matches` (rapprochement fleet-wide
# par nom). Même module `defender/anssi.py`, aucun aller-retour vers le serveur Vanitas.
@router.get("/api/vanitas/cve-avis/{cve_id}")
def vanitas_cve_avis(
    cve_id: str = IdPath("Identifiant CVE"),
    _perm: None = Depends(require_vanitas_read("postes")),
):
    return defender_anssi.get_cve_avis(cve_id)


# ── Widgets/Vulnérabilités (2026-08-12+) — top logiciels/CVE, inventaire complet, certificats,
# top alertes, exposition par criticité. Voir defender/vulnerabilities.py.
@router.get("/api/defender/top-vulnerable-software")
def defender_top_vulnerable_software(top: int = Query(10, ge=1, le=50)):
    return defender_vulnerabilities_tools.get_top_vulnerable_software(top=top)


@router.get("/api/defender/top-vulnerabilities")
def defender_top_vulnerabilities(top: int = Query(50, ge=1, le=200)):
    return defender_vulnerabilities_tools.get_top_vulnerabilities(top=top)


# Inventaire COMPLET des CVE du parc, sans enrichissement catalogue — aucun paramètre `top`.
@router.get("/api/defender/vulnerability-inventory")
def defender_vulnerability_inventory():
    return defender_vulnerabilities_tools.get_vulnerability_inventory()


@router.get("/api/defender/expiring-certificates")
def defender_expiring_certificates(within_days: int = Query(90, ge=1, le=3650)):
    return defender_vulnerabilities_tools.get_expiring_certificates(within_days=within_days)


@router.get("/api/defender/top-alerts")
def defender_top_alerts(days: int = Query(7, ge=1, le=90), top: int = Query(10, ge=1, le=50)):
    return defender_alerts_tools.get_top_active_alerts(days=days, top=top)


# ── Secure Score > "Par criticité" (2026-08-12) — `level` volontairement une query string
# libre (pas un enum) : la fonction Python échappe déjà la valeur pour KQL et renvoie une liste
# vide si le niveau ne correspond à aucun device.
@router.get("/api/defender/exposure-vulnerable-apps")
def defender_exposure_vulnerable_apps(
    level: str = Query(..., min_length=1, max_length=20, description="Niveau d'exposition MDE : High, Medium, Low ou None"),
    top: int = Query(5, ge=1, le=20),
):
    return defender_vulnerabilities_tools.get_top_vulnerable_apps_by_exposure(level=level, top=top)


# Détail PAR DEVICE (2026-08-12, v2 de "Par criticité").
@router.get("/api/defender/machines/{machine_id}/vulnerable-software")
def defender_device_vulnerable_software(
    machine_id: str = IdPath("ID natif Defender de la machine"),
    top: int = Query(5, ge=1, le=20),
):
    return defender_vulnerabilities_tools.get_device_vulnerable_software(device_id=machine_id, top=top)
