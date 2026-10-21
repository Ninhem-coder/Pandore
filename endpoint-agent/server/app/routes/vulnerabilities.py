"""Endpoints de consultation des CVE rapprochées de l'inventaire d'un agent.

🔧 Revue de sécurité du 2026-09-07 : gatées par `require_shell_token` (même correctif que
`routes/agents.py`/`routes/commands.py`, voir leurs en-têtes) — exposaient l'inventaire logiciel
et l'exposition CVE de tout le parc sans authentification.

🔧 Revue du 2026-09-09 : `POST /agents/{id}/refresh-vulnerabilities` (rafraîchissement manuel
par agent, `cve_matching.refresh_agent`) retirée — jamais câblée côté proxy Pandore ni
frontend depuis sa création, donc du code mort pur (et une surface d'attaque en moins : un
appelant authentifié aurait pu la marteler pour épuiser le quota partagé de l'API NVD). Le
rafraîchissement automatique fleet-wide (`cve_matching.refresh_fleet`, boucle périodique) reste
la seule voie de mise à jour.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..cve_matching import is_version_affected
from ..db import get_db
from ..models import Agent, CveFinding, InventorySnapshot
from ..security import require_shell_token

router = APIRouter(tags=["vulnerabilities"])


class VulnerabilityOut(BaseModel):
    product_name: str
    installed_version: str | None
    cve_id: str
    cvss_score: float | None
    severity: str | None
    published: datetime | None
    # None = indéterminable (version non comparable) — jamais présenté comme une certitude
    # positive ou négative dans ce cas, voir cve_matching.is_version_affected.
    version_affected: bool | None


def _latest_snapshot(db: Session, agent_id: str) -> InventorySnapshot | None:
    return (
        db.query(InventorySnapshot)
        .filter(InventorySnapshot.agent_id == agent_id)
        .order_by(InventorySnapshot.collected_at.desc())
        .first()
    )


def vulnerabilities_for_snapshot(db: Session, snapshot: InventorySnapshot) -> list[VulnerabilityOut]:
    """Croise les apps d'un snapshot avec le cache CveFinding par nom de produit — réutilisée
    par l'endpoint de rafraîchissement manuel (même forme de résultat après un refresh).

    🔧 Bug réel corrigé (signalé par Nicolas — une même CVE affichée des dizaines de fois pour
    un même logiciel) : une CVE peut avoir PLUSIEURS lignes `CveFinding` pour un même produit
    (une par condition de version disjointe trouvée dans NVD — voir nvd_client.py). Le code
    d'origine renvoyait UNE ENTRÉE PAR LIGNE, sans les regrouper ni les filtrer — pour un
    logiciel avec un long historique de versions listées individuellement par NVD (ex.
    CVE-2008-6536 sur 7-Zip, 36 conditions de version disjointes, TOUTES `version_affected:
    False` pour un 7-Zip 26.02 installé), ça affichait 36 fois la "même" CVE, dont AUCUNE ne
    s'applique en réalité à la version installée — visuellement indiscernables (mêmes cve_id/
    cvss/sévérité), lues à tort comme des doublons plutôt que comme des conditions de version
    non pertinentes déjà écartées par le calcul `is_version_affected` lui-même.

    Regroupé ICI par (produit, cve_id) : `True` si AU MOINS une condition confirme que la
    version installée est concernée, `None` si aucune ne confirme mais qu'au moins une reste
    indéterminable (jamais tranché à tort), sinon EXCLU (toutes les conditions écartent
    positivement la version installée — ne jamais présenter un faux positif déjà écarté par le
    code lui-même comme un risque réel)."""
    results: list[VulnerabilityOut] = []
    for app in snapshot.apps:
        findings = db.query(CveFinding).filter(CveFinding.product_name == app.name).all()

        by_cve: dict[str, list[CveFinding]] = {}
        for finding in findings:
            by_cve.setdefault(finding.cve_id, []).append(finding)

        for cve_id, rows in by_cve.items():
            verdicts = [is_version_affected(app.version, row) for row in rows]
            if any(v is True for v in verdicts):
                affected: bool | None = True
            elif all(v is False for v in verdicts):
                continue  # aucune condition connue ne s'applique à la version installée
            else:
                affected = None  # au moins une condition indéterminable, jamais tranché à tort

            reference = rows[0]  # cvss/sévérité/date identiques pour un même cve_id
            results.append(VulnerabilityOut(
                product_name=app.name,
                installed_version=app.version,
                cve_id=cve_id,
                cvss_score=reference.cvss_score,
                severity=reference.severity,
                published=reference.published,
                version_affected=affected,
            ))

    results.sort(key=lambda v: (v.cvss_score is None, -(v.cvss_score or 0)))
    return results


class TopVulnerabilityOut(BaseModel):
    cve_id: str
    product_name: str
    cvss_score: float | None
    severity: str | None
    device_count: int


@router.get("/vulnerabilities/top", response_model=list[TopVulnerabilityOut])
def get_top_vulnerabilities(
    limit: int = 5, db: Session = Depends(get_db), _auth: None = Depends(require_shell_token)
) -> list[TopVulnerabilityOut]:
    """Top CVE les plus répandues sur le parc, jalon "Vue d'ensemble" (2026-09-06) — comptées
    par nombre d'AGENTS DISTINCTS affectés (pas par nombre de logiciels/versions concordantes) :
    une CVE qui touche 2 logiciels différents sur le même poste ne compte qu'une fois pour ce
    poste. Réutilise `vulnerabilities_for_snapshot` (déjà dédupliquée par (produit, cve_id) et
    déjà purgée des faux positifs de version, voir son docstring) sur le DERNIER snapshot de
    chaque agent, agrégé ICI en mémoire — un calcul dédié en base (table de comptage
    matérialisée) serait disproportionné à l'échelle visée par ce projet (une poignée d'agents,
    recalculé à chaque appel plutôt qu'à chaque rafraîchissement de CVE)."""
    agents = db.query(Agent).all()
    by_cve: dict[str, TopVulnerabilityOut] = {}
    for agent in agents:
        snapshot = _latest_snapshot(db, agent.id)
        if snapshot is None:
            continue
        seen_this_agent: set[str] = set()
        for v in vulnerabilities_for_snapshot(db, snapshot):
            if v.cve_id in seen_this_agent:
                continue
            seen_this_agent.add(v.cve_id)
            entry = by_cve.get(v.cve_id)
            if entry is None:
                by_cve[v.cve_id] = TopVulnerabilityOut(
                    cve_id=v.cve_id,
                    product_name=v.product_name,
                    cvss_score=v.cvss_score,
                    severity=v.severity,
                    device_count=1,
                )
            else:
                entry.device_count += 1

    ranked = sorted(by_cve.values(), key=lambda e: (-e.device_count, -(e.cvss_score or 0)))
    return ranked[:limit]


@router.get("/agents/{agent_id}/vulnerabilities", response_model=list[VulnerabilityOut])
def get_agent_vulnerabilities(
    agent_id: str, db: Session = Depends(get_db), _auth: None = Depends(require_shell_token)
) -> list[VulnerabilityOut]:
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent inconnu.")

    snapshot = _latest_snapshot(db, agent_id)
    if snapshot is None:
        return []

    return vulnerabilities_for_snapshot(db, snapshot)
