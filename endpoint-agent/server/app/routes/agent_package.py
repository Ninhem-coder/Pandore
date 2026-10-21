"""Mise à jour de l'AGENT lui-même via Vanitas (2026-09-11) — demande de Nicolas, suite à la
question "la mise à jour de l'agent via Vanitas c'est bien d'actu ?" (réponse : non, jusqu'ici
entièrement manuelle — dotnet publish + rebuild MSI + réinstallation à la main sur chaque
poste). Cadrage tranché avec Nicolas ("on peut avoir les deux ?") : déclenchement TOUJOURS
manuel (bouton, poste par poste ou par groupe, jamais automatique) + une alerte périodique
purement informative qui signale un décalage de version sans jamais rien pousser toute seule
(voir `_vanitas_agent_update_alert_loop`, backend/api_server.py, côté Pandore).

Distinct du catalogue d'installeurs applicatifs (`routes/installers.py`) : ici c'est Vanitas
lui-même qui se met à jour, toujours un `.msi`, toujours via `msiexec /i ... /qn /norestart`
(commande FIXE, jamais configurable par l'admin comme pour un installeur applicatif classique —
voir `UpdateRunner.cs` côté agent) — le mécanisme `<MajorUpgrade>` déjà en place dans
`Product.wxs` (UpgradeCode stable) gère tout seul l'arrêt/remplacement/redémarrage du service.

Mêmes deux tiers d'authentification que `routes/installers.py` : gestion du paquet
(upload/liste/suppression) en `require_shell_token`, téléchargement en mTLS agent.
"""
import hashlib
import shutil
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import audit
from ..db import DATA_DIR, get_db
from ..models import Agent, AgentPackage
from ..security import get_actor, get_current_agent, require_shell_token

router = APIRouter(tags=["agent-package"])

AGENT_PACKAGES_DIR = DATA_DIR / "agent_packages"
AGENT_PACKAGES_DIR.mkdir(exist_ok=True)

_MAX_PACKAGE_BYTES = 200_000_000  # 200 Mo — un agent .NET self-contained tient largement dedans

# Même garde-fou que `routes/installers.py::_validate_installer_filename` (traversée de
# répertoire + noms de périphérique réservés Windows) — dupliqué plutôt que partagé, même
# convention déjà en place dans ce projet pour ce genre de petite fonction de validation.
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
)


def _validate_package_filename(original_filename: str) -> None:
    if any(sep in original_filename for sep in ("/", "\\", "..", ":")):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Nom de fichier invalide.")
    stem = original_filename.rsplit(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED_NAMES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Nom de fichier invalide.")
    if not original_filename.lower().endswith(".msi"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Seul un fichier .msi est accepté pour l'agent.")


class AgentPackageOut(BaseModel):
    id: str
    version: str
    original_filename: str
    sha256: str
    size_bytes: int
    uploaded_at: datetime


def _to_out(pkg: AgentPackage) -> AgentPackageOut:
    return AgentPackageOut(
        id=pkg.id,
        version=pkg.version,
        original_filename=pkg.original_filename,
        sha256=pkg.sha256,
        size_bytes=pkg.size_bytes,
        uploaded_at=pkg.uploaded_at,
    )


@router.get(
    "/agent-package/latest",
    response_model=AgentPackageOut | None,
    dependencies=[Depends(require_shell_token)],
)
def get_latest_agent_package(db: Session = Depends(get_db)) -> AgentPackageOut | None:
    """Le plus récent uploadé fait foi comme version "courante" — voir le docstring de
    `AgentPackage` (models.py) sur pourquoi l'historique complet est gardé plutôt que remplacé
    en place."""
    pkg = db.query(AgentPackage).order_by(AgentPackage.uploaded_at.desc()).first()
    return _to_out(pkg) if pkg else None


@router.get(
    "/agent-package/history",
    response_model=list[AgentPackageOut],
    dependencies=[Depends(require_shell_token)],
)
def list_agent_packages(db: Session = Depends(get_db)) -> list[AgentPackageOut]:
    packages = db.query(AgentPackage).order_by(AgentPackage.uploaded_at.desc()).all()
    return [_to_out(p) for p in packages]


@router.post(
    "/agent-package",
    response_model=AgentPackageOut,
    dependencies=[Depends(require_shell_token)],
)
def upload_agent_package(
    version: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    actor: str | None = Depends(get_actor),
) -> AgentPackageOut:
    if not version.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "La version est obligatoire.")
    original_filename = file.filename or "EndpointAgent.msi"
    _validate_package_filename(original_filename)

    # `id` généré explicitement AVANT le premier commit — même piège déjà rencontré et corrigé
    # sur `InstallerPackage` (2026-09-08) : `.id` reste `None` tant que SQLAlchemy n'a pas
    # flush/commit, alors qu'il faut déjà le connaître pour calculer le chemin de destination.
    pkg = AgentPackage(
        id=uuid.uuid4().hex,
        version=version.strip(),
        original_filename=original_filename,
        sha256="",
        size_bytes=0,
    )
    entry_dir = AGENT_PACKAGES_DIR / pkg.id
    entry_dir.mkdir(parents=True, exist_ok=True)
    dest_path = entry_dir / original_filename

    hasher = hashlib.sha256()
    size = 0
    try:
        with dest_path.open("wb") as out:
            while chunk := file.file.read(1024 * 1024):
                size += len(chunk)
                if size > _MAX_PACKAGE_BYTES:
                    raise HTTPException(status.HTTP_400_BAD_REQUEST, "Fichier trop volumineux (200 Mo max).")
                hasher.update(chunk)
                out.write(chunk)
    except HTTPException:
        shutil.rmtree(entry_dir, ignore_errors=True)
        raise

    pkg.sha256 = hasher.hexdigest()
    pkg.size_bytes = size
    db.add(pkg)
    audit.record_event(db, "poste", "agent_package_uploaded", f"Agent v{pkg.version}", actor=actor, detail=original_filename)
    db.commit()
    db.refresh(pkg)
    return _to_out(pkg)


@router.delete("/agent-package/{package_id}", dependencies=[Depends(require_shell_token)])
def delete_agent_package(
    package_id: str, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> dict:
    """Retire une entrée de l'HISTORIQUE — si c'était la plus récente, `GET /agent-package/
    latest` retombe simplement sur la précédente restante (ou `null` si plus aucune). Ne
    reconstruit jamais ce qui a déjà été poussé sur un poste : un agent déjà mis à jour avec ce
    paquet le reste, supprimer l'entrée n'annule aucune commande déjà exécutée."""
    pkg = db.get(AgentPackage, package_id)
    if pkg is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Paquet introuvable.")
    audit.record_event(db, "poste", "agent_package_deleted", f"Agent v{pkg.version}", actor=actor)
    db.delete(pkg)
    db.commit()
    shutil.rmtree(AGENT_PACKAGES_DIR / package_id, ignore_errors=True)
    return {"ok": True}


@router.get("/agent-package/{package_id}/download")
def download_agent_package(
    package_id: str,
    db: Session = Depends(get_db),
    _agent: Agent = Depends(get_current_agent),
) -> FileResponse:
    """Consommée par l'agent .NET (mTLS), pas par le dashboard — même motif que
    `routes/installers.py::download_installer`."""
    pkg = db.get(AgentPackage, package_id)
    if pkg is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Paquet introuvable.")
    path = AGENT_PACKAGES_DIR / package_id / pkg.original_filename
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Fichier du paquet introuvable sur le serveur.")
    return FileResponse(path, filename=pkg.original_filename, media_type="application/octet-stream")
