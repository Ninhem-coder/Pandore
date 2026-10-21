"""Catalogue d'installeurs applicatifs (2026-09-08, demande de Nicolas — "un push d'application
un peu comme dans Pandore, via les groupes").

Deux tiers d'authentification bien distincts sur ce fichier, comme sur `routes/agents.py`/
`commands.py` :
- gestion du catalogue (upload/liste/suppression) — `require_shell_token` (le dashboard
  Pandore, pour le compte d'un admin ; la distinction admin/lecture-seule vit UNIQUEMENT côté
  Pandore, ce serveur ne connaît qu'un secret partagé).
- **téléchargement du binaire** (`GET /installers/{id}/download`) — mTLS agent
  (`Depends(get_current_agent)`), c'est l'AGENT qui la consomme pour récupérer l'installeur
  avant de l'exécuter, jamais le dashboard directement.

Taille max 1 Go par installeur (même garde-fou que l'assistant de packaging Win32 de Pandore,
`backend/intune/packaging.py`) — écrit sur disque par blocs (`shutil.copyfileobj`), jamais
chargé entièrement en mémoire.
"""
import hashlib
import json
import shutil
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import audit
from ..db import DATA_DIR, get_db
from ..models import Agent, AgentCommand, InstallerPackage
from ..security import get_actor, get_current_agent, require_shell_token

router = APIRouter(tags=["installers"])

INSTALLERS_DIR = DATA_DIR / "installers"
INSTALLERS_DIR.mkdir(exist_ok=True)

_MAX_INSTALLER_BYTES = 1_000_000_000  # 1 Go

# Noms de périphérique réservés par Windows (insensible à la casse, avec ou sans extension) —
# un fichier littéralement nommé "CON.txt" ou "NUL" ne peut pas être créé normalement sur
# NTFS/Win32 et produirait un comportement surprenant côté agent au moment du téléchargement.
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
)


def _validate_installer_filename(original_filename: str) -> None:
    """Revue de sécurité du 2026-09-09 : le filtre initial (`/`, `\\`, `..`) bloquait bien la
    traversée de répertoire classique mais laissait passer un nom "drive-relative" Windows du
    genre `C:secret.txt` — `Path.Combine` côté agent .NET ignore alors ENTIÈREMENT le
    répertoire de travail durci et écrit hors du confinement prévu (flux alternatif NTFS via
    `:` compris). Rejeté ici, à la source, plutôt que de compter uniquement sur le correctif
    `Path.GetFileName` côté agent (défense en profondeur — les deux bouts doivent valider)."""
    if any(sep in original_filename for sep in ("/", "\\", "..", ":")):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Nom de fichier invalide.")
    stem = original_filename.rsplit(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED_NAMES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Nom de fichier invalide.")


class InstallerOut(BaseModel):
    id: str
    name: str
    version: str | None
    original_filename: str
    install_command: str
    sha256: str
    size_bytes: int
    uploaded_at: datetime


def _to_out(installer: InstallerPackage) -> InstallerOut:
    return InstallerOut(
        id=installer.id,
        name=installer.name,
        version=installer.version,
        original_filename=installer.original_filename,
        install_command=installer.install_command,
        sha256=installer.sha256,
        size_bytes=installer.size_bytes,
        uploaded_at=installer.uploaded_at,
    )


@router.get("/installers", response_model=list[InstallerOut], dependencies=[Depends(require_shell_token)])
def list_installers(db: Session = Depends(get_db)) -> list[InstallerOut]:
    installers = db.query(InstallerPackage).order_by(InstallerPackage.name).all()
    return [_to_out(i) for i in installers]


@router.post("/installers", response_model=InstallerOut, dependencies=[Depends(require_shell_token)])
def create_installer(
    name: str = Form(...),
    version: str = Form(""),
    install_command: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    actor: str | None = Depends(get_actor),
) -> InstallerOut:
    if not name.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Le nom est obligatoire.")
    if not install_command.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "La commande d'installation est obligatoire.")
    original_filename = file.filename or "installeur.bin"
    _validate_installer_filename(original_filename)

    # `id` généré explicitement AVANT le premier commit (pas de simple `default=` sur la
    # colonne) — 🔧 bug réel trouvé en testant : `installer.id` reste `None` tant que
    # SQLAlchemy n'a pas flush/commit l'objet, alors qu'il faut déjà connaître l'id pour
    # calculer le répertoire de destination sur disque AVANT d'écrire le fichier.
    installer = InstallerPackage(
        id=uuid.uuid4().hex,
        name=name.strip(),
        version=version.strip() or None,
        original_filename=original_filename,
        install_command=install_command.strip(),
        sha256="",
        size_bytes=0,
    )
    entry_dir = INSTALLERS_DIR / installer.id
    entry_dir.mkdir(parents=True, exist_ok=True)
    dest_path = entry_dir / original_filename

    hasher = hashlib.sha256()
    size = 0
    try:
        with dest_path.open("wb") as out:
            while chunk := file.file.read(1024 * 1024):
                size += len(chunk)
                if size > _MAX_INSTALLER_BYTES:
                    raise HTTPException(
                        status.HTTP_400_BAD_REQUEST, "Fichier trop volumineux (1 Go max)."
                    )
                hasher.update(chunk)
                out.write(chunk)
    except HTTPException:
        shutil.rmtree(entry_dir, ignore_errors=True)
        raise

    installer.sha256 = hasher.hexdigest()
    installer.size_bytes = size
    db.add(installer)
    label = f"{installer.name} · v{installer.version}" if installer.version else installer.name
    audit.record_event(db, "application", "created", label, actor=actor, detail=installer.original_filename)
    db.commit()
    db.refresh(installer)
    return _to_out(installer)


class UpdateInstallerBody(BaseModel):
    name: str
    version: str = ""
    install_command: str


@router.put("/installers/{installer_id}", response_model=InstallerOut, dependencies=[Depends(require_shell_token)])
def update_installer(
    installer_id: str,
    body: UpdateInstallerBody,
    db: Session = Depends(get_db),
    actor: str | None = Depends(get_actor),
) -> InstallerOut:
    """Modification de fiche seule (2026-09-09, demande de Nicolas — "faire des modifications
    sur une application") : nom/version/commande d'installation, JAMAIS le fichier lui-même
    (pas de re-upload ici — remplacer le binaire reviendrait à créer un nouvel installeur,
    hors du périmètre de cette demande précise)."""
    installer = db.get(InstallerPackage, installer_id)
    if installer is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Installeur introuvable.")
    if not body.name.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Le nom est obligatoire.")
    if not body.install_command.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "La commande d'installation est obligatoire.")
    installer.name = body.name.strip()
    installer.version = body.version.strip() or None
    installer.install_command = body.install_command.strip()
    label = f"{installer.name} · v{installer.version}" if installer.version else installer.name
    audit.record_event(db, "application", "updated", label, actor=actor)
    db.commit()
    db.refresh(installer)
    return _to_out(installer)


@router.delete("/installers/{installer_id}", dependencies=[Depends(require_shell_token)])
def delete_installer(
    installer_id: str, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> dict:
    installer = db.get(InstallerPackage, installer_id)
    if installer is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Installeur introuvable.")
    shutil.rmtree(INSTALLERS_DIR / installer_id, ignore_errors=True)
    audit.record_event(db, "application", "deleted", installer.name, actor=actor)
    db.delete(installer)
    db.commit()
    return {"ok": True}


class InstallerDeviceOut(BaseModel):
    agent_id: str
    hostname: str
    status: str  # "ok" | "bad" | "pending" — voir _device_status
    result: str | None
    created_at: datetime
    completed_at: datetime | None
    target_label: str | None  # nom du groupe visé, ou None si poussé directement sur ce poste


class InstallerDeploymentOut(BaseModel):
    installer_id: str
    targets: list[str]
    devices: list[InstallerDeviceOut]


def _device_status(command: AgentCommand) -> str:
    if command.status in ("pending", "running"):
        return "pending"
    return "ok" if command.success else "bad"


@router.get(
    "/installers/deployments",
    response_model=list[InstallerDeploymentOut],
    dependencies=[Depends(require_shell_token)],
)
def list_installer_deployments(db: Session = Depends(get_db)) -> list[InstallerDeploymentOut]:
    """Page "Applications déployées" (2026-09-10, demande de Nicolas — "déployer depuis le
    catalogue, assigner les groupes... et avoir une page pour voir les applications qu'on a
    déployées"). Reconstruit, à la LECTURE seule, le rapprochement installeur → postes ciblés
    à partir des lignes `AgentCommand(command_type="install_application")` déjà existantes —
    AUCUNE nouvelle table, aucune migration : ce que `push_install_to_group`/`queue_command`
    écrivent déjà dans `parameters` (voir `build_install_parameters`) suffit.

    Un poste peut avoir été ciblé plusieurs fois pour le MÊME installeur (ex. relance après un
    échec) — seule la commande la PLUS RÉCENTE compte pour son statut affiché.
    `targets` liste, lui, TOUS les noms de groupe visés au moins une fois pour cet installeur
    (un push direct vers un seul poste n'a pas de `target_label`, donc n'y apparaît jamais —
    le poste lui-même reste visible dans `devices`, juste pas dans les badges de groupe)."""
    rows = (
        db.query(AgentCommand, Agent.hostname)
        .join(Agent, Agent.id == AgentCommand.agent_id)
        .filter(AgentCommand.command_type == "install_application")
        .order_by(AgentCommand.created_at.asc())
        .all()
    )

    # Parcouru par `created_at` croissant : pour une même clé (installeur, poste), la dernière
    # écriture de la boucle est la plus récente — écrase silencieusement les tentatives
    # antérieures, exactement le comportement voulu (statut affiché = dernière tentative).
    latest_by_device: dict[tuple[str, str], tuple[AgentCommand, str, dict]] = {}
    targets_by_installer: dict[str, set[str]] = {}
    for command, hostname in rows:
        try:
            params = json.loads(command.parameters or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        installer_id = params.get("installer_id")
        if not installer_id:
            continue
        latest_by_device[(installer_id, command.agent_id)] = (command, hostname, params)
        target_label = params.get("target_label")
        if target_label:
            targets_by_installer.setdefault(installer_id, set()).add(target_label)

    devices_by_installer: dict[str, list[InstallerDeviceOut]] = {}
    for (installer_id, _agent_id), (command, hostname, params) in latest_by_device.items():
        devices_by_installer.setdefault(installer_id, []).append(
            InstallerDeviceOut(
                agent_id=command.agent_id,
                hostname=hostname,
                status=_device_status(command),
                result=command.result,
                created_at=command.created_at,
                completed_at=command.completed_at,
                target_label=params.get("target_label"),
            )
        )

    return [
        InstallerDeploymentOut(
            installer_id=installer_id,
            targets=sorted(targets_by_installer.get(installer_id, set())),
            devices=devices,
        )
        for installer_id, devices in devices_by_installer.items()
    ]


@router.get("/installers/{installer_id}/download")
def download_installer(
    installer_id: str,
    db: Session = Depends(get_db),
    _agent=Depends(get_current_agent),
) -> FileResponse:
    """Consommée par l'agent .NET (mTLS), pas par le dashboard — voir l'en-tête du fichier.
    Aucune ACL par poste/groupe : tout agent enrôlé et non révoqué peut télécharger n'importe
    quel installeur du catalogue, cohérent avec le modèle de confiance déjà en place (un admin
    qui pousse une commande vers un poste précis fait déjà confiance à ce mécanisme)."""
    installer = db.get(InstallerPackage, installer_id)
    if installer is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Installeur introuvable.")
    path = INSTALLERS_DIR / installer_id / installer.original_filename
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Fichier de l'installeur introuvable sur le serveur.")
    return FileResponse(path, filename=installer.original_filename, media_type="application/octet-stream")
