"""Routes Intune — /api/intune/* (devices, conformité, apps, packaging Win32, bibliothèque
d'applications, secure score) + section transverse Intune/Defender (/api/history,
/api/device-overview, /api/device-inventory). Déplacé de api_server.py le 2026-09-12."""
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from api_common import IdPath, _ID_PATTERN
from auth import require_admin
from common import history
from device_overview import get_device_inventory, get_device_overview
from intune import app_library as intune_library_tools
from intune import apps as intune_apps_tools
from intune import compliance as intune_compliance
from intune import compliance_detail as intune_compliance_detail_tools
from intune import devices as intune_devices_tools
from intune import packaging as intune_packaging_tools
from intune import secure_score as intune_secure_score_tools
from intune import users as intune_users_tools

router = APIRouter()


# ── Corps des routes /api/intune/packaging/* (voir intune/packaging.py). `GitHubReleasesBody`
# (listing de toutes les releases) distinct de `GitHubLookupBody` (assets d'UNE release).
class GitHubReleasesBody(BaseModel):
    owner: str
    repo: str


class GitHubLookupBody(BaseModel):
    owner: str
    repo: str
    tag: Optional[str] = None


class GitHubFetchBody(BaseModel):
    download_url: str
    asset_name: str
    # Optionnels (2026-08-27) — dépôt d'origine de l'asset choisi, retenu par packaging.py.
    owner: Optional[str] = None
    repo: Optional[str] = None


class PackageAppBody(BaseModel):
    install_mode: str
    options: list[str] = []
    application_name: str
    version: str
    detection_mode: str = "greaterOrEqual"
    # Source PowerShell uniquement (2026-08-27) — commande de désinstallation saisie par
    # l'admin, ignorée côté backend pour une source MSI (auto-générée).
    uninstall_command: str = ""


# ── Corps des routes /api/intune/app-library/* (voir intune/app_library.py). `icon`/
# `icon_content_type` — contenu du fichier en base64 (préfixe `data:...;base64,` retiré),
# validé/borné par app_library.py::_build_icon.
class ManualLibraryAppBody(BaseModel):
    display_name: str
    publisher: str = ""
    version: str = ""
    note: str = ""
    icon: Optional[str] = None
    icon_content_type: Optional[str] = None


class PackagedLibraryAppBody(BaseModel):
    job_id: str
    display_name: str = ""
    publisher: str = ""
    note: str = ""
    icon: Optional[str] = None
    icon_content_type: Optional[str] = None


# `remove_icon` distingue "retirer le logo" de "logo non renvoyé, garder l'existant".
class UpdateLibraryAppBody(BaseModel):
    display_name: str
    publisher: str = ""
    version: str = ""
    note: str = ""
    icon: Optional[str] = None
    icon_content_type: Optional[str] = None
    remove_icon: bool = False
    install_mode: Optional[str] = None
    options: Optional[list[str]] = None
    detection_mode: Optional[str] = None
    # Source PowerShell uniquement (2026-08-27) — `None` = ne pas y toucher, "" = effacer.
    uninstall_command: Optional[str] = None


class RepackageLibraryAppBody(BaseModel):
    job_id: str


@router.get("/api/intune/devices")
def intune_devices(filter: Optional[str] = None, top: Optional[int] = Query(None, ge=1, le=5000)):
    return intune_devices_tools.list_devices(filter=filter, top=top)


@router.get("/api/intune/devices/{device_id}")
def intune_device(device_id: str = IdPath("ID Intune de l'appareil")):
    return intune_devices_tools.get_device(device_id=device_id)


@router.get("/api/intune/non-compliant")
def intune_non_compliant():
    return intune_compliance.list_non_compliant_devices()


@router.get("/api/intune/compliance-policies")
def intune_compliance_policies():
    return intune_compliance.get_compliance_policies()


@router.get("/api/intune/compliance-policy-summary")
def intune_compliance_policy_summary():
    return intune_compliance.get_compliance_policy_summary()


@router.get("/api/intune/configuration-profiles")
def intune_configuration_profiles(platform: Optional[str] = None):
    return intune_devices_tools.get_configuration_profiles(platform=platform)


@router.get("/api/intune/apps")
def intune_apps(filter: Optional[str] = None):
    return intune_apps_tools.list_apps(filter=filter)


# Fusion "Application déployée" + "discovered apps", dédupliquée par nom (2026-09-02).
@router.get("/api/intune/apps-catalog")
def intune_apps_catalog():
    return intune_apps_tools.get_apps_catalog()


# `policy_id` optionnel : sans lui, résumé par politique ; avec lui, détail par PARAMÈTRE.
@router.get("/api/intune/devices/{device_id}/compliance-status")
def intune_device_compliance_status(
    device_id: str = IdPath("ID Intune de l'appareil"),
    policy_id: Optional[str] = Query(None, pattern=_ID_PATTERN, description="ID d'une politique de conformité — renvoie le détail par paramètre plutôt que le résumé par politique"),
):
    return intune_compliance.get_device_compliance_status(device_id=device_id, policy_id=policy_id)


@router.get("/api/intune/users")
def intune_users(search: Optional[str] = None):
    return intune_users_tools.list_users(search=search)


@router.get("/api/intune/summary")
def intune_summary():
    return intune_devices_tools.get_intune_summary()


@router.get("/api/intune/discovered-apps")
def intune_discovered_apps(search: Optional[str] = None, min_devices: Optional[int] = None):
    return intune_apps_tools.get_discovered_apps(search=search, min_devices=min_devices)


@router.get("/api/intune/discovered-apps/{app_id}/devices")
def intune_discovered_app_devices(app_id: str = IdPath("ID Intune de la discovered app")):
    return intune_apps_tools.get_discovered_app_devices(app_id=app_id)


# Onglet "Applications" de la Vue Appareil 360° (2026-09-02).
@router.get("/api/intune/devices/{device_id}/detected-apps")
def intune_device_detected_apps(device_id: str = IdPath("ID Intune de l'appareil")):
    return intune_apps_tools.get_device_detected_apps(device_id=device_id)


@router.get("/api/intune/apps/{app_id}/assignments")
def intune_app_assignments(app_id: str = IdPath("ID Intune de l'application")):
    return intune_apps_tools.get_app_assignments(app_id=app_id)


@router.get("/api/intune/apps/{app_id}/install-status")
def intune_app_install_status(
    app_id: str = IdPath("ID Intune de l'application"),
    os_filter: Optional[str] = None,
    version_below: Optional[str] = None,
):
    return intune_apps_tools.get_app_install_status(app_id=app_id, os_filter=os_filter, version_below=version_below)


# Placé APRÈS /api/intune/apps/{app_id}/install-status : chemin distinct, aucune collision.
@router.get("/api/intune/apps/install-summary")
def intune_apps_install_summary():
    return intune_apps_tools.get_apps_install_summary()


# ── Assistant de packaging Win32 (2026-08-26, voir intune/packaging.py) : NE PUBLIE RIEN sur
# Intune. Routes de MUTATION admin-only (2026-09-08, revue de sécurité) — subprocess local +
# téléchargement GitHub arbitraire ; téléchargements/lecture restent accessibles à tout compte.
@router.post("/api/intune/packaging/jobs")
def packaging_create_job(_admin: None = Depends(require_admin)):
    return intune_packaging_tools.create_job()


@router.post("/api/intune/packaging/jobs/{job_id}/source/upload")
def packaging_upload_source(
    job_id: str = IdPath("ID du job de packaging"),
    file: UploadFile = File(...),
    _admin: None = Depends(require_admin),
):
    return intune_packaging_tools.save_uploaded_source(job_id=job_id, filename=file.filename, stream=file.file)


@router.post("/api/intune/packaging/jobs/{job_id}/source/github-releases")
def packaging_github_releases(
    job_id: str = IdPath("ID du job de packaging"),
    body: GitHubReleasesBody = ...,
    _admin: None = Depends(require_admin),
):
    return intune_packaging_tools.github_list_releases(owner=body.owner, repo=body.repo)


@router.post("/api/intune/packaging/jobs/{job_id}/source/github-lookup")
def packaging_github_lookup(
    job_id: str = IdPath("ID du job de packaging"),
    body: GitHubLookupBody = ...,
    _admin: None = Depends(require_admin),
):
    # `job_id` non utilisé à cette étape (aucun fichier écrit tant qu'aucun asset choisi) — gardé
    # dans l'URL pour que toutes les routes "source" du wizard restent sous le même chemin.
    return intune_packaging_tools.github_lookup_releases(owner=body.owner, repo=body.repo, tag=body.tag)


@router.post("/api/intune/packaging/jobs/{job_id}/source/github-fetch")
def packaging_github_fetch(
    job_id: str = IdPath("ID du job de packaging"),
    body: GitHubFetchBody = ...,
    _admin: None = Depends(require_admin),
):
    return intune_packaging_tools.github_fetch_asset(
        job_id=job_id, download_url=body.download_url, asset_name=body.asset_name, owner=body.owner, repo=body.repo
    )


@router.post("/api/intune/packaging/jobs/{job_id}/package")
def packaging_package_app(
    job_id: str = IdPath("ID du job de packaging"),
    body: PackageAppBody = ...,
    _admin: None = Depends(require_admin),
):
    return intune_packaging_tools.package_app(
        job_id=job_id,
        install_mode=body.install_mode,
        options=body.options,
        application_name=body.application_name,
        version=body.version,
        detection_mode=body.detection_mode,
        uninstall_command=body.uninstall_command,
    )


@router.get("/api/intune/packaging/jobs/{job_id}/download")
def packaging_download(job_id: str = IdPath("ID du job de packaging")):
    # `build_deliverable_zip` renvoie un `Path`, pas décorée `@handle_tool_errors` — une erreur
    # devient une vraie HTTPException plutôt qu'un corps de réponse fichier invalide.
    try:
        zip_path = intune_packaging_tools.build_deliverable_zip(job_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return FileResponse(zip_path, filename="package-intune.zip", media_type="application/zip")


# ── Bibliothèque d'applications (2026-08-26, voir intune/app_library.py).
@router.get("/api/intune/app-library")
def library_list():
    return intune_library_tools.list_library_apps()


@router.post("/api/intune/app-library/manual")
def library_add_manual(body: ManualLibraryAppBody, _admin: None = Depends(require_admin)):
    return intune_library_tools.add_manual_app(
        display_name=body.display_name,
        publisher=body.publisher,
        version=body.version,
        note=body.note,
        icon=body.icon,
        icon_content_type=body.icon_content_type,
    )


@router.post("/api/intune/app-library/packaged")
def library_add_packaged(body: PackagedLibraryAppBody, _admin: None = Depends(require_admin)):
    return intune_library_tools.add_packaged_app(
        job_id=body.job_id,
        display_name=body.display_name,
        publisher=body.publisher,
        note=body.note,
        icon=body.icon,
        icon_content_type=body.icon_content_type,
    )


# "Système de mise à jour automatique" (2026-08-27) — déclenché par un bouton manuel.
@router.post("/api/intune/app-library/check-updates")
def library_check_updates(_admin: None = Depends(require_admin)):
    return intune_library_tools.check_for_updates()


@router.put("/api/intune/app-library/{entry_id}")
def library_update(
    entry_id: str = IdPath("ID de l'entrée de bibliothèque"),
    body: UpdateLibraryAppBody = ...,
    _admin: None = Depends(require_admin),
):
    return intune_library_tools.update_library_app(
        entry_id=entry_id,
        display_name=body.display_name,
        publisher=body.publisher,
        version=body.version,
        note=body.note,
        icon=body.icon,
        icon_content_type=body.icon_content_type,
        remove_icon=body.remove_icon,
        install_mode=body.install_mode,
        options=body.options,
        detection_mode=body.detection_mode,
        uninstall_command=body.uninstall_command,
    )


@router.post("/api/intune/app-library/{entry_id}/repackage")
def library_repackage(
    entry_id: str = IdPath("ID de l'entrée de bibliothèque"),
    body: RepackageLibraryAppBody = ...,
    _admin: None = Depends(require_admin),
):
    return intune_library_tools.repackage_library_app(entry_id=entry_id, job_id=body.job_id)


@router.delete("/api/intune/app-library/{entry_id}")
def library_remove(
    entry_id: str = IdPath("ID de l'entrée de bibliothèque"), _admin: None = Depends(require_admin)
):
    return {"removed": intune_library_tools.remove_library_app(entry_id)}


@router.get("/api/intune/app-library/{entry_id}/download")
def library_download(entry_id: str = IdPath("ID de l'entrée de bibliothèque")):
    # Même motif que packaging_download : `library_deliverable_path` renvoie un `Path`.
    try:
        zip_path = intune_library_tools.library_deliverable_path(entry_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return FileResponse(zip_path, filename="package-intune.zip", media_type="application/zip")


@router.get("/api/intune/compliance-policies/{policy_id}/device-statuses")
def intune_policy_device_statuses(
    policy_id: str = IdPath("ID Intune de la politique de conformité"),
    status_filter: Optional[str] = None,
):
    return intune_compliance.get_policy_device_statuses(policy_id=policy_id, status_filter=status_filter)


@router.get("/api/intune/compliance-detail")
def intune_compliance_detail(
    max_devices: Optional[int] = Query(None, ge=1, le=100000),
    force_refresh: bool = Query(False, description="Contourne le cache 120s et relance le scan complet"),
):
    return intune_compliance_detail_tools.get_compliance_detail(max_devices=max_devices, force_refresh=force_refresh)


# Endpoint Graph /security/*, même app registration que le reste d'Intune (AZURE_CLIENT_ID) —
# nécessite le scope SecurityEvents.Read.All.
@router.get("/api/intune/secure-score")
def intune_secure_score(days: int = Query(30, ge=1, le=90)):
    return intune_secure_score_tools.get_secure_score(days=days)


@router.get("/api/intune/secure-score-control-profiles")
def intune_secure_score_control_profiles():
    return intune_secure_score_tools.list_secure_score_control_profiles()


# ── Historique / Vue 360° (transverse Intune + Defender) ──
@router.get("/api/history")
def api_history():
    return history.get_history()


@router.get("/api/device-overview")
def api_device_overview(
    device_name: str = Query(..., min_length=1, max_length=256, description="Nom de l'appareil (deviceName Intune / computerDnsName Defender)"),
):
    return get_device_overview(device_name)


# Inventaire fleet-wide (2026-09-02) — voir device_overview.py::get_device_inventory.
@router.get("/api/device-inventory")
def api_device_inventory():
    return get_device_inventory()
