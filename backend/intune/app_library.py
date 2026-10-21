"""
Bibliothèque d'applications (2026-08-26, demande de Nicolas) — remplace le catalogue "apps
détectées sur le parc" de l'onglet Catalogue d'application (deviceManagement/detectedApps,
jamais consulté depuis sa création selon CLAUDE.md : "Nicolas n'a rien demandé dessus") par une
liste PERSISTANTE qu'il alimente lui-même, de deux façons ("les deux", tranché explicitement
plutôt que de deviner) :
  - en sauvegardant le résultat d'un packaging terminé (assistant "Déployer une application",
    voir intune/packaging.py) — `add_packaged_app` ;
  - par ajout manuel libre (nom/éditeur/version/note), sans passer par le packaging — pour
    cataloguer une app qui n'a pas besoin d'un livrable technique — `add_manual_app`.

Même motif de persistance que defender/watchlist.py (CVE suivies, même repo) : un fichier
JSON local (LIBRARY_FILE) protégé par un verrou en mémoire, écriture atomique via
common/atomic_io.atomic_write_text — pas de base de données, cohérent avec le reste de cet
outil mono-poste/mono-utilisateur (pas de verrou multi-process).

Une entrée "packaged" copie le livrable (.intunewin + instructions, voir
packaging.py::build_deliverable_zip) du répertoire scratch ÉPHÉMÈRE du job de packaging
(backend/.packaging_workdir/<job_id>/) vers un stockage PERMANENT dédié
(backend/data/app_library/<entry_id>/deliverable.zip) — la bibliothèque doit survivre même si
le répertoire de travail du wizard est nettoyé plus tard (TTL prévu mais pas encore implémenté
côté packaging.py).

`backend/data/app_library.json` (l'INDEX, JSON léger) suit la même convention que
`backend/data/history.json`/`watched_cves.json` : versionné avec le reste du repo. Les livrables
binaires sous `backend/data/app_library/` sont, eux, gitignorés (voir .gitignore) — un
`.intunewin` n'a rien à faire dans l'historique git, contrairement à quelques kilo-octets de
JSON.
"""
import base64
import binascii
import json
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from common.atomic_io import atomic_write_text
from common.config import BACKEND_DIR
from common.http_client import handle_tool_errors, tool_error
from intune import packaging as _packaging

LIBRARY_FILE = BACKEND_DIR / "data" / "app_library.json"
LIBRARY_FILE.parent.mkdir(exist_ok=True)

# Logo par app (2026-08-26, demande de Nicolas : "mettre un logo à l'application... pour le
# voir dans le catalogue") — stocké EN BASE64 directement dans l'index JSON (même forme que
# `largeIcon.value`/`.type` renvoyé par Graph pour les apps Intune, déjà consommé tel quel par
# `AppIcon` dans DeployedAppsTab.jsx) plutôt qu'un fichier séparé sur disque : un logo reste de
# l'ordre de quelques dizaines de Ko, pas besoin du mécanisme de stockage par fichier déjà en
# place pour les livrables `.intunewin` (bien plus volumineux). Borne à 750 Ko décodés — large
# pour un logo, mais évite qu'un fichier déposé par erreur (screenshot pleine résolution...)
# ne fasse gonfler `app_library.json` de façon disproportionnée.
_MAX_ICON_BYTES = 750_000
LIBRARY_FILES_DIR = BACKEND_DIR / "data" / "app_library"
LIBRARY_FILES_DIR.mkdir(exist_ok=True)

_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_raw() -> list[dict]:
    if not LIBRARY_FILE.exists():
        return []
    try:
        return json.loads(LIBRARY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Fichier corrompu/tronqué — repartir d'une liste vide plutôt que de faire planter
        # tout l'onglet (même choix que defender/watchlist.py::_read_raw).
        return []


def _write_raw(entries: list[dict]) -> None:
    atomic_write_text(LIBRARY_FILE, json.dumps(entries, ensure_ascii=False, indent=2))


def _build_icon(icon_base64: str | None, icon_content_type: str | None) -> dict | None:
    """Valide/normalise un logo déposé côté UI (déjà encodé en base64 par le navigateur via
    `FileReader.readAsDataURL`, préfixe `data:...;base64,` retiré côté frontend) — lève
    `ValueError` sur tout logo invalide/trop volumineux, à charge de l'appelant de le
    convertir en `tool_error` (cohérent avec le reste de ce module, ex.
    `library_deliverable_path`)."""
    icon_base64 = (icon_base64 or "").strip()
    if not icon_base64:
        return None
    try:
        decoded = base64.b64decode(icon_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Logo invalide (encodage incorrect).") from exc
    if len(decoded) > _MAX_ICON_BYTES:
        raise ValueError(f"Logo trop volumineux ({len(decoded) // 1024} Ko, 750 Ko max).")
    content_type = (icon_content_type or "image/png").strip() or "image/png"
    if not content_type.startswith("image/"):
        raise ValueError("Le logo doit être une image.")
    return {"value": icon_base64, "contentType": content_type}


@handle_tool_errors
def list_library_apps() -> list[dict]:
    """Bibliothèque d'apps, plus récemment ajoutée en premier."""
    with _lock:
        return _read_raw()


@handle_tool_errors
def add_manual_app(
    display_name: str,
    publisher: str = "",
    version: str = "",
    note: str = "",
    icon: str | None = None,
    icon_content_type: str | None = None,
) -> dict:
    """Ajout libre — n'importe quelle app, sans passer par l'assistant de packaging (ex. une
    app store, ou déjà packagée par ailleurs) : une fiche de référence, pas de livrable
    technique associé (`package` reste `None`, le bouton "Télécharger" reste caché côté UI
    pour ce type d'entrée). `icon`/`icon_content_type` optionnels — voir `_build_icon`."""
    display_name = (display_name or "").strip()
    if not display_name:
        return tool_error("Le nom de l'application est obligatoire.", "ValidationError")

    try:
        icon_obj = _build_icon(icon, icon_content_type)
    except ValueError as exc:
        return tool_error(str(exc), "ValidationError")

    created_at = _now_iso()
    entry = {
        "id": str(uuid.uuid4()),
        "source": "manual",
        "displayName": display_name,
        "publisher": (publisher or "").strip() or None,
        "version": (version or "").strip() or None,
        "note": (note or "").strip() or None,
        "addedAt": created_at,
        # Même valeur qu'`addedAt` à la création (2026-08-27, demande de Nicolas : "voir la
        # dernière modification plutôt que le ajouté le" dans le catalogue) — mise à jour par
        # `update_library_app`/`repackage_library_app` à chaque modification ultérieure,
        # jamais par ce module-ci autrement.
        "updatedAt": created_at,
        "package": None,
        "icon": icon_obj,
    }
    with _lock:
        entries = _read_raw()
        entries.insert(0, entry)
        _write_raw(entries)
    return entry


@handle_tool_errors
def add_packaged_app(
    job_id: str,
    display_name: str = "",
    publisher: str = "",
    note: str = "",
    icon: str | None = None,
    icon_content_type: str | None = None,
) -> dict:
    """Sauvegarde le résultat d'un packaging terminé (voir packaging.py::package_app) dans la
    bibliothèque, DE FAÇON PERMANENTE — copie le livrable hors du répertoire scratch du job
    (éphémère) plutôt que d'y référencer un chemin qui peut disparaître. `display_name`/
    `publisher` reprennent `suggestedMetadata` si non fournis (l'admin peut compléter
    l'éditeur, que le wizard ne connaît pas). `icon`/`icon_content_type` optionnels — voir
    `_build_icon` (aucune source d'icône automatique pour un app packagée par cet assistant,
    contrairement à `deviceManagement/detectedApps` côté Graph).

    PAS enregistrée côté MCP (voir mcp_server.py::EXCLUDED_FROM_MCP) : `job_id` est un état
    éphémère du wizard web, sans contexte équivalent dans une conversation Claude Desktop."""
    job_dir = _packaging._job_dir(job_id)
    result_path = job_dir / "package_result.json"
    if not result_path.is_file():
        return tool_error(
            "Aucun packaging terminé pour ce job — lance l'étape de packaging avant d'ajouter à la bibliothèque.",
            "ValidationError",
        )
    result = json.loads(result_path.read_text(encoding="utf-8"))
    meta = result.get("suggestedMetadata") or {}

    final_name = (display_name or meta.get("displayName") or "").strip()
    if not final_name:
        return tool_error("Le nom de l'application est obligatoire.", "ValidationError")

    try:
        icon_obj = _build_icon(icon, icon_content_type)
    except ValueError as exc:
        return tool_error(str(exc), "ValidationError")

    # Reconstruit le zip si besoin (déjà fait par le wizard au moment du téléchargement, mais
    # rien ne garantit que l'admin ait cliqué "Télécharger" avant "Ajouter à la bibliothèque").
    zip_path = _packaging.build_deliverable_zip(job_id)

    entry_id = str(uuid.uuid4())
    entry_dir = LIBRARY_FILES_DIR / entry_id
    entry_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(zip_path, entry_dir / "deliverable.zip")

    created_at = _now_iso()
    entry = {
        "id": entry_id,
        "source": "packaged",
        "displayName": final_name,
        "publisher": (publisher or "").strip() or None,
        "version": meta.get("version") or None,
        "note": (note or "").strip() or None,
        "addedAt": created_at,
        "updatedAt": created_at,
        "package": {
            "intunewinFileName": result.get("intunewinFileName"),
            "installCommand": result.get("installCommand"),
            "uninstallCommand": result.get("uninstallCommand"),
            "detectionScript": result.get("detectionScript"),
            "requirements": result.get("requirements"),
            # Choix bruts du wizard (2026-08-26) — voir packaging.py::package_app. Absent sur
            # les entrées créées AVANT ce changement (`result.get` renvoie `None`) :
            # `update_library_app` retombe sur des valeurs par défaut sensées dans ce cas
            # plutôt que de planter sur une entrée existante.
            "config": result.get("config"),
            # Dépôt GitHub d'origine (2026-08-27, demande de Nicolas : "enregistrer le lien du
            # dépôt Git... pour proposer les versions dispo sur le repo lors de la
            # modification") — `None` si la source a été déposée par upload direct plutôt que
            # via une release GitHub, voir packaging.py::_read_source_repo. Consommé par
            # `RepackageSection` (EditAppTab.jsx) pour lister les releases sans re-saisie.
            "repo": result.get("repo"),
        },
        "icon": icon_obj,
    }
    with _lock:
        entries = _read_raw()
        entries.insert(0, entry)
        _write_raw(entries)
    return entry


@handle_tool_errors
def update_library_app(
    entry_id: str,
    display_name: str,
    publisher: str = "",
    version: str = "",
    note: str = "",
    icon: str | None = None,
    icon_content_type: str | None = None,
    remove_icon: bool = False,
    install_mode: str | None = None,
    options: list[str] | None = None,
    detection_mode: str | None = None,
    uninstall_command: str | None = None,
) -> dict:
    """Modifie une entrée existante (2026-08-26, demande de Nicolas : "modifier les
    applications... la version et tous les autres champs qu'il y avait lors de la
    configuration") — deux volets :
    1. Fiche (nom/éditeur/version/note/logo) — pour TOUTE entrée, manuelle ou packagée. `icon`
       remplace le logo existant si fourni, `remove_icon=True` le retire, sinon (les deux
       absents) le logo existant est conservé tel quel — trois états distincts, pas juste
       présent/absent, pour qu'un simple ré-enregistrement des autres champs ne fasse pas
       disparaître un logo déjà en place.
    2. Configuration de packaging (mode d'installation/options/règle de détection) — pour une
       entrée "packagée" SEULEMENT (une entrée "manuelle" n'a jamais eu de configuration,
       `install_mode`/`options`/`detection_mode`/`uninstall_command` y sont silencieusement
       ignorés). Le script de détection est TOUJOURS régénéré via
       `packaging.py::_render_detection_script` (nom/version/mode sont source-agnostiques).
       Les commandes d'installation/désinstallation, elles, dépendent du TYPE de source
       (`pkg.config.sourceType`, voir packaging.py::package_app, 2026-08-27) :
       - MSI : régénérées via `_msi_commands` (installMode/options), comme avant ce champ.
       - PowerShell : `installCommand` reste FIXE (jamais régénérée, rien à recalculer —
         `powershell -file .\\Pandore.ps1` ne dépend d'aucun réglage) ; `uninstallCommand` est
         la SAISIE MANUELLE de l'admin (`uninstall_command`, `None` = ne pas y toucher, chaîne
         vide = l'effacer explicitement — même convention à 3 états que `icon`/`remove_icon`
         ci-dessus).
       Entrée packagée AVANT ce champ (`config.sourceType` absent) : traitée comme "msi" par
       défaut (`cfg.get("sourceType", "msi")`) — c'était le SEUL type possible avant le
       2026-08-27, comportement inchangé pour ces entrées-là. Le `.intunewin` déjà produit
       n'est JAMAIS régénéré ici, quel que soit le type de source : IntuneWinAppUtil.exe n'est
       pas ré-exécuté, ces réglages n'influencent que le texte à coller dans Intune."""
    display_name = (display_name or "").strip()
    if not display_name:
        return tool_error("Le nom de l'application est obligatoire.", "ValidationError")

    try:
        new_icon_obj = _build_icon(icon, icon_content_type)
    except ValueError as exc:
        return tool_error(str(exc), "ValidationError")

    with _lock:
        entries = _read_raw()
        entry = next((e for e in entries if e.get("id") == entry_id), None)
        if entry is None:
            return tool_error(f"Application introuvable dans la bibliothèque : {entry_id}", "ValidationError")

        final_version = (version or "").strip() or None
        entry["displayName"] = display_name
        entry["publisher"] = (publisher or "").strip() or None
        entry["version"] = final_version
        entry["note"] = (note or "").strip() or None
        entry["updatedAt"] = _now_iso()

        if remove_icon:
            entry["icon"] = None
        elif new_icon_obj is not None:
            entry["icon"] = new_icon_obj
        # ni l'un ni l'autre : logo existant conservé sans y toucher

        if entry.get("source") == "packaged" and entry.get("package"):
            pkg = entry["package"]
            cfg = pkg.get("config") or {}
            source_type = cfg.get("sourceType", "msi")
            final_detection_mode = detection_mode if detection_mode is not None else cfg.get("detectionMode", "greaterOrEqual")

            if source_type == "msi":
                final_install_mode = install_mode if install_mode is not None else cfg.get("installMode", "silent")
                final_options = options if options is not None else cfg.get("options") or []
                try:
                    install_cmd, uninstall_cmd = _packaging._msi_commands(final_install_mode, final_options)
                except ValueError as exc:
                    return tool_error(str(exc), "ValidationError")
                pkg["installCommand"] = install_cmd
                pkg["uninstallCommand"] = uninstall_cmd
                pkg["config"] = {
                    "sourceType": source_type,
                    "installMode": final_install_mode,
                    "options": final_options,
                    "detectionMode": final_detection_mode,
                }
            else:  # "powershell" — installCommand fixe, uninstallCommand saisie manuelle
                if uninstall_command is not None:
                    pkg["uninstallCommand"] = uninstall_command.strip()
                pkg["config"] = {**cfg, "detectionMode": final_detection_mode}

            pkg["detectionScript"] = _packaging._render_detection_script(display_name, final_version or "", final_detection_mode)

        _write_raw(entries)
    return entry


@handle_tool_errors
def repackage_library_app(entry_id: str, job_id: str) -> dict:
    """Remplace le livrable ET les commandes/script d'une entrée "packagée" existante par le
    résultat d'un NOUVEAU job de packaging terminé (2026-08-26, demande de Nicolas : "voir
    toutes les versions dans le repo git pour pouvoir le changer" — re-packager une entrée avec
    une AUTRE version de l'installeur, ex. une release GitHub différente). Garde le même
    `entry_id`/`displayName`/`publisher`/`note`/`icon`/`addedAt` — seul ce qui vient du
    packaging change (`package` intégralement remplacé, `version` mise à jour si le nouveau
    packaging en suggère une).

    À la différence de `update_library_app` (qui ne fait que RÉGÉNÉRER le texte des commandes/
    script à partir des MÊMES réglages, sans toucher au fichier), ce job DOIT avoir
    réellement produit un nouveau `.intunewin` via `packaging.package_app` — appelé par le
    frontend AVANT ce point, comme n'importe quel job du wizard normal."""
    job_dir = _packaging._job_dir(job_id)
    result_path = job_dir / "package_result.json"
    if not result_path.is_file():
        return tool_error(
            "Aucun packaging terminé pour ce job — lance l'étape de packaging avant de re-packager.",
            "ValidationError",
        )
    result = json.loads(result_path.read_text(encoding="utf-8"))
    zip_path = _packaging.build_deliverable_zip(job_id)

    with _lock:
        entries = _read_raw()
        entry = next((e for e in entries if e.get("id") == entry_id), None)
        if entry is None:
            return tool_error(f"Application introuvable dans la bibliothèque : {entry_id}", "ValidationError")
        if entry.get("source") != "packaged":
            return tool_error("Cette entrée n'a pas été packagée — impossible de la re-packager.", "ValidationError")

        entry_dir = LIBRARY_FILES_DIR / entry_id
        entry_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(zip_path, entry_dir / "deliverable.zip")

        meta = result.get("suggestedMetadata") or {}
        if meta.get("version"):
            entry["version"] = meta.get("version")
        entry["updatedAt"] = _now_iso()
        entry["package"] = {
            "intunewinFileName": result.get("intunewinFileName"),
            "installCommand": result.get("installCommand"),
            "uninstallCommand": result.get("uninstallCommand"),
            "detectionScript": result.get("detectionScript"),
            "requirements": result.get("requirements"),
            "config": result.get("config"),
            # Remplace aussi le dépôt d'origine (2026-08-27) — reflète la source du NOUVEAU
            # job : `None` si celui-ci vient d'un upload direct plutôt que de GitHub, même si
            # l'entrée avait un dépôt connu avant ce repackaging.
            "repo": result.get("repo"),
        }
        _write_raw(entries)
    return entry


def _set_update_warning(entry_id: str, warning: dict | None) -> None:
    """Lecture-modification-écriture DÉDIÉE (verrou propre à cet appel, jamais partagé avec un
    appel en cours à `repackage_library_app`) — voir `check_for_updates` ci-dessous : cette
    fonction ne doit JAMAIS travailler sur une copie de `entries` gardée en mémoire d'un appel
    précédent, sous peine d'écraser une mise à jour concurrente faite entre-temps par
    `repackage_library_app` sur une AUTRE entrée de la même liste."""
    with _lock:
        entries = _read_raw()
        entry = next((e for e in entries if e.get("id") == entry_id), None)
        if entry is None or not entry.get("package"):
            return
        if warning is None:
            entry["package"].pop("updateWarning", None)
        else:
            entry["package"]["updateWarning"] = warning
        _write_raw(entries)


@handle_tool_errors
def check_for_updates() -> dict:
    """Vérifie, pour chaque entrée packagée dont le dépôt GitHub d'origine est connu
    (`entry.package.repo`, voir packaging.py::_write_source_repo — absent sur les entrées
    créées ou repackagées avant l'ajout de ce champ, 2026-08-27), si une release plus récente
    que la version actuellement enregistrée est disponible sur ce dépôt, et REPACKAGE
    AUTOMATIQUEMENT celles qui le sont — "système de mise à jour automatique", demande
    explicite de Nicolas, déclenché par un bouton manuel côté catalogue (PAS une tâche de
    fond : cadrage tranché avec lui, "bouton manuel... pas de tâche de fond qui tourne sans que
    tu la voies").

    Le nom de l'asset à récupérer dans la NOUVELLE release est déduit de celui utilisé pour la
    version actuelle (`packaging._derive_expected_asset_name` — substitution du tag connu,
    jamais une heuristique de contenu). Si la déduction échoue OU que le nom déduit n'existe
    pas parmi les assets de la nouvelle release : PAS de choix à l'aveugle (demande explicite de
    Nicolas : "s'il tu as un doute de mettre un warning sur l'app et demander de choisir sur le
    repo") — l'entrée est marquée `needs_review` (`entry.package.updateWarning`, persistant
    jusqu'à ce que l'admin la repackage lui-même via "Modifier une application", qui remplace
    `package` en entier et efface donc ce champ implicitement).

    Chaque entrée est traitée indépendamment (une erreur réseau/GitHub sur l'une n'interrompt
    pas les suivantes) ; `results` liste le sort de CHAQUE entrée avec un dépôt connu, y compris
    "up_to_date", pour que le frontend puisse afficher un résumé complet plutôt que seulement
    les changements."""
    with _lock:
        entries = _read_raw()

    results = []
    for entry in entries:
        if entry.get("source") != "packaged":
            continue
        pkg = entry.get("package") or {}
        repo_meta = pkg.get("repo") or {}
        owner, repo, asset_name = repo_meta.get("owner"), repo_meta.get("repo"), repo_meta.get("assetName")
        entry_id, display_name = entry.get("id"), entry.get("displayName")
        if not (owner and repo and asset_name):
            continue  # pas de dépôt connu (entrée pré-2026-08-27, ou source uploadée) — rien à vérifier

        current_version = entry.get("version") or ""
        latest = _packaging.github_lookup_releases(owner=owner, repo=repo)
        if isinstance(latest, dict) and latest.get("error"):
            results.append({"id": entry_id, "displayName": display_name, "status": "error", "message": latest.get("message")})
            continue

        latest_tag = latest.get("tagName")
        if not latest_tag or latest_tag == current_version:
            results.append({"id": entry_id, "displayName": display_name, "status": "up_to_date", "version": current_version})
            continue

        expected_name = _packaging._derive_expected_asset_name(asset_name, current_version, latest_tag)
        asset = next((a for a in latest.get("assets", []) if a.get("name") == expected_name), None) if expected_name else None
        if asset is None:
            _set_update_warning(entry_id, {
                "latestTag": latest_tag,
                "message": (
                    f"Nouvelle version {latest_tag} disponible, mais l'asset correspondant n'a pas pu être "
                    "déterminé automatiquement — choisis-le manuellement via « Modifier une application » > "
                    "« Repackager avec une autre version »."
                ),
            })
            results.append(
                {"id": entry_id, "displayName": display_name, "status": "needs_review", "fromVersion": current_version, "toVersion": latest_tag}
            )
            continue

        job_id = None
        try:
            job_id = _packaging.create_job()["jobId"]
            fetched = _packaging.github_fetch_asset(
                job_id=job_id, download_url=asset.get("downloadUrl"), asset_name=asset.get("name"), owner=owner, repo=repo
            )
            if isinstance(fetched, dict) and fetched.get("error"):
                raise ValueError(fetched.get("message") or "Échec du téléchargement de l'asset.")

            cfg = pkg.get("config") or {}
            packaged = _packaging.package_app(
                job_id=job_id,
                install_mode=cfg.get("installMode", "silent"),
                options=cfg.get("options") or [],
                application_name=display_name or "",
                version=latest_tag,
                detection_mode=cfg.get("detectionMode", "greaterOrEqual"),
            )
            if isinstance(packaged, dict) and packaged.get("error"):
                raise ValueError(packaged.get("message") or "Échec du packaging.")

            updated = repackage_library_app(entry_id=entry_id, job_id=job_id)
            if isinstance(updated, dict) and updated.get("error"):
                raise ValueError(updated.get("message") or "Échec du repackaging.")
        except Exception as exc:
            results.append({"id": entry_id, "displayName": display_name, "status": "error", "message": str(exc)})
            continue
        finally:
            # Job éphémère interne, jamais exposé au frontend — nettoyé immédiatement plutôt
            # que laissé au TTL non implémenté de PACKAGING_WORKDIR (limitation connue,
            # documentée ailleurs) : rien ne le référence plus après ce point.
            if job_id:
                shutil.rmtree(_packaging.PACKAGING_WORKDIR / job_id, ignore_errors=True)

        results.append(
            {"id": entry_id, "displayName": display_name, "status": "updated", "fromVersion": current_version, "toVersion": latest_tag}
        )

    return {"results": results}


@handle_tool_errors
def remove_library_app(entry_id: str) -> bool:
    """Retire une entrée de la bibliothèque et supprime son livrable associé s'il existe.
    Renvoie `False` (pas une erreur) si elle n'y était déjà plus — même convention que
    defender/watchlist.py::remove_watched_cve (un double-clic ne doit pas être un échec)."""
    with _lock:
        entries = _read_raw()
        remaining = [e for e in entries if e["id"] != entry_id]
        removed = len(remaining) != len(entries)
        if removed:
            _write_raw(remaining)
    if removed:
        shutil.rmtree(LIBRARY_FILES_DIR / entry_id, ignore_errors=True)
    return removed


def library_deliverable_path(entry_id: str) -> Path:
    """PAS décorée @handle_tool_errors (retourne un `Path`, pas un dict) — même raisonnement
    que packaging.py::build_deliverable_zip : appelée directement par la route de
    téléchargement, qui convertit elle-même une exception en `HTTPException`."""
    entry = next((e for e in list_library_apps() if e.get("id") == entry_id), None)
    if entry is None:
        raise ValueError(f"Application introuvable dans la bibliothèque : {entry_id}")
    if entry.get("source") != "packaged":
        raise ValueError("Cette entrée n'a pas de livrable technique associé (ajout manuel).")
    zip_path = LIBRARY_FILES_DIR / entry_id / "deliverable.zip"
    if not zip_path.is_file():
        raise ValueError("Livrable introuvable pour cette entrée.")
    return zip_path
