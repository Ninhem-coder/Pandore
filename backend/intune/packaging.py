"""
Assistant de packaging Win32 pour Intune (2026-08-26, demande de Nicolas) — prépare un
livrable (`.intunewin` + commandes d'installation/désinstallation + script de détection
PowerShell) que l'admin colle ensuite À LA MAIN dans l'Intune admin center. CE MODULE NE
PUBLIE JAMAIS RIEN SUR INTUNE : aucun appel Graph en écriture ici — le geste manuel de
création de l'app dans Intune reste le seul point de publication, et donc le vrai gate de
revue humaine (cadrage validé explicitement avec Nicolas avant la conception détaillée).

Volontairement PAS ajouté à `TOOL_MODULES` dans `intune/mcp_server.py` : ce n'est pas un
outil de lecture de données Intune comme le reste de ce package, donc hors du contrat de
parité vérifié par `tests/test_mcp_tool_parity.py` — rester hors de `TOOL_MODULES` évite
complètement la contrainte plutôt que d'y ajouter une exclusion.

V1 scopée aux installeurs **MSI uniquement** (décision explicite de Nicolas, 2026-08-26) —
les options de ligne de commande (`/qn`, `/norestart`...) sont un vocabulaire MSI, pas
générique à tous les formats d'installeur (NSIS/Inno Setup ont une syntaxe différente).

Élargie le 2026-08-27 (demande de Nicolas) aux **scripts PowerShell** (`.ps1`) comme second
type de source pris en charge, EN PLUS du MSI (pas un remplacement) — voir `package_app` :
le TYPE de source est déduit de l'EXTENSION du fichier déposé/téléchargé, pas d'un paramètre
supplémentaire à faire porter par le wizard. Trois différences tranchées avec Nicolas
(`AskUserQuestion`) par rapport au MSI :
- Commande d'installation générée automatiquement (`powershell -executionpolicy bypass -file
  .\\Pandore.ps1`), mais PAS de "mode d'installation"/"options complémentaires" (vocabulaire
  msiexec, sans équivalent générique pour un script arbitraire — ces deux écrans du wizard
  n'ont pas de sens pour une source PowerShell).
- Commande de désinstallation : PAS auto-générée (un script n'a pas d'équivalent `msiexec
  /x` intégré) — laissée à la saisie manuelle de l'admin (`uninstall_command`, nouveau
  paramètre de `package_app`).
- Règle de détection : le MÊME gabarit registre que pour un MSI (`_render_detection_script`,
  inchangé) — fonctionne tant que le script installe lui-même quelque chose qui s'enregistre
  dans les clés Uninstall standard (cas courant : un script qui pose un MSI/EXE en sous-main).

Un "job" = un répertoire scratch nommé par un UUID4 (`PACKAGING_WORKDIR/<job_id>/`), qui
porte toute une session de packaging de bout en bout :
    <job_id>/
        source/<nom original ou "installeur.msi">   — l'installeur (upload direct ou GitHub)
        source/Pandore.msi                           — copie renommée, produite par package_app
        output/*.intunewin                           — généré par IntuneWinAppUtil.exe
        package_result.json                          — résultat de package_app, relu par
                                                          build_deliverable_zip (voir plus bas)
        deliverable.zip                               — livrable final téléchargé par l'admin

Premier module de ce backend à écrire des fichiers binaires sur disque et à exécuter un
process externe (`IntuneWinAppUtil.exe`) — voir les commentaires de sécurité sur
`_sanitize_filename`/`package_app` ci-dessous, qui posent les mêmes garde-fous que
`validate_graph_id`/`escape_odata_string` (common/http_client.py) mais pour cette nouvelle
classe de risque (chemins de fichiers, arguments de subprocess).
"""
import hashlib
import json
import re
import shutil
import subprocess
import uuid
import zipfile
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx

from common.atomic_io import atomic_write_text
from common.config import INTUNEWIN_TOOL_PATH, PACKAGING_WORKDIR
from common.http_client import handle_tool_errors, validate_graph_id

# Taille max acceptée pour un installeur (upload direct ou téléchargement GitHub) — hygiène
# de base pour ne pas remplir le disque avec un fichier de plusieurs Go ; ce n'est PAS une
# protection de sécurité à proprement parler (l'admin qui utilise cet outil est déjà
# l'utilisateur de confiance unique de ce dashboard local, voir api_server.py).
MAX_SOURCE_SIZE_BYTES = 1024 * 1024 * 1024  # 1 Go
_CHUNK_SIZE = 1024 * 1024

# Un gros MSI peut prendre plusieurs dizaines de secondes à traiter par IntuneWinAppUtil.exe.
_INTUNEWIN_TIMEOUT_S = 300

# Nom de fichier imposé au setup avant packaging (convention interne, demande de
# Nicolas) — conservé en `.msi` plutôt que forcé en `.exe` comme dans sa demande initiale :
# la V1 est scopée MSI uniquement (décision prise après cette demande), et `msiexec /i
# Pandore.exe` sur un binaire MSI renommé en `.exe` fonctionnerait mais serait trompeur à la
# lecture d'une commande générée.
_PANDORE_FILENAME = "Pandore.msi"
# Second type de source (2026-08-27) — même convention de nommage "Pandore", juste
# l'extension qui change selon le type de source déposé (voir `package_app`).
_PANDORE_PS1_FILENAME = "Pandore.ps1"
# Types de source pris en charge : extension du fichier déposé → nom "Pandore.*" imposé.
_SOURCE_TYPE_BY_EXT = {".msi": ("msi", _PANDORE_FILENAME), ".ps1": ("powershell", _PANDORE_PS1_FILENAME)}

# Hôtes de téléchargement GitHub légitimes — garde-fou de bon sens plutôt qu'une vraie
# frontière de sécurité (l'admin qui pilote cet outil pourrait de toute façon télécharger
# n'importe quoi lui-même) : évite juste que `github_fetch_asset` ne devienne accidentellement
# un downloader générique si `download_url` n'est pas ce qu'on attend.
_ALLOWED_DOWNLOAD_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}

_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9._ -]{1,255}$")
_SAFE_EXT_RE = re.compile(r"^\.[A-Za-z0-9]{1,10}$")
_GITHUB_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def _job_dir(job_id: str) -> Path:
    """Résout et valide le répertoire d'un job existant. `validate_graph_id` (déjà utilisée
    pour tous les ID Graph/MDE interpolés dans une URL, common/http_client.py) est réutilisée
    telle quelle ici : un UUID4 satisfait le même motif `^[A-Za-z0-9_-]{1,128}$`, et ça évite
    qu'un `job_id` contenant "/", ".." ou "%" ne change le répertoire réellement résolu sous
    `PACKAGING_WORKDIR` une fois interpolé dans un chemin — même raisonnement que pour un ID
    Graph dans une URL, appliqué ici à un chemin de fichier local plutôt qu'à une requête HTTP."""
    validate_graph_id(job_id, "job_id")
    job_dir = PACKAGING_WORKDIR / job_id
    if not job_dir.is_dir():
        raise ValueError(f"Job de packaging introuvable ou expiré : {job_id}")
    return job_dir


def _sanitize_filename(filename: str) -> str:
    """Isole le nom de fichier de tout composant de chemin (`Path(...).name` retire
    `../`/`/`) puis le valide contre une liste blanche de caractères. Un nom qui ne passe pas
    ce filtre (unicode exotique, caractères de contrôle...) retombe sur un nom neutre plutôt
    que d'être rejeté — seule l'EXTENSION d'origine est conservée quand elle est elle-même
    propre, pour qu'un `.msi` reste identifiable comme tel dans le reste du pipeline."""
    name = Path(filename or "installeur.msi").name
    # 🔧 Cas limite corrigé le 2026-09-07 (revue de sécurité) : `_SAFE_FILENAME_RE` autorise le
    # point dans son alphabet (pour une extension), donc un nom composé UNIQUEMENT de points
    # (`".."`, `"..."`...) le passait tel quel — `Path("..").name` ne retire PAS `..` comme le
    # ferait une résolution de chemin (pathlib le traite comme un segment de nom normal, pas
    # une référence au parent, quand on lit `.name`). `source_dir / ".."` résout alors au
    # répertoire du JOB LUI-MÊME plutôt qu'à un fichier dans `source/` — pas une évasion hors de
    # `PACKAGING_WORKDIR` (le chemin résolu reste dans l'arborescence du job), mais un
    # `open(job_dir, "wb")` qui échoue avec une erreur peu claire au lieu du fichier neutre
    # attendu. Rejeté explicitement, comme n'importe quel autre nom qui ne passerait pas le
    # filtre.
    if _SAFE_FILENAME_RE.match(name) and name.strip(".") != "":
        return name
    ext = Path(name).suffix
    ext = ext if _SAFE_EXT_RE.match(ext) else ""
    return f"installeur{ext}"


def _consume_stream_to_file(dest: Path, chunks) -> dict:
    """Écrit un flux d'octets (upload FastAPI ou réponse `httpx.stream`) vers `dest`, en
    calculant le SHA256 au fil de l'eau (affiché côté UI pour vérification manuelle — pas de
    source de vérité pour un checksum "officiel" par dépôt, donc pas de vérification
    automatique, juste de la transparence) et en coupant court si `MAX_SOURCE_SIZE_BYTES` est
    dépassé plutôt que de le découvrir après avoir tout écrit sur disque."""
    sha256 = hashlib.sha256()
    size = 0
    try:
        with open(dest, "wb") as f:
            for chunk in chunks:
                if not chunk:
                    continue
                size += len(chunk)
                if size > MAX_SOURCE_SIZE_BYTES:
                    raise ValueError(f"Fichier trop volumineux (> {MAX_SOURCE_SIZE_BYTES // (1024 * 1024)} Mo).")
                sha256.update(chunk)
                f.write(chunk)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    return {"fileName": dest.name, "sizeBytes": size, "sha256": sha256.hexdigest()}


def _clear_source_dir(source_dir: Path) -> None:
    """Un seul fichier source par job — un nouvel upload/téléchargement remplace le
    précédent plutôt que de s'accumuler à côté."""
    for existing in source_dir.iterdir():
        if existing.is_file():
            existing.unlink()


# `source_repo.json` (2026-08-27, demande de Nicolas : "quand une app est créée, enregistrer le
# lien du dépôt Git pour proposer les versions dispo sur le repo lors de la modification") —
# mémorise l'`owner`/`repo` GitHub d'origine d'un job AU NIVEAU DU JOB (pas juste dans l'état
# React du wizard, qui disparaît une fois la popup fermée) : `package_app` le relit pour
# l'inclure dans son résultat persisté, et `app_library.py::add_packaged_app`/
# `repackage_library_app` le copient sur l'entrée. Absent (pas de fichier) = source déposée par
# upload direct, jamais associée à un dépôt — pas une erreur, juste rien à proposer plus tard.
#
# `asset_name` (2026-08-27, demande de Nicolas : "système de mise à jour automatique" — voir
# `app_library.py::check_for_updates`) — le nom EXACT de l'asset choisi (ex.
# "7z2602-x64.msi"), gardé en plus d'owner/repo : `_derive_expected_asset_name` en a besoin
# pour deviner le nom de l'asset correspondant dans une NOUVELLE release, en y substituant le
# nouveau tag à la place de l'ancien.
def _write_source_repo(job_dir: Path, owner: str | None, repo: str | None, asset_name: str | None = None) -> None:
    meta_path = job_dir / "source_repo.json"
    if owner and repo and _GITHUB_SEGMENT_RE.match(owner) and _GITHUB_SEGMENT_RE.match(repo):
        atomic_write_text(
            meta_path, json.dumps({"owner": owner, "repo": repo, "assetName": asset_name}, ensure_ascii=False)
        )
    else:
        meta_path.unlink(missing_ok=True)


def _read_source_repo(job_dir: Path) -> dict | None:
    meta_path = job_dir / "source_repo.json"
    if not meta_path.is_file():
        return None
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


@handle_tool_errors
def create_job() -> dict:
    """Démarre une nouvelle session de packaging : crée le répertoire scratch du job. Le
    `jobId` (UUID4, imprévisible) sert de clé à toutes les étapes suivantes du wizard."""
    job_id = str(uuid.uuid4())
    job_dir = PACKAGING_WORKDIR / job_id
    (job_dir / "source").mkdir(parents=True)
    (job_dir / "output").mkdir(parents=True)
    return {"jobId": job_id}


@handle_tool_errors
def save_uploaded_source(job_id: str, filename: str, stream) -> dict:
    """Dépôt direct : `stream` est un objet fichier lisible par blocs (ex.
    `UploadFile.file` côté FastAPI) — signature volontairement sans dépendance à FastAPI,
    cohérent avec le reste de ce package ("fonctions nues" réutilisables hors de la couche
    API)."""
    job_dir = _job_dir(job_id)
    source_dir = job_dir / "source"
    _clear_source_dir(source_dir)
    # Un upload direct remplace toute source GitHub précédemment déposée sur ce job (repackage
    # avec un fichier local après avoir d'abord cherché sur GitHub, par exemple) — la source
    # n'a alors plus de dépôt d'origine à retenir.
    _write_source_repo(job_dir, None, None, None)
    dest = source_dir / _sanitize_filename(filename)

    def _chunks():
        while chunk := stream.read(_CHUNK_SIZE):
            yield chunk

    return _consume_stream_to_file(dest, _chunks())


@handle_tool_errors
def github_list_releases(owner: str, repo: str) -> dict:
    """Liste TOUTES les releases publiées d'un dépôt GitHub public (2026-08-26, demande de
    Nicolas : "voir toutes les versions dans le repo git pour pouvoir le changer") — juste les
    métadonnées (tag/nom/date), PAS les assets de chacune (ceux-ci ne sont récupérés qu'à la
    demande, une fois une release choisie, voir `github_lookup_releases` ci-dessous) : éviter
    un appel GitHub par release pour un simple listing. `per_page=100` (max GitHub) — un dépôt
    avec plus de 100 releases ne montrerait que les 100 plus récentes ; hypothèse jugée
    raisonnable pour un usage de packaging interne (pas de pagination implémentée, pas de cas
    réel rencontré à ce jour justifiant l'effort)."""
    if not _GITHUB_SEGMENT_RE.match(owner or "") or not _GITHUB_SEGMENT_RE.match(repo or ""):
        raise ValueError("Organisation ou dépôt GitHub invalide.")
    resp = httpx.get(
        f"https://api.github.com/repos/{owner}/{repo}/releases",
        headers={"Accept": "application/vnd.github+json"},
        params={"per_page": 100},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return {
        "releases": [
            {"tagName": r.get("tag_name"), "name": r.get("name"), "publishedAt": r.get("published_at")}
            for r in data
        ],
    }


@handle_tool_errors
def github_lookup_releases(owner: str, repo: str, tag: str | None = None) -> dict:
    """Liste TOUS les assets d'UNE release d'un dépôt GitHub public — ne télécharge rien.
    L'admin choisit l'asset dans l'UI (`github_fetch_asset` ci-dessous) : volontairement AUCUNE
    sélection automatique par regex/heuristique de nom (un repo comme `ip7z/7zip` publie
    plusieurs assets par release — x86/x64/msi/exe/extra) — le choix explicite de l'admin est
    le garde-fou contre un mauvais asset packagé et poussé par erreur.

    `tag` optionnel (2026-08-26, demande de Nicolas — voir `github_list_releases` ci-dessus) :
    absent/vide, se comporte EXACTEMENT comme avant ce changement (dernière release,
    `/releases/latest`) — rétrocompatible avec l'appel existant du wizard. Fourni (une release
    choisie dans la liste), cible cette release précise (`/releases/tags/{tag}`)."""
    if not _GITHUB_SEGMENT_RE.match(owner or "") or not _GITHUB_SEGMENT_RE.match(repo or ""):
        raise ValueError("Organisation ou dépôt GitHub invalide.")
    if tag:
        url = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{quote(tag, safe='')}"
    else:
        url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    resp = httpx.get(url, headers={"Accept": "application/vnd.github+json"}, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        "tagName": data.get("tag_name"),
        "publishedAt": data.get("published_at"),
        "assets": [
            {"name": a.get("name"), "sizeBytes": a.get("size"), "downloadUrl": a.get("browser_download_url")}
            for a in data.get("assets", [])
        ],
    }


@handle_tool_errors
def github_fetch_asset(job_id: str, download_url: str, asset_name: str, owner: str | None = None, repo: str | None = None) -> dict:
    """Télécharge l'asset CHOISI PAR L'ADMIN (voir `github_lookup_releases`) dans le
    répertoire source du job. Même contrat de retour que `save_uploaded_source`, pour que le
    frontend traite les deux sources de façon identique une fois cette étape passée.

    `owner`/`repo` optionnels (2026-08-27, demande de Nicolas — voir `_write_source_repo`) :
    le dépôt d'origine de cet asset, pour que `package_app` puisse le faire remonter dans son
    résultat et que la bibliothèque le retienne sur l'entrée créée."""
    host = urlparse(download_url or "").hostname or ""
    if host not in _ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError(f"URL de téléchargement hors GitHub refusée : {download_url!r}")
    job_dir = _job_dir(job_id)
    source_dir = job_dir / "source"
    _clear_source_dir(source_dir)
    dest = source_dir / _sanitize_filename(asset_name)

    # Revue de sécurité (2026-09-02) : `follow_redirects=True` suit la redirection où qu'elle
    # mène — le contrôle d'hôte ci-dessus ne portait que sur l'URL DE DÉPART. Un hôte de départ
    # légitime (github.com) qui redirigerait vers un hôte hors liste blanche (volontairement ou
    # via une faille côté GitHub) contournerait donc le garde-fou. `resp.url` (httpx) porte
    # l'URL FINALE une fois les redirections suivies — revérifiée après coup, avant d'écrire le
    # moindre octet sur disque.
    with httpx.stream("GET", download_url, follow_redirects=True, timeout=120) as resp:
        final_host = resp.url.host or ""
        if final_host not in _ALLOWED_DOWNLOAD_HOSTS:
            raise ValueError(f"Redirection de téléchargement hors GitHub refusée : {str(resp.url)!r}")
        resp.raise_for_status()
        result = _consume_stream_to_file(dest, resp.iter_bytes(_CHUNK_SIZE))
    # `asset_name` (pas `dest.name`/le nom assaini) : c'est la valeur à comparer plus tard aux
    # noms bruts renvoyés par l'API GitHub (voir `_derive_expected_asset_name`) — un nom assaini
    # divergerait de ce que GitHub renvoie réellement pour la même release.
    _write_source_repo(job_dir, owner, repo, asset_name)
    return result


# Transformations candidates essayées dans l'ordre par `_derive_expected_asset_name` — chacune
# normalise un tag GitHub d'une façon différente avant de chercher son EMPREINTE dans l'ancien
# nom de fichier (2026-08-27, demande de Nicolas : "système de mise à jour automatique", voir
# `app_library.py::check_for_updates`). Ordonnées de la plus stricte (tag tel quel) à la plus
# permissive (chiffres seuls) — la première transformation qui matche l'ancien nom de fichier
# EXACTEMENT UNE FOIS est retenue, pour éviter un remplacement ambigu si le motif apparaît
# plusieurs fois (ex. un numéro qui serait aussi une taille ou un code d'architecture).
_ASSET_TAG_TRANSFORMS = [
    lambda t: t,  # tag brut — ex. asset "myapp-1.2.3-win64.exe", tag "1.2.3"
    lambda t: t.lstrip("vV"),  # tag préfixé "v" — ex. tag "v1.2.3" → "1.2.3"
    lambda t: t.replace(".", "_"),  # séparateur underscore plutôt que point
    lambda t: t.lstrip("vV").replace(".", "_"),
    lambda t: re.sub(r"[^0-9]", "", t),  # chiffres seuls, concaténés — ex. 7-Zip : tag "26.02"
    # → "2602", trouvé tel quel dans "7z2602-x64.msi" (aucun séparateur dans le nom de fichier)
]


def _derive_expected_asset_name(old_asset_name: str, old_tag: str, new_tag: str) -> str | None:
    """Devine le nom de l'asset correspondant dans une NOUVELLE release, à partir du nom de
    l'asset utilisé pour la version ACTUELLE — jamais par heuristique de contenu/regex sur le
    nom lui-même (décision de conception explicite de `github_lookup_releases` : le choix
    d'asset reste toujours humain dans le wizard), mais par SUBSTITUTION du tag connu par le
    nouveau, seulement quand ce tag apparaît de façon NON AMBIGUË (une seule fois) dans l'ancien
    nom de fichier. Renvoie `None` si aucune transformation ne matche exactement une fois — à
    charge de l'appelant de traiter ça comme "je ne sais pas", jamais de deviner au-delà."""
    if not old_asset_name or not old_tag or not new_tag:
        return None
    for transform in _ASSET_TAG_TRANSFORMS:
        old_variant = transform(old_tag)
        if old_variant and old_asset_name.count(old_variant) == 1:
            new_variant = transform(new_tag)
            return old_asset_name.replace(old_variant, new_variant, 1)
    return None


# Les 3 modes documentés dans la demande initiale de Nicolas — "Affichage"/"Silencieux"
# partagent tous les deux une UI msiexec minimale (pas d'interaction possible), la différence
# ("notification visible" vs "aucune notification") tient à `/qb!` (barre de progression sans
# bouton Annuler) vs `/qn` (rien du tout), pas à un autre paramètre `-DeployMode` : ce dernier
# relève de l'assignation Intune (délai de report), pas de la ligne de commande msiexec
# elle-même.
_INSTALL_MODE_UI_FLAGS = {
    "interactive": "",
    "displayed": "/qb!",
    "silent": "/qn",
}

# Switches complémentaires (2026-08-26, demande de Nicolas) — cochables indépendamment du
# mode. Vocabulaire MSI standard uniquement (V1 scopée MSI). `norestart`/`forcerestart`/
# `promptrestart` sont TOUS LES TROIS des variantes du même comportement "que faire si un
# redémarrage est requis" — mutuellement exclusifs entre eux (pas juste les deux premiers),
# voir `_RESTART_BEHAVIOR_OPTIONS` ci-dessous. `logverbose` est orthogonal (journalisation),
# cumulable avec n'importe lequel des trois.
_OPTION_SWITCHES = {
    "norestart": "/norestart",
    "forcerestart": "/forcerestart",
    "promptrestart": "/promptrestart",
    "logverbose": "/l*v Pandore-install.log",
}
_RESTART_BEHAVIOR_OPTIONS = {"norestart", "forcerestart", "promptrestart"}


def _msi_commands(install_mode: str, options: list[str]) -> tuple[str, str]:
    ui_flag = _INSTALL_MODE_UI_FLAGS.get(install_mode)
    if ui_flag is None:
        raise ValueError(f"Mode d'installation inconnu : {install_mode!r}")
    unknown = set(options or []) - _OPTION_SWITCHES.keys()
    if unknown:
        raise ValueError(f"Option(s) inconnue(s) : {sorted(unknown)}")
    # Mutuellement exclusifs — le frontend doit les présenter en radio (un seul comportement
    # de redémarrage à la fois), pas en cases indépendantes, mais la garde vit aussi ici : ne
    # jamais faire confiance à la seule UI.
    chosen_restart_behaviors = _RESTART_BEHAVIOR_OPTIONS & set(options or [])
    if len(chosen_restart_behaviors) > 1:
        raise ValueError(f"Comportements de redémarrage mutuellement exclusifs : {sorted(chosen_restart_behaviors)}")

    extra = " ".join(_OPTION_SWITCHES[o] for o in options)
    install = " ".join(p for p in ["msiexec", "/i", _PANDORE_FILENAME, ui_flag, extra] if p)
    uninstall = " ".join(p for p in ["msiexec", "/x", _PANDORE_FILENAME, ui_flag, extra] if p)
    return install, uninstall


def _powershell_commands(uninstall_command: str) -> tuple[str, str]:
    """Source PowerShell (2026-08-27, demande de Nicolas) — commande d'installation FIXE
    (`_PANDORE_PS1_FILENAME` est toujours le même nom imposé, rien à paramétrer côté wizard,
    contrairement au MSI qui a un mode d'installation/des options). Syntaxe confirmée
    explicitement par Nicolas : `powershell -executionpolicy bypass -file .\\<script>`.

    Désinstallation : PAS de générateur — `uninstall_command` est le texte SAISI PAR L'ADMIN
    (aucun équivalent `msiexec /x` pour un script arbitraire, décision explicite de Nicolas :
    "commande de désinstallation à saisir à la main"). Renvoyé tel quel, y compris vide (le
    frontend affiche alors une invite à le compléter plutôt que de laisser croire qu'aucune
    désinstallation n'est nécessaire)."""
    install = f"powershell -executionpolicy bypass -file .\\{_PANDORE_PS1_FILENAME}"
    return install, (uninstall_command or "").strip()


# Template de détection PowerShell — AUCUN template existant à réutiliser (tranché avec
# Nicolas) : conçu ici comme un gabarit standard "recherche par nom dans les clés Uninstall du
# registre + comparaison de version", le motif le plus courant en détection Win32 Intune qui
# ne nécessite PAS de connaître le ProductCode MSI (aurait demandé d'inspecter le binaire MSI
# pour l'extraire — hors scope V1). Placeholders `__APPLICATION__`/`__VERSION__`/`__MODE__`
# (PAS `$Application` etc. directement : le script généré définit LUI-MÊME des variables
# PowerShell `$Application`/`$Version`/`$Mode`, un remplacement Python sur `$Application`
# aurait aussi matché la définition de variable elle-même — `__XXX__` ne collisionne avec
# rien de la syntaxe PowerShell environnante). `$Mode` = mode de comparaison de version
# ("equals" ou "greaterOrEqual") — à valider avec Nicolas sur un premier jet réel, le
# placeholder n'imposait pas cette sémantique précise dans sa demande initiale.
_DETECTION_TEMPLATE = """# Script de détection généré par l'assistant de packaging Win32 — à coller tel quel dans
# Intune > Applications > Win32 > Règles de détection > "Utiliser un script personnalisé".
$Application = "__APPLICATION__"
$Version     = "__VERSION__"
$Mode        = "__MODE__"  # "equals" ou "greaterOrEqual"

$uninstallKeys = @(
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
    "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
)

$match = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq $Application } |
    Select-Object -First 1

if (-not $match) {
    exit 1
}

try {
    $installedVersion = [version]$match.DisplayVersion
    $targetVersion = [version]$Version
} catch {
    exit 1
}

$detected = if ($Mode -eq "equals") {
    $installedVersion -eq $targetVersion
} else {
    $installedVersion -ge $targetVersion
}

if ($detected) {
    Write-Output "Installed"
    exit 0
}
exit 1
"""
_PLACEHOLDER_RE = re.compile(r"__(APPLICATION|VERSION|MODE)__")


def _escape_ps_double_quoted(value: str) -> str:
    """Échappe une valeur destinée à un littéral PowerShell ENTRE GUILLEMETS DOUBLES (le
    template `_DETECTION_TEMPLATE` ci-dessus, `$Application = "..."`). Revue de sécurité du
    2026-09-02 : la version précédente n'échappait que `"`, mais une chaîne PowerShell entre
    guillemets doubles INTERPOLE aussi `$variable`/`$(sous-expression)` et le backtick est son
    propre caractère d'échappement — un `application_name`/`version`/`detection_mode`
    contenant `$(...)` s'exécuterait donc tel quel dans le script généré. Vecteur concret :
    `check_for_updates()` (app_library.py) régénère `version` à partir du tag de la DERNIÈRE
    release GitHub d'un dépôt suivi (`github_lookup_releases`, nom de tag non contrôlé par ce
    backend) — un tag malveillant sur un dépôt suivi aurait pu injecter du PowerShell dans un
    script ensuite collé par l'admin dans Intune et déployé sur tout le parc. Ordre important :
    doubler les backticks AVANT d'ajouter les échappements `` `$ ``/`` `" ``, sinon ces derniers
    seraient eux-mêmes redoublés par erreur."""
    return (value or "").replace("`", "``").replace("$", "`$").replace('"', '`"')


def _render_detection_script(application: str, version: str, detection_mode: str) -> str:
    """Remplacement de chaîne SIMPLE sur des valeurs déjà saisies dans le wizard — jamais
    d'`eval`/moteur de template : le résultat est un texte destiné à être copié dans Intune,
    jamais exécuté par ce backend. Valeurs échappées via `_escape_ps_double_quoted` (backticks/
    `$`/guillemets doubles) pour ne jamais rompre le littéral généré NI y injecter de code
    PowerShell exécutable — voir son docstring pour le vecteur concret déjà identifié."""
    values = {
        "APPLICATION": _escape_ps_double_quoted(application),
        "VERSION": _escape_ps_double_quoted(version),
        "MODE": _escape_ps_double_quoted(detection_mode or "greaterOrEqual"),
    }
    return _PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], _DETECTION_TEMPLATE)


@handle_tool_errors
def package_app(
    job_id: str,
    install_mode: str,
    options: list[str],
    application_name: str,
    version: str,
    detection_mode: str = "greaterOrEqual",
    uninstall_command: str = "",
) -> dict:
    """Cœur du packaging : copie la source en `Pandore.msi`/`Pandore.ps1` (selon son
    extension — voir `_SOURCE_TYPE_BY_EXT`), exécute `IntuneWinAppUtil.exe -c <source> -s
    Pandore.* -o <output> -q`, génère les commandes d'installation/désinstallation et le
    script de détection. Le résultat est persisté dans `package_result.json`
    (`common/atomic_io.atomic_write_text`, même utilitaire que `common/history.py`/
    `common/auth.py`) pour que `build_deliverable_zip` puisse le relire sans repasser par
    IntuneWinAppUtil.exe.

    `install_mode`/`options` ne s'appliquent QUE pour une source MSI (vocabulaire msiexec,
    voir `_msi_commands`) — ignorés pour une source PowerShell, dont la commande
    d'installation est fixe (`_powershell_commands`). `uninstall_command` c'est l'inverse :
    ignoré pour une source MSI (auto-générée), utilisé UNIQUEMENT pour une source PowerShell
    (saisie manuelle de l'admin, pas de générateur possible pour un script arbitraire —
    décision explicite de Nicolas)."""
    job_dir = _job_dir(job_id)
    source_dir = job_dir / "source"
    sources = [
        p for p in source_dir.iterdir() if p.is_file() and p.name not in (_PANDORE_FILENAME, _PANDORE_PS1_FILENAME)
    ]
    if not sources:
        raise ValueError("Aucune source déposée pour ce job — dépose un installeur avant de packager.")

    source_ext = sources[0].suffix.lower()
    if source_ext not in _SOURCE_TYPE_BY_EXT:
        raise ValueError(
            f"Format de source non pris en charge ({source_ext or 'sans extension'}) — "
            "installeur MSI (.msi) ou script PowerShell (.ps1) uniquement."
        )
    source_type, pandore_filename = _SOURCE_TYPE_BY_EXT[source_ext]

    if not INTUNEWIN_TOOL_PATH:
        raise ValueError("INTUNEWIN_TOOL_PATH non configuré (voir backend/.env.example).")
    tool_path = Path(INTUNEWIN_TOOL_PATH)
    if not tool_path.is_file():
        raise ValueError(f"IntuneWinAppUtil.exe introuvable à INTUNEWIN_TOOL_PATH={INTUNEWIN_TOOL_PATH!r}.")

    pandore_path = source_dir / pandore_filename
    # Copie plutôt que renommage in-place : garde la source d'origine intacte pour repackager
    # avec d'autres options sans redéposer/re-télécharger le fichier.
    shutil.copy2(sources[0], pandore_path)

    output_dir = job_dir / "output"
    for stale in output_dir.iterdir():
        if stale.is_file():
            stale.unlink()

    # Liste d'arguments, JAMAIS de chaîne shell (shell=False) — première invocation de
    # process externe dans ce backend, mêmes garde-fous que le reste du code base applique
    # aux requêtes Graph (validate_graph_id/escape_odata_string) transposés à un subprocess.
    proc = subprocess.run(
        [str(tool_path), "-c", str(source_dir), "-s", pandore_filename, "-o", str(output_dir), "-q"],
        shell=False,
        capture_output=True,
        text=True,
        timeout=_INTUNEWIN_TIMEOUT_S,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:500]
        # `ValueError`, PAS `RuntimeError` : `handle_tool_errors` (common/http_client.py)
        # réserve spécifiquement `RuntimeError` aux échecs d'authentification MSAL
        # (common/auth.py::get_token) et l'étiquette "AuthError" en conséquence — une erreur
        # d'IntuneWinAppUtil.exe remonterait alors trompeusement comme un problème d'auth
        # Graph. Repéré en testant cette fonction en direct pendant l'implémentation.
        raise ValueError(f"IntuneWinAppUtil.exe a échoué (code {proc.returncode}) : {detail}")

    produced = list(output_dir.glob("*.intunewin"))
    if not produced:
        raise ValueError("IntuneWinAppUtil.exe n'a produit aucun fichier .intunewin.")

    if source_type == "msi":
        install_command, final_uninstall_command = _msi_commands(install_mode, options or [])
    else:  # "powershell"
        install_command, final_uninstall_command = _powershell_commands(uninstall_command)

    result = {
        "intunewinFileName": produced[0].name,
        "installCommand": install_command,
        "uninstallCommand": final_uninstall_command,
        "detectionScript": _render_detection_script(application_name, version, detection_mode),
        "requirements": {
            "operatingSystem": "Windows 10 1607 ou supérieur",
            "architecture": "x64",
        },
        "suggestedMetadata": {
            "displayName": application_name,
            "version": version,
        },
        # Choix bruts (2026-08-26, demande de Nicolas : "modifier les applications... la
        # version et tous les autres champs qu'il y avait lors de la configuration") — gardés
        # en plus des commandes/script déjà générés, pour que `app_library.py::
        # update_library_app` puisse les régénérer plus tard SANS ré-exécuter
        # IntuneWinAppUtil.exe (le `.intunewin` ne dépend pas de ces réglages, seul le texte
        # généré ci-dessus en dépend) — voir `_msi_commands`/`_render_detection_script`,
        # réutilisées telles quelles par cette fonction de mise à jour.
        #
        # `sourceType` (2026-08-27) : "msi" ou "powershell" — `app_library.py::
        # update_library_app` s'en sert pour savoir si `installCommand` doit être régénérée
        # (MSI, dépend d'installMode/options) ou laissée telle quelle (PowerShell, fixe/saisie
        # manuelle — rien à régénérer côté commandes, seule la détection dépend encore de
        # nom/version/mode, indépendamment du type de source).
        "config": {
            "sourceType": source_type,
            "installMode": install_mode,
            "options": options or [],
            "detectionMode": detection_mode,
        },
        # Dépôt GitHub d'origine (2026-08-27, demande de Nicolas) — `None` si la source a été
        # déposée par upload direct, voir `_write_source_repo`/`_read_source_repo`.
        "repo": _read_source_repo(job_dir),
    }
    atomic_write_text(job_dir / "package_result.json", json.dumps(result, ensure_ascii=False, indent=2))
    return result


def _render_instructions(result: dict) -> str:
    req = result.get("requirements") or {}
    meta = result.get("suggestedMetadata") or {}
    return f"""# Package Intune généré — {meta.get('displayName', '')}

Ce fichier accompagne `{result.get('intunewinFileName', '')}`. Dans l'Intune admin center,
Applications > Windows > Ajouter > "Application Win32" :

## Informations de l'app
- Nom : {meta.get('displayName', '')}
- Version : {meta.get('version', '')}

## Programme
- Commande d'installation : `{result.get('installCommand', '')}`
- Commande de désinstallation : `{result.get('uninstallCommand', '')}`

## Configuration requise
- Système d'exploitation : {req.get('operatingSystem', '')}
- Architecture : {req.get('architecture', '')}

## Règles de détection
Coller le script ci-dessous dans "Utiliser un script personnalisé" :

```powershell
{result.get('detectionScript', '')}
```

---
Généré par l'assistant de packaging Win32 du dashboard Pandore — jamais publié
automatiquement sur Intune, la création de l'app reste un geste manuel de l'admin par design.
"""


def build_deliverable_zip(job_id: str) -> Path:
    """Assemble le `.intunewin` + les instructions en un zip téléchargeable. PAS décorée
    `@handle_tool_errors` (contrairement au reste de ce module) : cette fonction retourne un
    `Path`, pas un dict — elle est appelée directement par la route de téléchargement dans
    `api_server.py`, qui convertit elle-même une exception en `HTTPException` plutôt que
    d'essayer de faire rentrer une erreur dans le corps d'une réponse `FileResponse`."""
    job_dir = _job_dir(job_id)
    result_path = job_dir / "package_result.json"
    if not result_path.is_file():
        raise ValueError("Aucun packaging effectué pour ce job — lance l'étape de packaging avant de télécharger.")
    result = json.loads(result_path.read_text(encoding="utf-8"))

    produced = list((job_dir / "output").glob("*.intunewin"))
    if not produced:
        raise ValueError("Le fichier .intunewin de ce job est introuvable — relance le packaging.")

    zip_path = job_dir / "deliverable.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(produced[0], arcname=produced[0].name)
        zf.writestr("instructions.md", _render_instructions(result))
    return zip_path
