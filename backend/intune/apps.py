"""
Applications Intune (déployées) et discovered apps — extrait de `intune/tools.py`
(1373 lignes) à la revue d'architecture du 2026-08-17, deuxième passe (découpage par
domaine : `intune/devices.py`, `intune/compliance.py`, `intune/compliance_detail.py`,
ce fichier, `intune/users.py`, `intune/secure_score.py`).

Comme le reste des modules issus de ce découpage : fonctions "nues" réutilisées à la fois
par le serveur MCP (`intune/mcp_server.py`) et par l'API REST du dashboard (`api_server.py`).
"""
from concurrent.futures import ThreadPoolExecutor

from common.http_client import escape_odata_string, handle_tool_errors, validate_graph_id
from intune.app_names import resolve_android_app_names
from intune.client import client, client_beta
from intune.devices import list_devices


def _platform_from_odata_type(odata_type: str | None) -> str:
    """Regroupe le zoo de sous-types Graph `mobileApp` (win32LobApp, win32CatalogApp,
    officeSuiteApp, iosStoreApp, iosVppApp, androidManagedStoreApp, macOSDmgApp,
    macOSOfficeSuiteApp, webApp, winGetApp... une bonne vingtaine de valeurs `@odata.type`
    possibles) en 5 familles ergonomiques pour le filtre OS de l'onglet "Application
    déployée" (2026-08-25, demande de Nicolas — "filtrer par OS ... sans avoir à faire un
    tableau différent pour chaque OS"). Classification par SOUS-CHAÎNE plutôt que table
    exhaustive : Microsoft ajoute régulièrement de nouveaux sous-types (winGetApp est récent),
    une table figée les ferait tous atterrir dans "web" (repli) jusqu'à mise à jour manuelle
    de ce fichier. `@odata.type` est toujours renvoyé par Graph sur une collection de types
    dérivés, même sans le demander explicitement dans `$select` — pas besoin de l'y ajouter.
    Ordre des tests important : "macos"/"ios"/"android" d'abord (sous-chaînes non ambiguës),
    "win"/"office"/"msi" ensuite (sinon "macOSOfficeSuiteApp" atterrirait dans Windows via le
    test "office")."""
    t = (odata_type or "").lower()
    if "macos" in t:
        return "macos"
    if "ios" in t or "ipad" in t:
        return "ios"
    if "android" in t:
        return "android"
    if "win" in t or "office" in t or "msi" in t:
        return "windows"
    return "web"


def _win32_app_versions() -> dict[str, str]:
    """Version affichée (`displayVersion`) des applications Win32 (LOB), récupérée à PART de
    la liste principale de `list_apps()` (2026-08-25, reprise après l'incident du même jour —
    voir CLAUDE.md à la racine du repo pour le détail complet).

    Trois tentatives précédentes, toutes invalidées EN CONDITIONS RÉELLES contre le tenant
    de production (session Claude Code, 2026-08-25 — accès direct confirmé, contrairement aux
    sessions précédentes) :
    1. `displayVersion` dans le `$select` de la collection générique `/mobileApps` (v1.0) → 400
       ("Could not find a property named 'displayVersion' on type 'microsoft.graph.mobileApp'").
    2. Cast de type au niveau COLLECTION (`/mobileApps/microsoft.graph.win32LobApp?$select=...`)
       → MÊME 400, message identique mais `on type 'microsoft.graph.win32LobApp'` : `$select`
       est en fait validé contre le type DÉCLARÉ à CHAQUE niveau (base ou casté), jamais contre
       le type réel/concret de la ressource — un cast ne suffit donc jamais à en débloquer les
       propriétés.
    3. GET individuel par app (`/mobileApps/{id}?$select=id,displayVersion`, avec ou sans cast
       après l'`{id}`) → MÊME 400 dans les deux cas, testé directement en Python contre le
       tenant : `$select` reste validé contre le type déclaré même sur une ressource unique.
    4. Idem sur `client_beta` avec `$select` → MÊME 400 ("on type 'microsoft.graph.mobileApp'").

    **Cause racine identifiée** : `displayVersion` n'existe QUE côté beta (absent de la
    réponse v1.0 même sans aucun `$select`, confirmé par comparaison directe des deux) ET la
    validation de `$select` contre le type déclaré est systématique dans cette API — la SEULE
    façon d'obtenir `displayVersion` est un GET **sans aucun `$select`** sur `client_beta`, qui
    renvoie alors l'objet concret complet (toutes les propriétés du sous-type réel, Graph ne
    valide `$select` que quand `$select` est présent). Testé et confirmé : une app Win32 avec
    une vraie version installée renvoie bien `"displayVersion": "7.4.3"` par ce biais.

    Un seul appel Graph paginé sur toute la collection (`get_all_pages`, même coût qu'un
    `list_apps()` classique) plutôt qu'un GET par app — en plus d'être la seule méthode qui
    fonctionne, c'est aussi la moins chère (1 appel au lieu de ~130). Filtré côté client sur
    `@odata.type` contenant "win32" (couvre `win32LobApp` et tout futur sous-type Win32) : les
    autres types n'ont de toute façon jamais de `displayVersion`. Isolé dans son propre
    try/except, comme avant : un souci futur sur cet appel annexe fait simplement disparaître
    le badge de version, jamais tomber la liste principale."""
    try:
        apps = client_beta.get_all_pages("/deviceAppManagement/mobileApps")
        return {
            a["id"]: a["displayVersion"]
            for a in apps
            if a.get("id") and a.get("displayVersion") and "win32" in (a.get("@odata.type") or "").lower()
        }
    except Exception:
        return {}


@handle_tool_errors
def list_apps(filter: str | None = None) -> list[dict]:
    """Applications déployées via Intune.

    `lastModifiedDateTime` (2026-08-25, demande de Nicolas — "la date de dernière modif"
    plutôt que la date d'ajout initiale) et `largeIcon` (icône Intune de l'app, PNG en base64
    dans un objet `{contentType, value}` — absent par défaut sur `mobileApps`, il faut le
    `$select` explicitement, absent aussi tout court sur pas mal d'apps, voir AppIcon dans
    DeployedAppsTab.jsx pour le repli) ajoutés au `$select` pour la même demande.

    `displayVersion` (2026-08-25, même demande, "tu peux me rajouter la version ?") : quatre
    tentatives successives, voir `_win32_app_versions()` ci-dessus pour l'historique complet
    et la cause racine (validation `$select` + champ absent en v1.0). Fusionné ici dans la
    boucle ci-dessous. Ne s'applique de toute façon qu'aux apps Win32 (LOB) ; les autres types
    (Store, ligne métier iOS/Android, etc.) n'auront jamais de version par ce biais.

    `platform` (même demande, "filtrer par OS") : dérivé de `@odata.type` (toujours renvoyé
    par Graph sur cette collection de types dérivés, sans avoir besoin de le `$select`) via
    `_platform_from_odata_type` — ce n'est PAS un champ Graph natif, ajouté après coup à
    chaque élément pour que le frontend n'ait pas à connaître le zoo de sous-types."""
    # `displayVersion` retiré du $select principal (2026-08-25) : c'est un champ du sous-type
    # `win32LobApp`, ABSENT du type de base `microsoft.graph.mobileApp` que Graph valide
    # quand on interroge la collection générique /deviceAppManagement/mobileApps — Graph
    # renvoie une 400 sur TOUTE la requête ("Could not find a property named 'displayVersion'
    # on type 'microsoft.graph.mobileApp'"), pas juste un champ vide comme espéré. Contrairement
    # à `largeIcon`/`lastModifiedDateTime`, qui SONT sur le type de base et fonctionnent.
    # Récupéré à la place via `_win32_app_versions()` (requête séparée, isolée) ci-dessous.
    params: dict = {
        "$select": "id,displayName,publisher,createdDateTime,lastModifiedDateTime,largeIcon"
    }
    if filter:
        params["$filter"] = filter
    apps = client.get_all_pages("/deviceAppManagement/mobileApps", params=params)
    versions = _win32_app_versions()
    for app in apps:
        app["platform"] = _platform_from_odata_type(app.get("@odata.type"))
        version = versions.get(app.get("id"))
        if version:
            app["displayVersion"] = version
    return apps


@handle_tool_errors
def get_apps_install_summary() -> dict:
    """
    Agrégat "installés / échecs / en attente" tous appareils confondus, sur l'ensemble des
    applications déployées via Intune — alimente le bandeau KPI de l'onglet "Application
    déployée" ("Taux d'installation moyen", "Échecs d'installation", 2026-08-25, demande de
    Nicolas) ET, depuis le redesign en cartes du même jour ("un design qui utilise plus
    l'espace"), la barre de répartition affichée sur CHAQUE carte via `byApp` — sans appel
    Graph supplémentaire : c'est la même passe par app qui alimentait déjà l'agrégat global,
    on garde simplement le détail par app au lieu de ne conserver que la somme.

    Volontairement PAS une somme de get_app_install_status() sur chaque app : cette
    fonction-là énumère TOUS les devices par app — coûteux, c'est pour ça qu'elle reste
    chargée à la demande, au clic sur une ligne (voir useAppInstallStatus). Ici on utilise un
    agrégat un-appel-par-app, pas par device, un ordre de grandeur moins cher : c'est ce qui
    permet de le charger automatiquement à l'ouverture de l'onglet (useAppInstallSummary)
    plutôt qu'à la demande comme get_app_install_status.

    ⚠️ Endpoint changé le 2026-08-25 (même jour, découvert en testant contre le tenant
    de production en conditions réelles pendant une passe de redesign de l'onglet) :
    `mobileAppInstallSummary` (`/deviceAppManagement/mobileApps/{id}/installSummary`, beta) —
    utilisé jusqu'ici — s'est avéré renvoyer une 400 ("Resource not found for the segment
    'installSummary'") pour LES 172 APPS DU TENANT SANS EXCEPTION, silencieusement absorbée
    par `_fetch_one` (échec individuel ignoré, par design) : `byApp` était vide, `appsWithData`
    à 0, `installRate` toujours `None`, bandeau KPI et barre de répartition de chaque carte
    invisibles depuis le début — jamais remonté par Nicolas, découvert seulement en
    interrogeant directement l'API réelle. Comme `managedDeviceMobileAppInstallStatuses` (voir
    `get_app_install_status` ci-dessous), c'est un endpoint déprécié par Microsoft depuis mai
    2023 sans mise à jour de la documentation publique. Remplacé par
    `POST /deviceManagement/reports/getAppStatusOverviewReport` (endpoint de reporting, comme
    `retrieveDeviceAppInstallationStatusReport`), avec `filter: "(ApplicationId eq '{id}')"` —
    confirmé fonctionnel par un appel direct contre le tenant de production (réponse tabulaire
    Schema/Values habituelle, une seule ligne pour l'app filtrée).

    Un appel en échec pour une app précise (type d'app qui ne supporte pas cet agrégat, ex.
    certains web links/apps store) est ignoré individuellement plutôt que de faire échouer tout
    le calcul — voir `_fetch_one`. Cette app-là est simplement absente de `byApp` ; la carte
    correspondante n'affiche alors pas de barre de répartition (voir InstallRateBar côté
    frontend), plutôt qu'une barre à zéro qui laisserait croire à "aucun device assigné".
    """
    app_ids = [
        a["id"]
        for a in client.get_all_pages("/deviceAppManagement/mobileApps", params={"$select": "id"})
        if a.get("id")
    ]

    def _fetch_one(app_id: str) -> dict | None:
        try:
            data = client_beta.post(
                "/deviceManagement/reports/getAppStatusOverviewReport",
                {"filter": f"(ApplicationId eq '{app_id}')"},
            )
            values = data.get("Values") or []
            if not values:
                return None
            schema = [c.get("Column") for c in data.get("Schema", [])]
            return dict(zip(schema, values[0]))
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        summaries = list(pool.map(_fetch_one, app_ids))

    installed = failed = pending = not_installed = not_applicable = 0
    apps_with_data = 0
    by_app: dict[str, dict] = {}
    for app_id, s in zip(app_ids, summaries):
        if not s:
            continue
        apps_with_data += 1
        app_installed = s.get("InstalledDeviceCount") or 0
        app_failed = s.get("FailedDeviceCount") or 0
        app_pending = s.get("PendingInstallDeviceCount") or 0
        app_not_installed = s.get("NotInstalledDeviceCount") or 0
        app_not_applicable = s.get("NotApplicableDeviceCount") or 0

        installed += app_installed
        failed += app_failed
        pending += app_pending
        not_installed += app_not_installed
        not_applicable += app_not_applicable

        by_app[app_id] = {
            "installed": app_installed,
            "failed": app_failed,
            "pending": app_pending,
            "notInstalled": app_not_installed,
            "notApplicable": app_not_applicable,
        }

    # Taux d'installation = installés / (installés + échecs + en attente + non installés) —
    # "non applicable" exclu du dénominateur (device hors périmètre de l'assignation, ex.
    # mauvaise plateforme) : sinon le taux serait mécaniquement gonflé par des devices qui
    # n'étaient de toute façon jamais ciblés par cette app.
    denominator = installed + failed + pending + not_installed
    install_rate = round((installed / denominator) * 100, 1) if denominator else None

    return {
        "appsCount": len(app_ids),
        "appsWithData": apps_with_data,
        "installedTotal": installed,
        "failedTotal": failed,
        "pendingTotal": pending,
        "notInstalledTotal": not_installed,
        "notApplicableTotal": not_applicable,
        "installRate": install_rate,
        "byApp": by_app,
    }


@handle_tool_errors
def get_discovered_apps(search: str | None = None, min_devices: int | None = None) -> dict:
    """Applications détectées (discovered apps) sur le parc, déployées ou installées manuellement."""
    params: dict = {
        "$select": "id,displayName,version,deviceCount,sizeInByte,platform",
        "$orderby": "deviceCount desc",
    }
    if search:
        params["$filter"] = f"contains(displayName,'{escape_odata_string(search)}')"
    apps = client_beta.get_all_pages("/deviceManagement/detectedApps", params=params)
    if min_devices:
        apps = [a for a in apps if (a.get("deviceCount") or 0) >= min_devices]

    return {
        "total": len(apps),
        "apps": [
            {
                "displayName": a.get("displayName"),
                "version": a.get("version") or "Inconnue",
                "deviceCount": a.get("deviceCount") or 0,
                "platform": a.get("platform") or "unknown",
                "sizeInByte": a.get("sizeInByte") or 0,
                "id": a.get("id"),
            }
            for a in apps
        ],
    }


@handle_tool_errors
def get_discovered_app_devices(app_id: str) -> dict:
    """Liste nominative des devices sur lesquels une discovered app spécifique est détectée.

    `department`/`userPrincipalName`/`complianceState` (2026-09-02, demande de Nicolas —
    "pour les app détectées seulement... les filtres comme pour app déployés") : même
    enrichissement "département" que `get_app_install_status` (voir `_department_by_upn`
    ci-dessous), pour que le panneau "voir les devices" d'une version détectée
    (DeployedAppsTab.jsx) puisse filtrer par département/état de conformité exactement comme le
    panneau "Application déployée" filtre par département/état d'installation.

    ⚠️ Repéré en testant (pas anticipé) : `deviceManagement/detectedApps/{id}/managedDevices`
    (la collection interrogée ci-dessous) ne renvoie JAMAIS `userPrincipalName`/
    `complianceState` malgré leur présence dans `$select` — vérifié sur 111 devices réels
    (Google Chrome), 0/111 avec ces deux champs renseignés. Contrairement à la collection
    `deviceManagement/managedDevices` "normale" (déjà interrogée ailleurs par `list_devices`,
    CES champs y sont bien présents) — encore une limitation silencieuse d'une collection
    Graph "par navigation", du même genre que documenté ailleurs dans ce module. Corrigé par
    un repli : `list_devices()` (déjà bon marché, table de correspondance par NOM déjà
    utilisée par `compliance_detail.py`) comble `userPrincipalName`/`complianceState` quand la
    collection detectedApps les a laissés vides, AVANT de résoudre le département — sans ce
    repli, "Département"/"État" affichaient "Non renseignée"/"Inconnu" pour 100% des devices,
    mécaniquement corrects mais inutiles en pratique.
    """
    validate_graph_id(app_id, "app_id")
    select = "id,deviceName,userPrincipalName,userDisplayName,operatingSystem,osVersion,lastSyncDateTime,managementState,complianceState,manufacturer,model"
    devices = client_beta.get_all_pages(f"/deviceManagement/detectedApps/{app_id}/managedDevices", params={"$select": select})

    all_devices = list_devices()
    by_name = (
        {(d.get("deviceName") or "").strip().lower(): d for d in all_devices if d.get("deviceName")}
        if isinstance(all_devices, list)
        else {}
    )
    departments = _department_by_upn()

    def _enrich(d: dict) -> dict:
        fallback = by_name.get((d.get("deviceName") or "").strip().lower(), {})
        upn = d.get("userPrincipalName") or fallback.get("userPrincipalName")
        # `complianceState` de la collection detectedApps n'est PAS vide comme userPrincipalName
        # (repéré en testant) : elle renvoie systématiquement la chaîne littérale "unknown",
        # une valeur réelle mais inexploitable — `or` seul ne suffit pas à déclencher le repli
        # (une chaîne non vide est "truthy"), il faut exclure "unknown" explicitement.
        raw_compliance = d.get("complianceState")
        compliance = raw_compliance if raw_compliance and raw_compliance != "unknown" else fallback.get("complianceState")
        return {
            "deviceName": d.get("deviceName"),
            "userPrincipalName": upn,
            "userDisplayName": d.get("userDisplayName") or fallback.get("userDisplayName"),
            "operatingSystem": d.get("operatingSystem"),
            "osVersion": d.get("osVersion"),
            "lastSyncDateTime": d.get("lastSyncDateTime"),
            "complianceState": compliance,
            "managementState": d.get("managementState"),
            "manufacturer": d.get("manufacturer"),
            "model": d.get("model"),
            "deviceId": d.get("id"),
            "department": departments.get((upn or "").lower()),
        }

    return {
        "total": len(devices),
        "devices": [_enrich(d) for d in devices],
    }


_MIN_MATCH_LEN = 5  # évite qu'un nom court/générique ("VPN", "Apps"...) matche n'importe quoi

# Apps déployées qui ne sont PAS des installations de logiciel — des CONFIGURATIONS poussées
# via Intune sur un logiciel déjà installé par ailleurs (2026-09-02, demande de Nicolas :
# "dans le cadre spécifique des Forticlient Ajout Conf je veux bien que tu mettes pas les
# versions ce sont des configurations qu'on pousse via intune"). Les rapprocher d'un logiciel
# détecté (et de son historique de versions, ex. "[ORG] FortiClient Ajout Conf Fortigate SITE
# VPN-DC" ↔ FortiClient/18 versions) n'a aucun sens : cette app ne touche jamais à la version
# de FortiClient elle-même. Liste de marqueurs plutôt qu'un seul cas en dur — extensible si
# Nicolas signale un autre motif de nommage du même genre.
_CONFIG_PUSH_MARKERS = ("ajout conf",)


def _is_config_push(deployed_name: str) -> bool:
    lower = (deployed_name or "").lower()
    return any(marker in lower for marker in _CONFIG_PUSH_MARKERS)


# Discovered apps dont la corrélation de version n'a jamais de sens, quelle que soit l'app
# déployée qui matche (2026-09-02, demande de Nicolas — "pour forticlient... ne mets pas de
# corrélation de version juste pour lui") : comparaison en minuscules, extensible comme
# `_CONFIG_PUSH_MARKERS` ci-dessus.
_EXCLUDED_MATCH_NAMES = {"forticlient"}


def _contains_word(haystack: str, needle: str) -> bool:
    """Sous-chaîne `needle` présente dans `haystack` sur une frontière de MOT (pas au milieu
    d'un autre mot) — corrige des faux positifs réels rencontrés en testant contre le tenant
    de production : un simple `in` faisait matcher "open" (discovered app générique) avec
    "OpenSSL" (à l'intérieur du mot, sans frontière) ou "Green" avec "Greenshot". Ne résout pas
    tout (un nom court mais réellement délimité, ex. "Black" dans "Font Gilroy-Black", reste un
    faux positif plausible) — le rapprochement reste volontairement approximatif, voir
    `get_apps_catalog`."""
    idx = haystack.find(needle)
    while idx != -1:
        before_ok = idx == 0 or not haystack[idx - 1].isalnum()
        after_idx = idx + len(needle)
        after_ok = after_idx == len(haystack) or not haystack[after_idx].isalnum()
        if before_ok and after_ok:
            return True
        idx = haystack.find(needle, idx + 1)
    return False


def _group_discovered_apps(rows: list[dict]) -> dict[str, dict]:
    """Regroupe les lignes brutes de `get_discovered_apps` (une par couple nom+version détecté
    sur le parc) en UNE entrée par nom d'app — voir `get_apps_catalog` pour le contexte
    (2026-09-02, demande de Nicolas : "j'aimerai bien qu'on ait les discover app + les app
    déployés je veux pas 600 doublons ... je veux cependant voir toutes les versions").
    Confirmé en direct contre le tenant de production AVANT d'écrire cette fonction : 18894
    lignes brutes pour seulement 7479 noms distincts (Google Chrome à lui seul : 98 lignes
    "version" en circulation) — c'est la source exacte des "doublons" signalés par Nicolas.

    ⚠️ Un même (nom, version) peut ENCORE apparaître sur plusieurs lignes brutes (repéré en
    testant après un premier jet de cette fonction : les 98 lignes de Google Chrome ne
    couvrent en fait que 51 versions distinctes — Graph renvoie apparemment des entrées
    `detectedApps` séparées pour un même couple nom+version, sans qu'on puisse distinguer la
    cause exacte côté API) — deuxième niveau de déduplication ci-dessous, sur `(nom, version)`
    cette fois, `deviceCount` sommé plutôt que de laisser deux lignes "version" identiques dans
    le détail affiché à Nicolas.
    """
    groups: dict[str, dict] = {}
    for row in rows:
        name = row.get("displayName") or "Application inconnue"
        group = groups.get(name)
        if group is None:
            group = {"displayName": name, "platform": row.get("platform") or "unknown", "totalDeviceCount": 0, "versions": {}}
            groups[name] = group
        group["totalDeviceCount"] += row.get("deviceCount") or 0
        version = row.get("version") or "Inconnue"
        v_entry = group["versions"].setdefault(version, {"deviceCount": 0, "ids": []})
        v_entry["deviceCount"] += row.get("deviceCount") or 0
        # Les ids Graph bruts derrière cette version (2026-09-02, demande de Nicolas : "je ne
        # vois pas qui a l'application seulement la version") — conservés pour permettre, côté
        # frontend, un clic "voir les devices" par version via l'endpoint DÉJÀ existant
        # `get_discovered_app_devices(app_id)`. Une version peut porter plusieurs ids (voir le
        # 2e niveau de déduplication ci-dessus) : le frontend interroge chacun et fusionne.
        if row.get("id"):
            v_entry["ids"].append(row["id"])
    for group in groups.values():
        version_list = [
            {"version": v, "deviceCount": e["deviceCount"], "ids": e["ids"]} for v, e in group["versions"].items()
        ]
        version_list.sort(key=lambda v: v["deviceCount"], reverse=True)
        group["versions"] = version_list
        group["versionCount"] = len(version_list)
    return groups


@handle_tool_errors
def get_apps_catalog() -> list[dict]:
    """Fusion "Application déployée" (list_apps, ce qui a été PUSHÉ via Intune) + "discovered
    apps" (get_discovered_apps, ce qui a été DÉTECTÉ sur le disque du parc) — 2026-09-02,
    demande de Nicolas : "j'aimerai bien qu'on ait les discover app + les app déployés je veux
    pas 600 doublons ... je veux cependant voir toutes les versions".

    Rapprochement forcément APPROXIMATIF (même philosophie que le rapprochement ANSSI/CERT-FR
    de defender/anssi.py — jamais présenté comme une certitude) : les apps déployées de ce
    tenant portent des noms internes/préfixés ("[ORG] Désinstallation FortiClient", "[ORG]
    Disable IPV6"...), rarement le nom du logiciel réel tel que détecté sur le disque
    ("FortiClient") — vérifié en direct AVANT de coder. Une discovered app est considérée
    "déployée" si son nom (>= 4 caractères, pour éviter qu'un nom de 2-3 lettres ne matche
    n'importe quoi) apparaît comme sous-chaîne du nom de l'app déployée ; en cas de plusieurs
    candidats, le plus long l'emporte (le match le plus spécifique).

    Renvoie une liste À PLAT, une entrée par app visible dans "Application déployée" :
    - `source: "deployed"` — app Intune sans correspondance détectée, comportement inchangé
      (mêmes champs que list_apps, `discovered: null`).
    - `source: "both"` — app Intune ET correspondance détectée : mêmes champs que "deployed"
      PLUS `discovered` (totalDeviceCount/versionCount/versions — toutes les versions jamais
      perdues, juste regroupées par nom plutôt qu'une ligne par version).
    - `source: "discovered"` — logiciel détecté sur le parc SANS app Intune correspondante :
      `id` synthétique (`"discovered:{nom}"`, jamais un vrai id Intune — le frontend ne doit
      JAMAIS l'utiliser pour un appel `install-status`/lien Intune), `publisher`/
      `lastModifiedDateTime`/`largeIcon` absents (non disponibles côté detectedApps),
      `discovered` renseigné.

    Isolé pour ne jamais dégrader "Application déployée" en cas de souci sur le volet
    "discovered" (18894 lignes brutes, un vrai scan complet du parc, plus fragile qu'un simple
    `list_apps`) : si `get_discovered_apps` échoue, la liste déployée est renvoyée SEULE,
    inchangée (`source: "deployed"` partout), plutôt que de faire planter toute la page pour un
    enrichissement.

    2026-09-02, retour de Nicolas — deux ajustements après le premier jet :
    - Un logiciel détecté matché à une app déployée obtient DÉSORMAIS AUSSI sa propre entrée
      `"discovered"` autonome (avant, il disparaissait du filtre "Détectées seulement" une fois
      absorbé dans l'app déployée correspondante — "je veux voir tous les détectés même ceux
      qui sont en corrélation ... genre 7-zip").
    - "FortiClient" (`_EXCLUDED_MATCH_NAMES`) n'est plus jamais utilisé comme correspondance
      pour AUCUNE app déployée, quel que soit son nom — "pour FortiClient... ne mets pas de
      corrélation de version juste pour lui". "FortiClient VPN" (nom distinct) n'est PAS
      concerné, seulement la correspondance exacte "FortiClient".
    """
    deployed = list_apps()
    if len(deployed) == 1 and isinstance(deployed[0], dict) and deployed[0].get("error"):
        raise ValueError(deployed[0].get("message") or "Erreur lors du chargement des applications déployées")

    discovered_payload = get_discovered_apps()
    discovered_groups: dict[str, dict] = {}
    if isinstance(discovered_payload, dict) and not discovered_payload.get("error"):
        discovered_groups = _group_discovered_apps(discovered_payload.get("apps") or [])

    discovered_lower = {name.lower(): name for name in discovered_groups if len(name) >= _MIN_MATCH_LEN}

    def _find_match(deployed_name: str) -> str | None:
        haystack = (deployed_name or "").lower()
        best_lower = None
        for lower_name in discovered_lower:
            if (
                (best_lower is None or len(lower_name) > len(best_lower))
                and lower_name not in _EXCLUDED_MATCH_NAMES
                and _contains_word(haystack, lower_name)
            ):
                best_lower = lower_name
        return discovered_lower.get(best_lower) if best_lower else None

    result: list[dict] = []
    for app in deployed:
        name = app.get("displayName")
        match_name = None if _is_config_push(name) else _find_match(name)
        entry = dict(app)
        if match_name:
            group = discovered_groups[match_name]
            entry["source"] = "both"
            entry["discovered"] = {
                "totalDeviceCount": group["totalDeviceCount"],
                "versionCount": group["versionCount"],
                "versions": group["versions"],
                "matchedName": match_name,
            }
        else:
            entry["source"] = "deployed"
            entry["discovered"] = None
        result.append(entry)

    # Chaque logiciel détecté a AUSSI sa propre entrée "discovered" — MÊME s'il correspond à
    # une app déployée ci-dessus (2026-09-02, demande de Nicolas : "voir tous les détectés
    # même ceux qui sont en corrélation avec une application, genre 7-zip ou autre") : avant ce
    # changement, un logiciel détecté matché à une app déployée disparaissait du filtre
    # "Détectées seulement", devenant introuvable en le cherchant par son nom réel plutôt que
    # son nom déployé interne ("[CoreUpdate] 7-Zip"). Les deux entrées (déployée enrichie +
    # détectée autonome) coexistent volontairement — ce ne sont plus des doublons au sens
    # d'avant (même nom répété par version), mais deux VUES légitimement différentes du même
    # logiciel (le paquet poussé via Intune vs. l'inventaire brut détecté sur le disque).
    for name, group in discovered_groups.items():
        result.append(
            {
                "id": f"discovered:{name}",
                "displayName": name,
                "publisher": None,
                "platform": group["platform"],
                "lastModifiedDateTime": None,
                "displayVersion": None,
                "largeIcon": None,
                "source": "discovered",
                "discovered": {
                    "totalDeviceCount": group["totalDeviceCount"],
                    "versionCount": group["versionCount"],
                    "versions": group["versions"],
                    "matchedName": None,
                },
            }
        )

    return result


@handle_tool_errors
def get_device_detected_apps(device_id: str) -> list[dict]:
    """Applications détectées (discovered apps) sur UN appareil précis — Vue "Appareil" 360°
    (2026-09-02, demande de Nicolas : "on peut rajouter pour tous les devices un onglet avec
    les applications ?"). Utilise la propriété de navigation Graph INVERSE de
    `get_discovered_app_devices` ci-dessus (`deviceManagement/detectedApps/{id}/managedDevices`
    liste les devices d'UNE app ; ici, `deviceManagement/managedDevices/{id}/detectedApps` liste
    les apps d'UN device) — même ressource Graph, sens inverse, jamais empruntée avant ce jour.
    Testé en direct contre le tenant de production (DEMO-WKS-106) : 87 applications détectées
    (7-Zip, Adobe Acrobat, 1Password...).

    Distinct de "Application déployée" (apps PUSHÉES via Intune, avec statut d'installation
    réussi/échoué, voir get_app_install_status) : ceci liste tout logiciel DÉTECTÉ sur le
    disque, déployé via Intune ou installé manuellement — pas de statut d'installation ici.
    L'endpoint de reporting `retrieveDeviceAppInstallationStatusReport` (get_app_install_status)
    ne peut PAS être filtré par device (vérifié en direct : 400 Bad Request avec un filtre
    `DeviceId`, ce report n'accepte qu'un filtre `ApplicationId`) — pas de vue "statut
    d'installation par app" symétrique disponible pour un device pris seul.

    Sur Android, `displayName` est quasi toujours l'identifiant de PAQUET brut (ex.
    "com.android.chrome") plutôt qu'un nom convivial — corrigé quand possible via
    `intune.app_names.resolve_android_app_names` (résolution Google Play Store, voir ce
    module pour le détail et ses limites) — isolée dans un try/except : jamais de raison de
    faire disparaître la liste d'apps pour un problème de résolution purement cosmétique.
    """
    validate_graph_id(device_id, "device_id")
    select = "id,displayName,version,platform,sizeInByte"
    apps = client_beta.get_all_pages(f"/deviceManagement/managedDevices/{device_id}/detectedApps", params={"$select": select})
    apps.sort(key=lambda a: (a.get("displayName") or "").lower())
    result = [
        {
            "id": a.get("id"),
            "displayName": a.get("displayName") or "Application inconnue",
            "version": a.get("version") or "Inconnue",
            "platform": a.get("platform") or "unknown",
            "sizeInByte": a.get("sizeInByte") or 0,
        }
        for a in apps
    ]
    try:
        result = resolve_android_app_names(result)
    except Exception:
        pass
    return result


def _normalize_version(v: str | None) -> list[int]:
    parts = (v or "").replace("-", ".").split(".")
    out = []
    for p in parts:
        try:
            out.append(int(p))
        except ValueError:
            out.append(0)
    return out


def _version_is_below(version: str | None, target: list[int]) -> bool:
    if not version:
        return True  # version inconnue = incluse (comportement du MCP Node d'origine)
    v = _normalize_version(version)
    for i in range(max(len(v), len(target))):
        vi = v[i] if i < len(v) else 0
        ti = target[i] if i < len(target) else 0
        if vi < ti:
            return True
        if vi > ti:
            return False
    return False  # égal = pas inférieur


_INSTALL_STATUS_REPORT_SELECT = [
    "DeviceName",
    "UserPrincipalName",
    "AppVersion",
    "InstallState",
    "Platform",
    "LastModifiedDateTime",
    "DeviceId",
]
_INSTALL_STATUS_REPORT_PAGE_SIZE = 500
_INSTALL_STATUS_REPORT_MAX_PAGES = 40  # garde-fou (20 000 lignes) contre une pagination qui bouclerait


def _fetch_install_status_rows(app_id: str) -> list[dict]:
    """Lignes de statut d'installation par device pour une app, via l'endpoint de reporting
    `retrieveDeviceAppInstallationStatusReport` (2026-08-25, REMPLACE
    `/mobileApps/{id}/managedDeviceMobileAppInstallStatuses`, qui renvoyait une 400 Graph
    ("Resource not found for the segment") en conditions réelles sur le tenant de production —
    endpoint déprécié côté Microsoft depuis mai 2023 sans mise à jour de la documentation
    publique, confirmé par plusieurs rapports communautaires au même symptôme exact.

    Contrairement à l'ancien endpoint (pagination Graph standard via `@odata.nextLink`,
    `get_all_pages`), celui-ci est un endpoint de REPORTING : POST avec un corps
    `{select, skip, top, filter, orderBy}`, réponse tabulaire `{Schema: [{Column: ...}, ...],
    Values: [[...], ...], TotalRowCount}` plutôt qu'une liste d'objets — nécessite de
    reconstruire les objets à la main (`schema` → index de colonne) et de paginer soi-même via
    `skip`/`top` (pas de `@odata.nextLink` ici).
    """
    columns = _INSTALL_STATUS_REPORT_SELECT
    rows: list[dict] = []
    skip = 0
    for _ in range(_INSTALL_STATUS_REPORT_MAX_PAGES):
        body = {
            "select": columns,
            "skip": skip,
            "top": _INSTALL_STATUS_REPORT_PAGE_SIZE,
            "filter": f"(ApplicationId eq '{app_id}')",
            "orderBy": [],
        }
        data = client.post("/deviceManagement/reports/microsoft.graph.retrieveDeviceAppInstallationStatusReport", body)
        schema = [c.get("Column") for c in data.get("Schema", [])]
        values = data.get("Values", [])
        rows.extend(dict(zip(schema, row)) for row in values)
        if len(values) < _INSTALL_STATUS_REPORT_PAGE_SIZE:
            break
        skip += _INSTALL_STATUS_REPORT_PAGE_SIZE
    return rows


# `InstallState` de l'endpoint de reporting `retrieveDeviceAppInstallationStatusReport` :
# hypothèse initiale PascalCase (`"NotInstalled"`...) invalidée en conditions réelles
# (`TypeError: 'int' object is not subscriptable`) — Graph renvoie en fait un ENTIER, pas une
# chaîne, et ce mapping n'est documenté nulle part par Microsoft. Déduit par CORRÉLATION
# empirique (2026-08-25, session Claude Code, accès direct au tenant de production) : comparé
# les codes bruts vus sur `[CoreUpdate] Google Chrome` (24 devices, correspondance EXACTE
# 16×"1"=16 installés / 8×"3"=8 non installés côté `get_apps_install_summary`, qui utilise un
# endpoint séparé et fiable — `getAppStatusOverviewReport`) et sur une app à ~530 devices
# (correspondance EXACTE pour `failed`=3="2"×3 ; proche mais pas exacte pour `pending`=5 vs
# "5"×6 et `notApplicable`=25 vs "-1"×26 — écart probablement dû à des lignes dupliquées
# device+utilisateur sur les assignations multi-utilisateurs, PAS un mapping incorrect vu la
# cohérence du reste). `uninstallFailed`/`unknown` jamais observés dans l'échantillon testé —
# laissés au code brut (voir _normalize_install_state) plutôt que devinés.
_INSTALL_STATE_CODES = {
    "1": "installed",
    "2": "failed",
    "3": "notInstalled",
    "5": "pendingInstall",
    "-1": "notApplicable",
}


def _normalize_install_state(state) -> str | None:
    """Convertit le code numérique brut renvoyé par l'endpoint de reporting (voir
    `_INSTALL_STATE_CODES` ci-dessus) vers le même vocabulaire camelCase que
    `INSTALL_STATE_LABEL_FR` côté frontend (DeployedAppsTab.jsx), pour un affichage traduit en
    français plutôt qu'un code brut. Un code absent de la table (état jamais observé sur le
    tenant testé) est renvoyé tel quel — le frontend affiche alors ce code brut plutôt que de
    planter, dégradation propre en attendant de compléter le mapping."""
    if state is None:
        return None
    code = str(state)
    return _INSTALL_STATE_CODES.get(code, code)


def _department_by_upn() -> dict[str, str]:
    """`{userPrincipalName en minuscules: department}` pour tout le tenant — utilisé par
    `get_app_install_status()` pour afficher/filtrer par département (2026-08-25, demande de
    Nicolas : filtrer les appareils selon le département Entra ID de leur utilisateur). Sur ce
    tenant, l'attribut Entra ID `department` de chaque utilisateur encode directement l'entité
    à laquelle il appartient — pas une correspondance à construire, on relaie juste ce champ.

    Un seul appel Graph paginé sur `/users` (même fonction que `intune/users.py::list_users`,
    mais appelée directement ici plutôt que réutilisée : `list_users` est décorée
    `@handle_tool_errors`, qui encode une erreur en `[{"error": True, ...}]` au lieu de lever —
    un tel dict serait silencieusement absorbé par la compréhension ci-dessous faute de
    `userPrincipalName`, ce qui masquerait l'échec au lieu de le rendre visible via le
    try/except explicite ici, cohérent avec `_win32_app_versions` ci-dessus). Isolé en
    try/except comme le reste des enrichissements annexes de ce fichier : un souci sur cet
    appel fait simplement disparaître la colonne/le filtre "Département", jamais planter le détail
    par device."""
    try:
        users = client.get_all_pages("/users", params={"$select": "userPrincipalName,department"})
        return {
            u["userPrincipalName"].lower(): u["department"]
            for u in users
            if u.get("userPrincipalName") and u.get("department")
        }
    except Exception:
        return {}


@handle_tool_errors
def get_app_assignments(app_id: str) -> dict:
    """Groupes d'assignation Intune d'une app déployée (2026-09-02, demande de Nicolas — panneau
    détail "agrandi" de "Application déployée" : "voir toutes les informations genre groupe
    require available et exclude").

    Vérifié en direct contre le tenant de production AVANT d'écrire cette fonction :
    `mobileApps/{id}/assignments` renvoie `intent` (required/available/
    availableWithoutEnrollment/uninstall) et `target.@odata.type` (groupAssignmentTarget/
    exclusionGroupAssignmentTarget/allDevicesAssignmentTarget/allLicensedUsersAssignmentTarget),
    `target.groupId` SANS le nom du groupe — résolu séparément via `/groups?$filter=id in
    (...)` (un seul appel supplémentaire pour tous les groupes d'une app, confirmé fonctionnel
    en direct).

    Regroupé en 3 catégories (demande explicite de Nicolas, pas les 4 intents Graph bruts) :
    - Un target `exclusionGroupAssignmentTarget` → "excluded", quel que soit son `intent` (le
      champ `intent` est structurellement présent sur ces lignes mais sans signification pour
      une exclusion — vérifié : Graph renvoie bien un `intent` sur une ligne d'exclusion, mais
      seul `target.@odata.type` distingue réellement une exclusion).
    - Sinon `intent == "required"` → "required".
    - Sinon (available / availableWithoutEnrollment / uninstall) → "available" — simplification
      assumée après vérification : `uninstall` n'a jamais été observé sur ce tenant en testant
      un échantillon d'apps, à séparer plus tard si Nicolas en a besoin.
    """
    validate_graph_id(app_id, "app_id")
    assignments = client.get(f"/deviceAppManagement/mobileApps/{app_id}/assignments").get("value", [])

    group_ids = {a["target"]["groupId"] for a in assignments if a.get("target", {}).get("groupId")}
    names: dict[str, str] = {}
    if group_ids:
        id_list = ",".join(f"'{escape_odata_string(gid)}'" for gid in group_ids)
        groups = client.get("/groups", params={"$filter": f"id in ({id_list})", "$select": "id,displayName"})
        names = {g["id"]: g["displayName"] for g in groups.get("value", [])}

    required: list[str] = []
    available: list[str] = []
    excluded: list[str] = []
    for a in assignments:
        target = a.get("target", {})
        odata_type = target.get("@odata.type", "")
        if odata_type.endswith("allDevicesAssignmentTarget"):
            label = "Tous les appareils"
        elif odata_type.endswith("allLicensedUsersAssignmentTarget"):
            label = "Tous les utilisateurs"
        else:
            gid = target.get("groupId")
            label = names.get(gid, gid or "Groupe inconnu")

        if odata_type.endswith("exclusionGroupAssignmentTarget"):
            excluded.append(label)
        elif a.get("intent") == "required":
            required.append(label)
        else:
            available.append(label)

    return {
        "required": sorted(required),
        "available": sorted(available),
        "excluded": sorted(excluded),
    }


@handle_tool_errors
def get_app_install_status(app_id: str, os_filter: str | None = None, version_below: str | None = None) -> dict:
    """
    État d'installation d'une app Intune sur tous les devices, avec version installée
    par device. Utile pour trouver les devices avec une version obsolète (ex: FortiClient < 7.4.3).

    `department` (2026-08-25, demande de Nicolas — filtre par "département") : ajouté à chaque
    device via `_department_by_upn()`, résolu par `userPrincipalName`. `None` si l'utilisateur
    n'a pas de UPN sur cette ligne (device sans utilisateur assigné) ou pas de `department`
    renseigné dans Entra ID — le frontend l'affiche alors comme "Non renseignée" plutôt que de
    l'exclure du filtre "Département".
    """
    validate_graph_id(app_id, "app_id")
    statuses = _fetch_install_status_rows(app_id)
    departments = _department_by_upn()

    results = statuses
    if os_filter:
        needle = os_filter.lower()
        results = [s for s in results if needle in (s.get("Platform") or "").lower()]

    if version_below:
        target = _normalize_version(version_below)
        results = [s for s in results if _version_is_below(s.get("AppVersion"), target)]

    return {
        "total": len(results),
        "devices": [
            {
                "deviceName": s.get("DeviceName"),
                "userPrincipalName": s.get("UserPrincipalName"),
                "department": departments.get((s.get("UserPrincipalName") or "").lower()),
                "appVersion": s.get("AppVersion") or "Inconnue",
                "installState": _normalize_install_state(s.get("InstallState")),
                "osDescription": s.get("Platform"),
                "lastSyncDateTime": s.get("LastModifiedDateTime"),
                "deviceId": s.get("DeviceId"),
            }
            for s in results
        ],
    }
