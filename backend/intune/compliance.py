"""
Politiques et statuts de conformité Intune.

Source unique depuis le 2026-10-21 : l'API de RAPPORTS Intune (`POST beta /deviceManagement/
reports/{action}`), celle qu'utilise le portail — même approche que Lumis
(`lib/it/habilitations/intune-reports.ts`), demandée par Nicolas ("pour tout ce qui concerne
les conformités on peut passer via le /report de l'api Graph, il donne les vrais résultats").

Pourquoi : les endpoints OData historiques étaient faux ou cassés, et ce module en
contournait les défauts à grand renfort d'heuristiques (lignes d'affectation "fantômes",
reclassement par l'état global, résolution par utilisateur — voir docs/internal/HISTORY.md, V1 à V40).
Mesure du 2026-10-21 sur le tenant de production, 34 politiques :
  - `deviceStatusOverview` (ancien agrégat) différait du rapport sur 19 politiques sur 34
    (ex. "Check Secure Boot" : 4 non conformes + 28 "en attente" contre 7 + 0 dans le rapport,
    qui correspond au portail) ;
  - `/deviceStatuses` renvoyait des lignes d'affectation sans appareil au statut faux ;
  - `managedDevices/{id}/deviceCompliancePolicyStates` ne listait que "Default Device
    Compliance Policy" ;
  - le rapport, lui : 7 880 lignes appareil × politique, 100 % des `DeviceId` égaux à un
    `managedDevices.id`, aucun nom vide, OS toujours renseigné, et il connaît la politique
    intégrée "Default Device Compliance Policy" (absente de `/deviceCompliancePolicies`).

Rapports utilisés (noms du portail, faute de frappe Microsoft comprise : "Compliace") :
  - `getDeviceStatusByCompliacePolicyReport` — une politique, tous ses appareils (1 appel) ;
  - `getDevicePoliciesComplianceReport` — un appareil, toutes ses politiques (1 appel) ;
  - `getPolicyNonComplianceMetadata` — complète la liste des politiques (Default Policy).

Format : PAS une collection OData — `Schema` (colonnes) + `Values` (lignes positionnelles) +
`TotalRowCount`, pagination `skip`/`top` (voir `_run_report`).

Seule exception volontaire : le détail PAR PARAMÈTRE d'un couple appareil/politique
(`get_device_compliance_status(device_id, policy_id)`) reste sur la navigation `settingStates`,
qui fonctionne (seule l'ÉNUMÉRATION des politiques d'un appareil était cassée) et dont le champ
`setting` porte les clés techniques sur lesquelles sont indexées les traductions FR des réglages
(`ComplianceOsGrid.jsx::_settingLabelFr`). Le rapport équivalent
(`getDevicePolicySettingsComplianceReport`) expose d'autres clés (`SettingName`
"Windows10CompliancePolicy.SecureBootEnabled") — y passer demanderait de réindexer ces libellés.

Le calcul agrégé "détail des appareils non conformes par politique, regroupé par OS" vit dans
`intune/compliance_detail.py`, qui s'appuie sur `get_policy_report_rows` ci-dessous.
"""
from concurrent.futures import ThreadPoolExecutor

from common.cache import TTLCache
from common.http_client import escape_odata_string, handle_tool_errors, validate_graph_id
from intune.client import client, client_beta

# ── Moteur de rapports ──────────────────────────────────────────────────────────────────────

# 1 000 lignes par page : accepté par le service (le portail en demande 50). 200 pages au-delà
# desquelles c'est un filtre qui a sauté, pas un parc qui a grossi — même garde-fou que Lumis.
_REPORT_PAGE_SIZE = 1000
_REPORT_MAX_PAGES = 200


def _zip_report(body: dict) -> tuple[list[dict], int | None]:
    """`{Schema, Values, TotalRowCount}` -> (lignes en dict, total annoncé ou None)."""
    columns = [str(c.get("Column") or "") for c in (body or {}).get("Schema") or []]
    rows = [dict(zip(columns, values)) for values in (body or {}).get("Values") or []]
    total = (body or {}).get("TotalRowCount")
    return rows, total if isinstance(total, int) else None


def _run_report(action: str, filter_expr: str | None = None) -> list[dict]:
    """Exécute un rapport Intune et rend TOUTES ses lignes (toutes pages confondues).
    `select: []` = toutes les colonnes. Les 429/5xx sont réessayés par `ODataClient`."""
    rows: list[dict] = []
    skip = 0
    for _ in range(_REPORT_MAX_PAGES):
        body: dict = {"select": [], "skip": skip, "top": _REPORT_PAGE_SIZE}
        if filter_expr:
            body["filter"] = filter_expr
        page, total = _zip_report(client_beta.post(f"/deviceManagement/reports/{action}", body))
        rows.extend(page)
        skip += len(page)
        if not page or skip >= (total if total is not None else skip):
            return rows
    raise ValueError(f"Rapport {action} : plus de {_REPORT_MAX_PAGES} pages, filtre probablement ignoré")


# Code numérique `PolicyStatus` du rapport -> valeur de l'énumération Graph `complianceStatus`
# (casse chameau, celle qu'utilisaient /deviceStatuses et deviceCompliancePolicyStates — tout le
# reste du code et le frontend raisonnent dessus). Codes 1, 2, 4, 5 observés sur le tenant ;
# les autres viennent de l'énumération Microsoft (même table que Lumis).
_STATUS_BY_CODE = {
    0: "unknown",
    1: "notApplicable",
    2: "compliant",
    3: "remediated",
    4: "nonCompliant",
    5: "error",
    6: "conflict",
    7: "notAssigned",
}
_STATUS_BY_LABEL = {
    "compliant": "compliant",
    "not compliant": "nonCompliant",
    "noncompliant": "nonCompliant",
    "not applicable": "notApplicable",
    "notapplicable": "notApplicable",
    "error": "error",
    "conflict": "conflict",
    "remediated": "remediated",
    "unknown": "unknown",
}


def _report_status(row: dict) -> str:
    """Statut d'une ligne de rapport. Le code numérique fait foi quand il est présent — 0 y est
    légitime ("unknown") : test d'absence, pas de véracité. Sinon le libellé `_loc`."""
    code = row.get("PolicyStatus")
    if code is not None and code != "":
        try:
            numeric = int(code)
        except (TypeError, ValueError):
            numeric = None
        if numeric in _STATUS_BY_CODE:
            return _STATUS_BY_CODE[numeric]
    label = str(row.get("PolicyStatus_loc") or "").strip().lower()
    return _STATUS_BY_LABEL.get(label, "unknown")


def _report_filter_eq(column: str, value: str) -> str:
    return f"({column} eq '{escape_odata_string(value)}')"


# ── Politiques ──────────────────────────────────────────────────────────────────────────────


def _list_policies() -> list[dict]:
    """Politiques de conformité : `/deviceCompliancePolicies` (avec `@odata.type`, qui donne la
    plateforme — d'où l'absence de `$select`) + celles que seul `getPolicyNonComplianceMetadata`
    connaît (la politique intégrée "Default Device Compliance Policy").
    Forme : `{id, displayName, odataType}`."""
    listed = client.get_all_pages("/deviceManagement/deviceCompliancePolicies")
    policies = [
        {"id": p["id"], "displayName": p.get("displayName"), "odataType": p.get("@odata.type")}
        for p in listed
        if p.get("id")
    ]
    known = {p["id"] for p in policies}
    for row in _run_report("getPolicyNonComplianceMetadata"):
        if not str(row.get("PolicyBaseTypeName") or "").endswith("DeviceCompliancePolicy"):
            continue
        policy_id = row.get("PolicyId")
        if policy_id and policy_id not in known:
            known.add(policy_id)
            policies.append({"id": policy_id, "displayName": row.get("PolicyName"), "odataType": None})
    return policies


# Toutes les lignes appareil × politique, mémorisées brièvement : le résumé (Dashboard), le
# détail (page Conformité) et le statut d'un appareil en ont besoin à quelques secondes
# d'intervalle — inutile de relancer ~35 rapports pour chacun.
_POLICY_REPORTS_TTL_SECONDS = 120
_policy_reports_cache = TTLCache(_POLICY_REPORTS_TTL_SECONDS)


def get_policy_report_rows(force_refresh: bool = False) -> list[dict]:
    """`[{id, displayName, odataType, rows | None, error | None}]` — une entrée par politique,
    `rows` = lignes brutes de `getDeviceStatusByCompliacePolicyReport`. Une politique dont le
    rapport échoue garde `rows: None` + `error` (jamais une liste vide, indiscernable de "aucun
    appareil") ; l'échec de la LISTE des politiques, lui, est levé."""
    if not force_refresh:
        cached = _policy_reports_cache.get("all")
        if cached is not None:
            return cached

    policies = _list_policies()

    def _fetch(p: dict) -> dict:
        try:
            rows = _run_report("getDeviceStatusByCompliacePolicyReport", _report_filter_eq("PolicyId", p["id"]))
            return {**p, "rows": rows, "error": None}
        except Exception as e:  # une politique isolée en échec ne fait pas échouer les autres
            return {**p, "rows": None, "error": str(e)}

    with ThreadPoolExecutor(max_workers=8) as pool:
        result = list(pool.map(_fetch, policies))
    _policy_reports_cache.set("all", result)
    return result


@handle_tool_errors
def list_non_compliant_devices() -> dict:
    """Tous les appareils non conformes (état GLOBAL de l'appareil, `managedDevices`)."""
    select = "id,deviceName,operatingSystem,userDisplayName,userPrincipalName,lastSyncDateTime"
    devices = client.get_all_pages(
        "/deviceManagement/managedDevices",
        params={"$filter": "complianceState eq 'noncompliant'", "$select": select},
    )
    return {"count": len(devices), "devices": devices}


@handle_tool_errors
def get_compliance_policies() -> list[dict]:
    """Toutes les politiques de conformité Intune configurées."""
    select = "id,displayName,description,createdDateTime,lastModifiedDateTime"
    return client.get_all_pages("/deviceManagement/deviceCompliancePolicies", params={"$select": select})


def _summary_counts(rows: list[dict]) -> dict:
    """Compteurs d'une politique à partir de ses lignes de rapport — mêmes clés que l'ancien
    `deviceStatusOverview`, pour que le frontend n'ait rien à changer."""
    counts = {"successCount": 0, "failedCount": 0, "errorCount": 0, "notApplicableCount": 0, "pendingCount": 0}
    for row in rows:
        status = _report_status(row)
        if status in ("compliant", "remediated"):
            counts["successCount"] += 1
        elif status == "nonCompliant":
            counts["failedCount"] += 1
        elif status in ("error", "conflict"):
            counts["errorCount"] += 1
        elif status == "notApplicable":
            counts["notApplicableCount"] += 1
        else:  # unknown / notAssigned : évaluation pas encore rendue
            counts["pendingCount"] += 1
    return counts


@handle_tool_errors
def get_compliance_policy_summary() -> list[dict]:
    """
    Pour chaque politique de conformité (y compris "Default Device Compliance Policy"), les
    compteurs successCount/failedCount/errorCount/notApplicableCount/pendingCount sur tout le
    parc assigné, calculés depuis le rapport `getDeviceStatusByCompliacePolicyReport` — un
    appel par politique, les chiffres du portail Intune.
    """
    out = []
    for p in get_policy_report_rows():
        base = {"id": p["id"], "displayName": p.get("displayName"), "odataType": p.get("odataType")}
        if p["rows"] is None:
            out.append({**base, "error": p["error"]})
            continue
        contacts = [r.get("LastContact") for r in p["rows"] if r.get("LastContact")]
        out.append({**base, **_summary_counts(p["rows"]), "lastUpdateDateTime": max(contacts) if contacts else None})
    return out


@handle_tool_errors
def get_device_compliance_status(device_id: str, policy_id: str | None = None) -> list[dict]:
    """
    Statut de conformité d'un appareil.

    Sans `policy_id` : une ligne par politique ASSIGNÉE à l'appareil, depuis le rapport
    `getDevicePoliciesComplianceReport` (un appel). Remplace `deviceCompliancePolicyStates`,
    qui ne renvoyait plus que "Default Device Compliance Policy" sur ce tenant.

    Avec `policy_id` : le détail PAR PARAMÈTRE de cette politique pour cet appareil, via la
    navigation `deviceCompliancePolicyStates/{policy_id}/settingStates` — conservée exprès (voir
    l'en-tête du module : clés `setting` des traductions FR). Graph refuse
    `$expand=settingStates` sur la collection (400) : il faut naviguer vers la politique.
    """
    validate_graph_id(device_id, "device_id")
    if policy_id:
        validate_graph_id(policy_id, "policy_id")
        return client.get_all_pages(
            f"/deviceManagement/managedDevices/{device_id}/deviceCompliancePolicyStates/{policy_id}/settingStates"
        )
    rows = _run_report("getDevicePoliciesComplianceReport", _report_filter_eq("DeviceId", device_id))
    return [
        {
            "id": r.get("PolicyId"),
            "displayName": r.get("PolicyName"),
            "state": _report_status(r),
            "platformType": r.get("PolicyPlatformType"),
            "version": r.get("PolicyVersion"),
            "lastReportedDateTime": r.get("LastContact"),
        }
        for r in rows
    ]


# Plateforme déduite du type Graph de la politique. Une politique de conformité Intune est
# TOUJOURS typée par plateforme : une windows10CompliancePolicy ne peut pas s'appliquer à un
# Android — repli légitime pour attribuer un OS à une ligne.
_POLICY_TYPE_OS = {
    "windows10compliancepolicy": "Windows",
    "windows81compliancepolicy": "Windows",
    "windowsphone81compliancepolicy": "Windows",
    "macoscompliancepolicy": "macOS",
    "ioscompliancepolicy": "iOS",
    "androidcompliancepolicy": "Android",
    "androidworkprofilecompliancepolicy": "Android",
    "androiddeviceownercompliancepolicy": "Android",
    "aospdeviceownercompliancepolicy": "Android",
}


def _os_from_policy_type(odata_type: str | None) -> str | None:
    """"#microsoft.graph.windows10CompliancePolicy" -> "Windows" (None si type inconnu)."""
    if not odata_type:
        return None
    return _POLICY_TYPE_OS.get(str(odata_type).split(".")[-1].strip("#").lower())


# Repli sur la convention de nommage du tenant ("[ORG] Android - …", "[ORG] SRV - Windows - …"),
# UNIQUEMENT quand `@odata.type` est absent (fragile : un renommage la casse).
_POLICY_NAME_OS = (
    ("android", "Android"),
    ("macos", "macOS"),
    ("ios", "iOS"),
    ("linux", "Linux"),
    ("windows", "Windows"),
)


def _os_from_policy_name(display_name: str | None) -> str | None:
    name = (display_name or "").lower()
    for marker, os_name in _POLICY_NAME_OS:
        if marker in name:
            return os_name
    return None


def _policy_platform(policy: dict) -> str | None:
    """Plateforme d'une politique : son type Graph d'abord, son nom en dernier recours."""
    return _os_from_policy_type(policy.get("odataType")) or _os_from_policy_name(policy.get("displayName"))


# Libellé `OS_loc` du rapport -> vocabulaire `operatingSystem` de managedDevices (celui sur
# lequel le frontend regroupe les cartes par OS). Valeurs observées le 2026-10-21 : "Windows",
# "Android (fully managed/dedicated)", "Android (work profile)", "macOS", "iOS".
def _os_from_report(os_label: str | None) -> str | None:
    label = (os_label or "").strip().lower()
    if not label:
        return None
    for marker, os_name in (("android", "Android"), ("macos", "macOS"), ("ios", "iOS"), ("windows", "Windows"), ("linux", "Linux")):
        if label.startswith(marker):
            return os_name
    return os_label


# complianceStatus par politique (casse chameau) -> catégorie affichée. Quatre familles (V13,
# demande de Nicolas : non conformes, erreurs, non applicables et en attente dans le MÊME
# tableau, différenciés par la colonne État).
_POLICY_STATUS_CATEGORY = {
    "noncompliant": "Non conforme",
    "error": "Erreur",
    "conflict": "Erreur",
    "notapplicable": "Non applicable",
    "unknown": "En attente",
    "notassigned": "En attente",
    "compliant": "Conforme",
    "remediated": "Conforme",
}

# Catégories retenues dans le panneau (tout sauf les appareils réellement conformes).
_REPORTED_CATEGORIES = ("Non conforme", "Erreur", "Non applicable", "En attente")

# Catégories considérées comme un échec avéré.
_FAILING_CATEGORIES = ("Non conforme", "Erreur")


def _category_from_policy_status(status: str | None) -> str:
    return _POLICY_STATUS_CATEGORY.get((status or "").strip().lower(), "Erreur")


def _shape_report_row(row: dict) -> dict:
    """Ligne de `getDeviceStatusByCompliacePolicyReport` -> forme historique des statuts par
    politique (celle de l'ancien `/deviceStatuses`)."""
    return {
        "deviceId": row.get("DeviceId"),
        "aadDeviceId": row.get("AadDeviceId"),
        "deviceName": row.get("DeviceName"),
        "userPrincipalName": row.get("UPN"),
        "operatingSystem": _os_from_report(row.get("OS_loc")),
        "status": _report_status(row),
        "lastReportedDateTime": row.get("LastContact"),
        # Le rapport ne porte pas l'échéance de la période de grâce (l'ancien /deviceStatuses
        # non plus de façon fiable) : clé conservée pour la compatibilité des appelants.
        "gracePeriodExpiration": None,
        "isPlaceholder": False,
    }


@handle_tool_errors
def get_policy_device_statuses(policy_id: str, status_filter: str | None = None) -> dict:
    """
    Appareils et statut de conformité pour UNE politique, depuis
    `getDeviceStatusByCompliacePolicyReport`. Plus de lignes d'affectation "fantômes" : le
    rapport ne renvoie que des appareils réels — `placeholderRows`/`placeholderCount` restent
    dans la réponse (toujours vides) pour la compatibilité des appelants.
    `status_filter` : valeur `complianceStatus` (ex. "nonCompliant"), comparaison exacte.
    """
    validate_graph_id(policy_id, "policy_id")
    rows = [_shape_report_row(r) for r in _run_report("getDeviceStatusByCompliacePolicyReport", _report_filter_eq("PolicyId", policy_id))]
    if status_filter:
        rows = [r for r in rows if r["status"] == status_filter]
    return {
        "policyId": policy_id,
        "statusFilter": status_filter or "all",
        "total": len(rows),
        "devices": rows,
        "placeholderRows": [],
        "placeholderCount": 0,
    }


@handle_tool_errors
def get_device_all_policy_statuses(device_id: str, device_name: str, platform: str | None = None) -> list[dict]:
    """Statut de conformité d'UN appareil pour toutes ses politiques (Vue Appareil 360°), en un
    seul appel au rapport `getDevicePoliciesComplianceReport` — exactement la liste du portail
    (onglet "Conformité de l'appareil"), politiques assignées uniquement.

    `device_name`/`platform` ne servent plus (l'ancienne version reconstruisait la liste en
    interrogeant chaque politique de la plateforme puis en filtrant sur le nom) : conservés dans
    la signature pour ne pas casser les appelants (device_overview.py, serveur MCP).
    Forme : `[{id, displayName, state, lastReportedDateTime}]`."""
    statuses = get_device_compliance_status(device_id)
    if isinstance(statuses, list) and len(statuses) == 1 and isinstance(statuses[0], dict) and statuses[0].get("error"):
        raise ValueError(statuses[0].get("message") or "Erreur lors du chargement du rapport de conformité")
    return [
        {
            "id": s["id"],
            "displayName": s.get("displayName"),
            "state": s.get("state") or "unknown",
            "lastReportedDateTime": s.get("lastReportedDateTime"),
        }
        for s in statuses
    ]
