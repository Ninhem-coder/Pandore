"""
Détail des appareils non conformes par politique de conformité Intune, regroupables par OS côté
dashboard (onglet "Conformité").

Réécrit le 2026-10-21 sur l'API de rapports Intune (voir l'en-tête de `intune/compliance.py`) :
`getDeviceStatusByCompliacePolicyReport` renvoie, pour chaque politique, une ligne par appareil
RÉEL avec son nom, son OS, son UPN et son statut pour CETTE politique — les chiffres du portail.

L'ancien pipeline (~800 lignes, versions V1 à V40, historique complet dans docs/internal/HISTORY.md)
existait uniquement pour compenser les défauts des endpoints OData historiques : lignes
d'affectation sans appareil au statut faux (`_is_placeholder_status_row`), reprise de ces
lignes par utilisateur avec vérification appareil par appareil, reclassement d'après l'état
global de l'appareil, garde-fou de plateforme, plafonnement à l'agrégat… Le rapport n'ayant
aucun de ces défauts (mesuré : 7 880 lignes, 100 % rattachées à un `managedDevices.id`, aucun
nom vide), tout ce code est retiré. Les clés de sortie sont conservées à l'identique (les
compteurs de réconciliation valent désormais 0) pour que le frontend n'ait rien à changer.
"""
from common.cache import TTLCache
from common.http_client import handle_tool_errors
from intune.compliance import (
    _FAILING_CATEGORIES,
    _REPORTED_CATEGORIES,
    _category_from_policy_status,
    _os_from_report,
    _policy_platform,
    _shape_report_row,
    get_policy_report_rows,
)
from intune.devices import list_devices

# Cache du résultat assemblé (en plus de celui des lignes brutes dans compliance.py) : un
# aller-retour sur l'onglet ne repaie même pas l'assemblage. `force_refresh` (bouton
# "Rafraîchir") contourne les deux.
_COMPLIANCE_DETAIL_TTL_SECONDS = 120
_compliance_detail_cache = TTLCache(_COMPLIANCE_DETAIL_TTL_SECONDS)


@handle_tool_errors
def get_compliance_detail(max_devices: int | None = None, force_refresh: bool = False) -> dict:
    """
    Pour chaque politique ayant au moins un appareil non conforme ou en erreur, la liste
    nominative de ses appareils NON conformes au sens large (non conformes, erreurs, non
    applicables, en attente — différenciés par `complianceCategory`), avec leur OS.

    `max_devices` plafonne le nombre d'appareils renvoyés PAR politique (`truncated` le
    signale). Résultat mis en cache 120 s par valeur de `max_devices`.
    """
    cache_key = str(max_devices)
    if not force_refresh:
        cached = _compliance_detail_cache.get(cache_key)
        if cached is not None:
            return cached

    result = _compute_compliance_detail(max_devices, force_refresh)
    _compliance_detail_cache.set(cache_key, result)
    return result


def _compute_compliance_detail(max_devices: int | None, force_refresh: bool = False) -> dict:
    reports = get_policy_report_rows(force_refresh=force_refresh)

    # État GLOBAL de chaque appareil (managedDevices), affiché à côté du statut par politique
    # (`deviceComplianceState`) — information, plus arbitrage : le rapport fait foi.
    all_devices = list_devices()
    device_by_id: dict[str, dict] = {}
    if not (isinstance(all_devices, dict) and all_devices.get("error")):
        device_by_id = {d["id"]: d for d in all_devices if d.get("id")}

    policies: list[dict] = []
    unavailable_policies: list[dict] = []
    scanned = 0
    aggregate_total = 0

    for p in reports:
        if p["rows"] is None:
            unavailable_policies.append(
                {"id": p["id"], "displayName": p.get("displayName"), "failedCount": 0, "error": p["error"]}
            )
            continue

        shaped = [_shape_report_row(r) for r in p["rows"]]
        failing = sum(1 for r in shaped if _category_from_policy_status(r["status"]) in _FAILING_CATEGORIES)
        if not failing:
            continue
        scanned += 1
        aggregate_total += failing

        policy_os = _policy_platform(p)
        devices = []
        for r in shaped:
            category = _category_from_policy_status(r["status"])
            if category not in _REPORTED_CATEGORIES:
                continue
            managed = device_by_id.get(r["deviceId"]) or {}
            devices.append(
                {
                    "deviceId": r["deviceId"],
                    "deviceName": r["deviceName"] or "Device sans nom",
                    "userPrincipalName": r["userPrincipalName"] or managed.get("userPrincipalName"),
                    # OS de l'appareil (managedDevices), sinon celui du rapport, sinon la
                    # plateforme de la politique — jamais "Inconnu" quand l'une des trois existe.
                    # Normalisé ("Linux (ubuntu)" -> "Linux") : la politique intégrée "Default
                    # Device Compliance Policy", couverte depuis le passage aux rapports, évalue
                    # aussi les postes Linux, dont l'operatingSystem porte la distribution.
                    "operatingSystem": _os_from_report(managed.get("operatingSystem"))
                    or r["operatingSystem"]
                    or policy_os
                    or "Inconnu",
                    "status": r["status"],
                    "deviceComplianceState": managed.get("complianceState"),
                    "complianceCategory": category,
                    "lastReportedDateTime": r["lastReportedDateTime"],
                    "resolvedFromPlaceholder": False,
                }
            )
        # Non conformes d'abord, puis erreurs, non applicables, en attente.
        devices.sort(key=lambda d: (_REPORTED_CATEGORIES.index(d["complianceCategory"]), d["deviceName"].lower()))
        policies.append(
            {
                "id": p["id"],
                "displayName": p.get("displayName"),
                "failedCount": len(devices),
                "aggregateFailedCount": failing,
                "placeholderRows": 0,
                "resolvedFromPlaceholders": 0,
                "reclassifiedByDeviceState": 0,
                "platformMismatchCount": 0,
                "unresolvedPlaceholderRows": 0,
                "unverifiedCandidates": 0,
                "devices": devices,
            }
        )

    policies.sort(key=lambda p: p["failedCount"], reverse=True)

    truncated = False
    if max_devices:
        for p in policies:
            if len(p["devices"]) > max_devices:
                p["devices"] = p["devices"][:max_devices]
                truncated = True

    return {
        "policies": policies,
        "truncated": truncated,
        "maxDevicesPerPolicy": max_devices,
        # Politiques dont le rapport a échoué : affichées explicitement par le frontend.
        "unavailablePolicies": unavailable_policies,
        # Clés historiques conservées pour le frontend — toujours vides/nulles avec le rapport
        # (plus de lignes d'affectation, plus de reprise, plus de reclassement).
        "placeholderOnlyPolicies": [],
        "missingPolicies": [],
        "scannedPolicies": scanned,
        "totalFailedCount": sum(p["failedCount"] for p in policies),
        "aggregateTotalCount": aggregate_total,
        "placeholderRows": 0,
        "resolvedFromPlaceholders": 0,
        "reclassifiedByDeviceState": 0,
        "platformMismatchCount": 0,
        "unresolvedPlaceholderRows": 0,
        "unverifiedCandidates": 0,
        "source": "intune-reports",
    }
