"""
Inventaire et configuration des appareils Intune — extrait de `intune/tools.py`
(1373 lignes) à la revue d'architecture du 2026-08-17, deuxième passe (le premier passage
avait traité les caches/tests/parité MCP ; celle-ci découpe le fichier lui-même par domaine :
appareils, conformité, détail de conformité, apps, utilisateurs, Secure Score — voir
`intune/compliance.py`, `intune/compliance_detail.py`, `intune/apps.py`, `intune/users.py`,
`intune/secure_score.py`).

Comme le reste des modules issus de ce découpage : fonctions "nues" réutilisées à la fois par
le serveur MCP (`intune/mcp_server.py`) et par l'API REST du dashboard (`api_server.py`).
"""

from common.http_client import escape_odata_string, handle_tool_errors, tool_error, validate_graph_id
from intune.client import client


@handle_tool_errors
def list_devices(filter: str | None = None, top: int | None = None) -> list[dict]:
    """Liste les appareils Intune (conformité, OS, utilisateur assigné). `top` absent = tout le tenant."""
    select = "id,deviceName,operatingSystem,osVersion,complianceState,userDisplayName,userPrincipalName,lastSyncDateTime,managementState,azureADDeviceId"
    params: dict = {"$select": select}
    if filter:
        params["$filter"] = filter

    if top:
        params["$top"] = top
        data = client.get("/deviceManagement/managedDevices", params=params)
        return data.get("value", [])

    return client.get_all_pages("/deviceManagement/managedDevices", params=params)


@handle_tool_errors
def get_device(
    device_id: str | None = None,
    device_name: str | None = None,
    azure_ad_device_id: str | None = None,
) -> dict:
    """Détail complet d'un appareil Intune, par ID, par nom (deviceName) ou par identifiant
    Azure AD (`azureADDeviceId`).

    `azure_ad_device_id` (2026-09-02, demande de Nicolas) : sur un appareil mobile, le nom
    Intune (`deviceName`) et le nom Defender (`computerDnsName`) peuvent être TOTALEMENT
    différents — pas juste une casse ou un suffixe de domaine différents (déjà documenté pour
    `device_name=` ci-dessous), mais deux conventions de nommage sans rapport (ex. confirmé en
    direct sur le tenant de production : "DEMO-MOB-103" côté Intune vs
    "jdupont_Android" côté Defender, pour LE MÊME appareil). Les deux systèmes partagent
    en revanche le MÊME identifiant Azure AD — voir device_overview.py pour le repli qui
    utilise ce chemin quand la recherche par nom échoue d'un seul côté."""
    if device_id:
        validate_graph_id(device_id, "device_id")
        return client.get(f"/deviceManagement/managedDevices/{device_id}")
    if azure_ad_device_id:
        all_devices = list_devices()
        if not isinstance(all_devices, list):
            return tool_error("Device not found", "NotFound")
        needle = azure_ad_device_id.strip().lower()
        devices = [d for d in all_devices if (d.get("azureADDeviceId") or "").lower() == needle]
        if not devices:
            return tool_error("Device not found", "NotFound")
        matched_id = devices[0].get("id")
        result = client.get(f"/deviceManagement/managedDevices/{matched_id}") if matched_id else devices[0]
        if len(devices) > 1:
            result["ambiguousMatches"] = len(devices)
        return result
    if device_name:
        safe_name = escape_odata_string(device_name)
        data = client.get("/deviceManagement/managedDevices", params={"$filter": f"deviceName eq '{safe_name}'"})
        devices = data.get("value", [])

        # `eq` est sensible à la casse côté Graph : un poste dont le `deviceName` Intune ne
        # correspond pas exactement à la casse tapée par l'utilisateur (fréquent après un
        # renommage) ne matchait rien ici alors qu'il existe bien — revue de code du
        # 2026-08-20. Filet de secours peu coûteux : scan complet du parc UNIQUEMENT si le
        # filtre exact n'a rien trouvé, jamais en systématique.
        if not devices:
            all_devices = list_devices()
            if isinstance(all_devices, list):
                needle = device_name.strip().lower()
                devices = [d for d in all_devices if (d.get("deviceName") or "").lower() == needle]

        if not devices:
            return tool_error("Device not found", "NotFound")

        # Le scan de secours ci-dessus utilise le `$select` allégé de `list_devices` — on
        # récupère le détail complet du (premier) match par ID pour garder le même contrat de
        # sortie que le chemin `device_id=` ci-dessus (tous les champs Graph, pas seulement
        # ceux de la liste).
        matched_id = devices[0].get("id")
        result = client.get(f"/deviceManagement/managedDevices/{matched_id}") if matched_id else devices[0]
        if len(devices) > 1:
            # Homonyme (rare mais réel) : on renvoie la première correspondance plutôt qu'une
            # erreur bloquante, mais on signale explicitement l'ambiguïté au lieu de la passer
            # sous silence — voir device_overview.py qui relaie ce champ.
            result["ambiguousMatches"] = len(devices)
        return result
    return tool_error("device_id, device_name ou azure_ad_device_id requis", "BadRequest")


def _project_configuration_profile(p: dict) -> dict:
    return {
        "id": p.get("id"),
        "displayName": p.get("displayName"),
        "description": p.get("description"),
        "createdDateTime": p.get("createdDateTime"),
        "lastModifiedDateTime": p.get("lastModifiedDateTime"),
    }


@handle_tool_errors
def get_configuration_profiles(platform: str | None = None) -> list[dict]:
    """Profils de configuration Intune (device configuration profiles), filtrables par plateforme."""
    if platform:
        # `odata.type` (sans arobase) n'est pas un nom de propriété Graph valide : l'ancien
        # `contains(odata.type, '...')` ne correspondait à aucune syntaxe supportée et ne
        # filtrait donc jamais rien côté serveur (RÉF : REVUE_CODE_2026-08-10.md). Le
        # discriminant de type polymorphe Graph est `@odata.type`
        # (ex. "#microsoft.graph.windows10GeneralConfiguration"), qui ne se filtre pas de
        # façon fiable en $filter pour cette collection — on filtre donc côté client, comme
        # déjà fait pour la plateforme des politiques de conformité (voir
        # intune/compliance.py::_policy_platform).
        # $select est volontairement OMIS : comme pour deviceCompliancePolicies, une
        # projection Graph fait disparaître `@odata.type` de la réponse.
        profiles = client.get_all_pages("/deviceManagement/deviceConfigurations")
        needle = platform.lower()
        profiles = [p for p in profiles if needle in (p.get("@odata.type") or "").lower()]
        return [_project_configuration_profile(p) for p in profiles]

    select = "id,displayName,description,createdDateTime,lastModifiedDateTime"
    return client.get_all_pages("/deviceManagement/deviceConfigurations", params={"$select": select})


@handle_tool_errors
def get_intune_summary() -> dict:
    """Résumé global Intune : total appareils, taux de conformité, répartition par OS/état.

    Taux de conformité STRICT (2026-10-21, demande de Nicolas d'harmoniser le Dashboard et la
    page Conformité) : seuls les appareils `complianceState == "compliant"` comptent comme
    conformes — `inGracePeriod` (non-conformité réelle, simplement tolérée), `unknown` (jamais
    évalué) et `noncompliant` n'en font pas partie. Avant, le taux valait `(total -
    noncompliant) / total` et comptait donc les deux premiers comme conformes (92,1 % au lieu de
    85,5 % le 2026-10-21). SOURCE UNIQUE de ce taux : le point d'historique quotidien
    (api_server.py::_take_history_snapshot) réutilise `compliantCount` d'ici, jamais sa propre
    formule."""
    all_devices = client.get_all_pages(
        "/deviceManagement/managedDevices",
        {"$select": "id,operatingSystem,complianceState,managementState"},
    )

    by_os: dict = {}
    by_compliance: dict = {}
    for d in all_devices:
        by_os[d.get("operatingSystem")] = by_os.get(d.get("operatingSystem"), 0) + 1
        by_compliance[d.get("complianceState")] = by_compliance.get(d.get("complianceState"), 0) + 1

    total = len(all_devices)
    compliant = by_compliance.get("compliant", 0)
    return {
        "totalDevices": total,
        "compliantCount": compliant,
        "nonCompliantCount": by_compliance.get("noncompliant", 0),
        "complianceRate": f"{(compliant / total * 100):.1f}%" if total else "N/A",
        "byOperatingSystem": by_os,
        "byComplianceState": by_compliance,
    }
