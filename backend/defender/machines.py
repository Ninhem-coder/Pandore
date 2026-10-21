"""
Machines Defender for Endpoint (inventaire, onboarding) — extrait de `defender/tools.py`
(721 lignes) à la revue d'architecture du 2026-08-17, deuxième passe (le premier passage
avait traité les caches/tests/parité MCP ; celle-ci découpe le fichier lui-même par domaine :
machines, alertes, hunting, vulnérabilités — voir `defender/alerts.py`, `defender/hunting.py`,
`defender/vulnerabilities.py`).

Comme le reste des modules issus de ce découpage : fonctions "nues" réutilisées à la fois par
le serveur MCP (`defender/mcp_server.py`) et par l'API REST du dashboard (`api_server.py`).
"""
from common.http_client import escape_odata_string, handle_tool_errors, tool_error, validate_graph_id
from defender.client import client
from defender.hunting import run_hunting_query


def _format_machine(m: dict) -> dict:
    """Sélectionne les champs utiles d'une machine pour alléger les réponses des LISTES
    (list_machines, list_non_onboarded_machines) — potentiellement des centaines de lignes,
    d'où le tri volontairement minimal. Ne PAS enrichir cette fonction pour un besoin qui ne
    concerne qu'UN appareil (voir _format_machine_detail ci-dessous) : ça alourdirait toutes
    les listes du parc pour un usage qui n'en a besoin qu'au singulier."""
    return {
        "id": m.get("id"),
        "computerDnsName": m.get("computerDnsName"),
        "aadDeviceId": m.get("aadDeviceId"),
        "osPlatform": m.get("osPlatform"),
        "osVersion": m.get("osVersion"),
        "onboardingStatus": m.get("onboardingStatus"),
        "healthStatus": m.get("healthStatus"),
        "firstSeen": m.get("firstSeen"),
        "lastSeen": m.get("lastSeen"),
        "lastIpAddress": m.get("lastIpAddress"),
        "riskScore": m.get("riskScore"),
        "exposureLevel": m.get("exposureLevel"),
        "machineTags": m.get("machineTags", []),
    }


def _format_machine_detail(m: dict) -> dict:
    """Version enrichie de _format_machine, réservée à la fiche d'UN appareil précis (Vue
    Appareil 360°, `get_machine(name=...)` ci-dessous) : une machine seule peut se permettre
    d'exposer davantage de champs que les listes du parc, sans coût réseau supplémentaire —
    ce sont les MÊMES champs `/api/machines` renvoie déjà, `_format_machine` les jetait
    simplement (compte rendu du 2026-08-19 : comparaison avec les pages device natives
    Intune/Defender, qui montrent beaucoup plus que ce que _format_machine laissait passer).

    `rbacGroupName`/`isAadJoined`/`osBuild` sont documentés dans le schéma public de l'API
    "List machines" (learn.microsoft.com/defender-endpoint/api/get-machines). `agentVersion`/
    `osArchitecture`/`deviceValue`/`managedBy`/`defenderAvStatus`/`ipAddresses` sont des champs
    stables de l'API MDE mais PAS vérifiés sur le tenant de production au moment d'écrire ceci
    — `.get()` partout : un champ absent redescend `None` (affiché "—" côté frontend) plutôt
    que de faire échouer l'appel.

    `partnerReportedThreatState` (2026-09-02, maquette "État de santé appareil" — statut de
    menace remonté par un partenaire MTD tiers) ajouté sur le même principe : documenté sur la
    ressource Machine (learn.microsoft.com/defender-endpoint/api/machine), jamais vérifié sur
    ce tenant avant ce jour — `None` si absent/non applicable (aucun partenaire MTD configuré),
    affiché "—" côté frontend plutôt que de planter."""
    base = _format_machine(m)
    base.update(
        {
            "rbacGroupName": m.get("rbacGroupName"),
            "isAadJoined": m.get("isAadJoined"),
            "osBuild": m.get("osBuild"),
            "osArchitecture": m.get("osArchitecture"),
            "agentVersion": m.get("agentVersion"),
            "deviceValue": m.get("deviceValue"),
            "managedBy": m.get("managedBy"),
            "defenderAvStatus": m.get("defenderAvStatus"),
            "ipAddresses": m.get("ipAddresses"),
            "partnerReportedThreatState": m.get("partnerReportedThreatState"),
            # (2026-09-02, retour de Nicolas sur un appareil Android réel dont l'IP ne
            # s'affichait pas) : `lastIpAddress` revient `None` sur certains appareils mobiles
            # (confirmé en direct, cecilia_cester_Android) alors que `lastExternalIpAddress`
            # (déjà présent dans la réponse `/api/machines`, jamais extrait avant ce jour) est
            # renseigné — voir DeviceOverviewTab.jsx::primaryIpAddress pour l'ordre de repli.
            "lastExternalIpAddress": m.get("lastExternalIpAddress"),
        }
    )
    return base


_TOTAL_MACHINES_KQL = """
DeviceInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, IsExcluded) by DeviceId
| summarize NotExcludedCount = countif(IsExcluded == false)
"""


@handle_tool_errors
def get_defender_summary() -> dict:
    """Résumé global du parc MDE : total, répartition par onboarding/santé/OS/exposition.

    `totalMachines` (2026-08-28, demande de Nicolas : la carte "Machines Defender" ne
    correspondait pas à ce qu'il voit dans le portail Defender avec les filtres "30 derniers
    jours" + "Not excluded") — n'est PLUS `len(machines)` sur `/api/machines` SANS FILTRE
    (comptait aussi des appareils jamais vus depuis des mois/exclus manuellement, gonflant le
    total très au-delà de ce que le portail affiche par défaut). Recalculé via Advanced Hunting
    sur `DeviceInfo` (`IsExcluded`, colonne confirmée en direct sur le tenant de production —
    absente du schéma REST `/api/machines` lui-même), `arg_max(Timestamp, IsExcluded)` par
    device pour ne garder que le dernier état connu de chacun avant de compter. Testé en direct
    : 1216 (NotExcluded, 30 jours) contre 1417 (total 30 jours, exclus compris) et ~1967 pour
    l'ancien total /api/machines sans aucun filtre.

    Repli sur l'ancien comportement (`len(machines)`) UNIQUEMENT si la requête KQL échoue —
    jamais casser tout le résumé pour un souci sur cette seule métrique.

    `byOnboardingStatus`/`byHealthStatus`/`byOSPlatform`/`byExposureLevel` restent calculés sur
    `/api/machines` SANS ce filtre, volontairement : l'entonnoir d'onboarding a justement
    besoin des appareils "CanBeOnboarded"/"InsufficientInfo", qui n'ont jamais eu de capteur
    Defender actif et n'apparaissent donc jamais dans `DeviceInfo` — leur appliquer le même
    filtre les ferait disparaître entièrement du camembert Onboarding."""
    machines = client.get_all_pages("/api/machines")

    onboarding_counts: dict = {}
    health_counts: dict = {}
    os_counts: dict = {}
    exposure_counts: dict = {}

    for m in machines:
        onboarding_counts[m.get("onboardingStatus", "Unknown")] = (
            onboarding_counts.get(m.get("onboardingStatus", "Unknown"), 0) + 1
        )
        health_counts[m.get("healthStatus", "Unknown")] = (
            health_counts.get(m.get("healthStatus", "Unknown"), 0) + 1
        )
        os_counts[m.get("osPlatform", "Unknown")] = os_counts.get(m.get("osPlatform", "Unknown"), 0) + 1
        # "Device exposure distribution" du dashboard natif MDVM (tvm-dashboard-insights) —
        # même champ `exposureLevel` que _format_machine plus bas, déjà présent dans la
        # réponse /api/machines : aucun nouvel appel Graph/MDE nécessaire pour ce widget.
        exposure_counts[m.get("exposureLevel", "Unknown")] = exposure_counts.get(m.get("exposureLevel", "Unknown"), 0) + 1

    total_machines = len(machines)
    hunting = run_hunting_query(_TOTAL_MACHINES_KQL)
    if not (isinstance(hunting, dict) and hunting.get("error")):
        hunting_results = hunting.get("results") or []
        if hunting_results and "NotExcludedCount" in hunting_results[0]:
            total_machines = hunting_results[0]["NotExcludedCount"]

    return {
        "totalMachines": total_machines,
        "byOnboardingStatus": onboarding_counts,
        "byHealthStatus": health_counts,
        "byOSPlatform": os_counts,
        "byExposureLevel": exposure_counts,
    }


@handle_tool_errors
def list_machines(filter: str | None = None, top: int = 100) -> list[dict]:
    """Liste les machines onboardées. `top=0` récupère tout le parc (pagination complète)."""
    if top == 0:
        machines = client.get_all_pages("/api/machines", params={"$filter": filter} if filter else None)
    else:
        params: dict = {"$top": top}
        if filter:
            params["$filter"] = filter
        data = client.get("/api/machines", params=params)
        machines = data.get("value", [])

    return [_format_machine(m) for m in machines]


@handle_tool_errors
def get_machine(machine_id: str | None = None, name: str | None = None, aad_device_id: str | None = None) -> dict:
    """Détail d'une machine, par ID natif Defender, par nom DNS ou par identifiant Azure AD.

    La branche `name=` (recherche par nom, utilisée par la Vue Appareil 360° —
    `device_overview.py`) renvoie la version ENRICHIE `_format_machine_detail` : contrairement
    à `list_machines`, il n'y a ici qu'UNE SEULE machine à mettre en forme, donc rien
    n'empêche d'exposer davantage de champs (voir le docstring de `_format_machine_detail`).

    `aad_device_id=` (2026-09-02, demande de Nicolas) : sur un appareil mobile, le nom DNS
    Defender (`computerDnsName`) peut être TOTALEMENT différent du nom Intune (`deviceName`) —
    confirmé en direct sur le tenant de production ("jdupont_Android" côté Defender vs
    "DEMO-MOB-103" côté Intune, même appareil). Les deux systèmes partagent en revanche le
    MÊME identifiant Azure AD (`aadDeviceId` ici, `azureADDeviceId` côté Intune) — voir
    device_overview.py pour le repli qui emprunte ce chemin quand la recherche par nom échoue
    d'un seul côté. `$filter=aadDeviceId eq '...'` renvoie une 400 côté API Defender (testé en
    direct, champ non filtrable côté serveur) — scan complet du parc, même coût que le filet de
    secours déjà en place pour `name=` ci-dessus (`list_machines`/`client.get_all_pages` déjà
    utilisés ailleurs pour ce même volume)."""
    if machine_id:
        validate_graph_id(machine_id, "machine_id")
        return client.get(f"/api/machines/{machine_id}")

    if aad_device_id:
        all_machines = client.get_all_pages("/api/machines")
        needle = aad_device_id.strip().lower()
        machines = [m for m in all_machines if (m.get("aadDeviceId") or "").lower() == needle]
        if not machines:
            return tool_error(f"Aucune machine trouvée avec l'identifiant Azure AD '{aad_device_id}'", "NotFound")
        result = _format_machine_detail(machines[0])
        if len(machines) > 1:
            result["ambiguousMatches"] = len(machines)
        return result

    if name:
        safe_name = escape_odata_string(name)
        data = client.get("/api/machines", params={"$filter": f"computerDnsName eq '{safe_name}'"})
        machines = data.get("value", [])

        # `eq` est sensible à la casse côté API Defender : un poste enregistré en DNS avec une
        # casse différente de celle tapée par l'utilisateur (fréquent après un renommage/une
        # réimportation) ne matchait rien ici alors qu'il existe bien — revue de code du
        # 2026-08-20. Filet de secours volontairement peu coûteux : on ne retombe sur un scan
        # complet du parc QUE si le filtre exact n'a rien trouvé (cas rare), jamais en systématique.
        if not machines:
            all_machines = client.get_all_pages("/api/machines")
            needle = name.strip().lower()
            machines = [m for m in all_machines if (m.get("computerDnsName") or "").lower() == needle]

        if not machines:
            return tool_error(f"Aucune machine trouvée avec le nom '{name}'", "NotFound")

        result = _format_machine_detail(machines[0])
        if len(machines) > 1:
            # Homonyme DNS (rare mais réel) : on renvoie tout de même la première machine
            # plutôt qu'une erreur bloquante, mais on signale explicitement l'ambiguïté au
            # lieu de la passer sous silence — voir device_overview.py qui relaie ce champ.
            result["ambiguousMatches"] = len(machines)
        return result

    return tool_error("Fournir machine_id, name ou aad_device_id", "BadRequest")


@handle_tool_errors
def list_non_onboarded_machines(include_can_be_onboarded: bool = True) -> list[dict]:
    """Machines détectées par MDE mais dont le statut n'est pas 'Onboarded'."""
    statuses = ["InsufficientInfo"]
    if include_can_be_onboarded:
        statuses.append("CanBeOnboarded")

    filter_str = " or ".join([f"onboardingStatus eq '{s}'" for s in statuses])
    machines = client.get_all_pages("/api/machines", params={"$filter": filter_str})
    return [_format_machine(m) for m in machines]
