"""
Vue "360°" d'un appareil : rapproche, par NOM d'appareil, l'inventaire/la conformité Intune
et l'inventaire/les alertes Defender for Endpoint — actuellement répartis sur deux onglets
séparés (Intune, Defender) sans aucun lien entre eux, alors que c'est souvent la même
machine physique vue par deux systèmes distincts (demande de Nicolas, 2026-08-18).

Volontairement au niveau racine du backend (ni intune/, ni defender/) : cette fonction est
la SEULE de tout le projet qui dépend des deux domaines à la fois — la loger dans l'un des
deux packages aurait recréé exactement le couplage que le split en sous-modules par domaine
(revue d'architecture du 2026-08-17) visait à éviter. `api_server.py` l'importe directement,
comme il importe déjà `defender.*`/`intune.*`.

Jointure par NOM (`deviceName` Intune / `computerDnsName` Defender), pas par ID au premier
abord : c'est le seul identifiant qu'un utilisateur du dashboard connaît spontanément (il tape
un nom de machine, pas un GUID Intune ou un hash Defender). `intune.devices.get_device` et
`defender.machines.get_machine` savent déjà chercher par nom chacun de leur côté — cette
fonction se contente d'appeler les deux et de fusionner, SANS supposer qu'un appareil existe
dans les deux systèmes.

Repli par identifiant Azure AD (2026-09-02, demande de Nicolas) : sur un appareil mobile, le
nom Intune et le nom Defender peuvent être TOTALEMENT différents, pas juste une casse ou un
suffixe de domaine — confirmé en direct sur le tenant de production ("DEMO-MOB-103" côté
Intune vs "jdupont_Android" côté Defender, même appareil). Si la recherche par nom ne
trouve rien d'UN SEUL côté alors que l'autre a réussi, on retente ce côté manquant avec
l'identifiant Azure AD de celui qui a été trouvé (`azureADDeviceId` Intune ==
`aadDeviceId` Defender) avant de conclure à une absence réelle.
"""
from concurrent.futures import ThreadPoolExecutor

from common.http_client import handle_tool_errors, tool_error
from defender.alerts import get_machine_alerts
from defender.machines import get_machine, list_machines
from defender.vulnerabilities import get_device_vulnerabilities
from intune.apps import get_device_detected_apps
from intune.compliance import get_device_all_policy_statuses, get_device_compliance_status
from intune.devices import get_device, list_devices


def _as_error(payload):
    """Reconnaît une erreur `handle_tool_errors`, qu'elle soit renvoyée nue (fonctions
    annotées `-> dict`, ex. get_device/get_machine) ou dans une liste à un seul élément
    (fonctions annotées `-> list[dict]`, ex. get_device_compliance_status/get_machine_alerts)
    — même contrat que `listPayloadError` côté frontend (useDashboardData.js)."""
    if isinstance(payload, dict) and payload.get("error"):
        return payload
    if isinstance(payload, list) and len(payload) == 1 and isinstance(payload[0], dict) and payload[0].get("error"):
        return payload[0]
    return None


@handle_tool_errors
def get_device_overview(device_name: str) -> dict:
    """Fiche combinée Intune + Defender pour un appareil, recherché par nom (`deviceName`
    côté Intune, `computerDnsName` côté Defender — pas nécessairement identiques à la
    lettre, ex. suffixe de domaine, mais c'est la meilleure clé commune disponible sans
    configuration supplémentaire).

    Renvoie toujours un résultat structuré même si l'appareil n'existe que dans UN des deux
    systèmes (`intune.found`/`defender.found` à `False` dans ce cas) — ce n'est PAS une
    erreur ici (contrairement à `intune.devices.get_device` ou `defender.machines.get_machine`
    appelés seuls, qui renvoient une erreur "NotFound" s'ils ne trouvent rien) : un device
    Defender-only (serveur jamais géré par Intune) ou Intune-only (téléphone jamais onboardé
    MDE) est un résultat parfaitement normal à afficher, pas un échec.
    """
    device_name = (device_name or "").strip()
    if not device_name:
        return tool_error("Nom d'appareil requis", "BadRequest")

    # Phase 1 — recherche par NOM des deux côtés, en parallèle (indépendants l'un de l'autre).
    with ThreadPoolExecutor(max_workers=2) as pool:
        intune_future = pool.submit(lambda: get_device(device_name=device_name))
        defender_future = pool.submit(lambda: get_machine(name=device_name))
        intune_device = intune_future.result()
        defender_machine = defender_future.result()

    intune_err = _as_error(intune_device)
    intune_found = intune_err is None
    defender_err = _as_error(defender_machine)
    defender_found = defender_err is None

    # Phase 2 — repli par identifiant Azure AD (2026-09-02) : UN SEUL côté a échoué par nom
    # alors que l'autre a réussi et porte un identifiant Azure AD exploitable → on retente le
    # côté manquant avec cet identifiant avant de conclure à une absence réelle. Toujours
    # séquentiel après la phase 1 (on a besoin du résultat d'un côté pour retenter l'autre),
    # mais un seul aller-retour HTTP de plus dans le cas où ce repli s'applique — jamais dans
    # le cas courant (nom identique des deux côtés, la grande majorité du parc).
    if not defender_found and intune_found:
        aad_id = intune_device.get("azureADDeviceId")
        if aad_id:
            retry = get_machine(aad_device_id=aad_id)
            retry_err = _as_error(retry)
            if retry_err is None:
                defender_machine, defender_err, defender_found = retry, None, True
    elif not intune_found and defender_found:
        aad_id = defender_machine.get("aadDeviceId")
        if aad_id:
            retry = get_device(azure_ad_device_id=aad_id)
            retry_err = _as_error(retry)
            if retry_err is None:
                intune_device, intune_err, intune_found = retry, None, True

    # Phase 3 — données dépendantes (statuts de conformité / applications détectées / alertes /
    # logiciels vulnérables), une seule fois qu'on sait définitivement quel(s) côté(s) sont
    # trouvés. Toujours en parallèle quand les deux sont trouvés, même raisonnement de latence
    # que l'ancienne version (revue de code du 2026-08-20).
    def _fetch_intune_extra():
        if not intune_found:
            return None, None
        # Onglet "Conformité" de la Vue Appareil 360° (2026-09-02, demande de Nicolas : "je ne
        # vois que la conformité de default de intune je ne vois pas les autres comme dans le
        # device dans intune") — voir intune/compliance.py::get_device_all_policy_statuses
        # pour le bug confirmé sur l'ancien get_device_compliance_status (SANS policy_id) :
        # cette collection Graph ne renvoie plus qu'une politique "Default" générique, quel
        # que soit le device réellement testé.
        fetched = get_device_all_policy_statuses(
            device_id=intune_device["id"],
            device_name=intune_device.get("deviceName") or device_name,
            platform=intune_device.get("operatingSystem"),
        )
        statuses = fetched if _as_error(fetched) is None else None
        # "Applications" de la Vue Appareil 360° (2026-09-02, demande de Nicolas) — voir
        # intune/apps.py::get_device_detected_apps.
        fetched_apps = get_device_detected_apps(device_id=intune_device["id"])
        apps = fetched_apps if _as_error(fetched_apps) is None else None
        return statuses, apps

    def _fetch_defender_extra():
        if not defender_found:
            return None, None
        machine_alerts = get_machine_alerts(machine_id=defender_machine["id"])
        alerts = machine_alerts if _as_error(machine_alerts) is None else None
        # Onglet "Vulnérabilités" de la Vue Appareil 360° (2026-09-02, demande de Nicolas :
        # "je les veux toutes dans un tableau scrollable... comme dans les vuln normal") — voir
        # defender/vulnerabilities.py::get_device_vulnerabilities. Remplace
        # get_device_vulnerable_software (groupé par logiciel, pas assez pour une table de CVE
        # cliquables) comme source de CETTE vue ; l'ancienne fonction reste utilisée telle
        # quelle par Secure Score > "Par criticité", pas touchée.
        fetched_vulns = get_device_vulnerabilities(device_id=defender_machine["id"])
        vulns = fetched_vulns if _as_error(fetched_vulns) is None else None
        return alerts, vulns

    with ThreadPoolExecutor(max_workers=2) as pool:
        intune_extra_future = pool.submit(_fetch_intune_extra)
        defender_extra_future = pool.submit(_fetch_defender_extra)
        compliance_statuses, detected_apps = intune_extra_future.result()
        alerts, vulnerable_software = defender_extra_future.result()

    return {
        "deviceName": device_name,
        "intune": {
            "found": intune_found,
            "device": intune_device if intune_found else None,
            "complianceStatuses": compliance_statuses,
            "detectedApps": detected_apps,
            "error": intune_err["message"] if intune_err else None,
        },
        "defender": {
            "found": defender_found,
            "machine": defender_machine if defender_found else None,
            "alerts": alerts,
            "vulnerabilities": vulnerable_software,
            "error": defender_err["message"] if defender_err else None,
        },
    }


@handle_tool_errors
def get_device_inventory() -> list[dict]:
    """
    Inventaire fleet-wide (2026-09-02, demande de Nicolas — maquette "Inventaire des
    appareils" : "on peut avoir un peu ça aussi... l'inventaire des devices") : fusionne
    `intune.devices.list_devices()` et `defender.machines.list_machines(top=0)` — DEUX appels
    déjà bon marché et déjà en place ailleurs (get_intune_summary/get_defender_summary), un seul
    passage Python pour rapprocher les deux par nom. AUCUN appel par appareil (contrairement à
    `get_device_overview` ci-dessus, qui fait 3-5 appels mais pour UN SEUL device) — c'est ce
    qui rend un inventaire de tout le parc praticable en un seul aller-retour.

    Jointure par NOM en premier lieu, complétée par un 2e passage par identifiant Azure AD
    (2026-09-02, demande de Nicolas) : sur un appareil mobile, `deviceName` (Intune) et
    `computerDnsName` (Defender) peuvent être TOTALEMENT différents — pas juste une casse ou un
    suffixe de domaine, confirmé en direct sur le tenant de production ("DEMO-MOB-103" vs
    "jdupont_Android", même appareil). `azureADDeviceId` (Intune)/`aadDeviceId`
    (Defender) sont déjà présents dans les DEUX listes bon marché ci-dessous — aucun appel
    supplémentaire nécessaire, juste un 2e passage en mémoire pour fusionner les paires
    orphelines de la 1ʳᵉ passe. Un appareil qui ne matche NI par nom NI par identifiant Azure AD
    (cas réel, ex. appareil Defender-only jamais enrôlé Intune) apparaît toujours comme deux
    lignes distinctes plutôt qu'une fusion forcée — signalé, pas caché : chaque ligne porte
    `has_intune`/`has_defender` explicites.
    """
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_intune = pool.submit(list_devices)
        f_defender = pool.submit(list_machines, top=0)
        intune_devices = f_intune.result()
        defender_machines = f_defender.result()

    intune_err = _as_error(intune_devices)
    if intune_err is not None:
        return [intune_err]
    defender_err = _as_error(defender_machines)
    if defender_err is not None:
        return [defender_err]

    by_name: dict[str, dict] = {}
    for d in intune_devices:
        name = (d.get("deviceName") or "").strip()
        if not name:
            continue
        by_name.setdefault(name.lower(), {"name": name})["intune"] = d
    for m in defender_machines:
        name = (m.get("computerDnsName") or "").strip()
        if not name:
            continue
        entry = by_name.setdefault(name.lower(), {"name": name})
        entry.setdefault("name", name)
        entry["defender"] = m

    # 2e passage — réconciliation par identifiant Azure AD (voir docstring) : pour chaque
    # entrée Intune-only issue de la 1ʳᵉ passe, cherche si un appareil Defender-only (sous un
    # AUTRE nom, donc une AUTRE clé de `by_name`) partage le même `azureADDeviceId`/
    # `aadDeviceId`. Si oui, fusionne les deux lignes en une seule et supprime le doublon —
    # sans ça, le même appareil physique apparaîtrait deux fois dans l'inventaire.
    # `list(...)` : snapshot des entrées AVANT la boucle — le corps de la boucle peut retirer
    # une clé de `by_name` (le doublon fusionné), ce qui ferait planter une itération directe
    # sur `by_name.values()` ("dictionary changed size during iteration").
    defender_by_aad = {m["aadDeviceId"].lower(): m for m in defender_machines if m.get("aadDeviceId")}
    for entry in list(by_name.values()):
        if entry.get("defender") is not None:
            continue
        aad_id = (entry.get("intune") or {}).get("azureADDeviceId")
        if not aad_id:
            continue
        defender_match = defender_by_aad.get(aad_id.lower())
        if not defender_match:
            continue
        defender_key = (defender_match.get("computerDnsName") or "").strip().lower()
        if defender_key and by_name.get(defender_key, {}).get("intune") is None:
            by_name.pop(defender_key, None)
        entry["defender"] = defender_match

    results = []
    for entry in by_name.values():
        intune = entry.get("intune")
        defender = entry.get("defender")
        results.append(
            {
                "name": entry["name"],
                "operating_system": (intune or {}).get("operatingSystem") or (defender or {}).get("osPlatform"),
                "user": (intune or {}).get("userDisplayName") or (intune or {}).get("userPrincipalName"),
                "compliance_state": (intune or {}).get("complianceState"),
                "exposure_level": (defender or {}).get("exposureLevel"),
                "health_status": (defender or {}).get("healthStatus"),
                "last_sync_intune": (intune or {}).get("lastSyncDateTime"),
                "last_seen_defender": (defender or {}).get("lastSeen"),
                "has_intune": intune is not None,
                "has_defender": defender is not None,
            }
        )
    return results
