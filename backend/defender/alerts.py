"""
Alertes Microsoft Defender for Endpoint — extrait de `defender/tools.py` à la revue
d'architecture du 2026-08-17 (voir l'en-tête de `defender/machines.py` pour le contexte
complet du découpage).
"""
from datetime import datetime, timedelta, timezone

from common.http_client import escape_odata_string, handle_tool_errors, validate_graph_id
from defender.client import client

_SEVERITY_ORDER_ALERT = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}


@handle_tool_errors
def list_alerts(severity: str | None = None, status: str | None = None, top: int = 50) -> list[dict]:
    """Alertes MDE, filtrables par sévérité (High/Medium/Low/Informational) et statut."""
    filters = []
    if severity:
        filters.append(f"severity eq '{escape_odata_string(severity)}'")
    if status:
        filters.append(f"status eq '{escape_odata_string(status)}'")

    params: dict = {"$top": top, "$orderby": "alertCreationTime desc"}
    if filters:
        params["$filter"] = " and ".join(filters)

    data = client.get("/api/alerts", params=params)
    return data.get("value", [])


@handle_tool_errors
def get_machine_alerts(machine_id: str) -> list[dict]:
    """Alertes associées à une machine spécifique."""
    validate_graph_id(machine_id, "machine_id")
    data = client.get(f"/api/machines/{machine_id}/alerts")
    return data.get("value", [])


@handle_tool_errors
def get_alert(alert_id: str) -> dict:
    """Détail complet d'une alerte MDE (2026-08-17, V43 — demande Nicolas : voir le détail
    d'une alerte depuis le dashboard, pas seulement la ligne résumée de /api/alerts).

    Port direct de "Get alert information by ID" (learn.microsoft.com/defender-endpoint/
    api/get-alert-info-by-id) : GET /api/alerts/{id}, permission requise Alert.ReadWrite.All
    côté MDE (contrairement à la liste, qui accepte Alert.Read.All OU Alert.ReadWrite.All —
    le détail par ID n'accepte QUE ReadWrite, donc pas de nouveau gap de permission si
    Alert.ReadWrite.All est déjà accordé pour la liste).

    Contient, en plus des champs déjà renvoyés par list_alerts : `evidence` (liste des
    entités impliquées — fichiers/process/utilisateurs/IP/URL avec leurs attributs propres),
    `comments` (annotations d'analyste : comment/createdBy/createdTime), `mitreTechniques`,
    `determination`, `investigationState`, `relatedUser`.

    `validate_graph_id` (2026-09-02, revue de sécurité — alignement avec le reste du module :
    c'était la seule fonction de ce fichier à valider l'ID différemment, via
    `urllib.parse.quote` seul) : pas exploitable en pratique (l'encodage neutralisait déjà tout
    risque de changer de segment d'URL via `/`/`..`), mais `validate_graph_id` est le même
    garde-fou que `get_machine_alerts` juste au-dessus et que le reste du backend — un appel
    direct depuis la couche MCP (qui ne repasse pas par la validation `IdPath` de la route
    REST) profite ainsi de la même vérification de format que partout ailleurs.
    """
    validate_graph_id(alert_id, "alert_id")
    return client.get(f"/api/alerts/{alert_id}")


@handle_tool_errors
def get_top_active_alerts(days: int = 7, top: int = 10) -> list[dict]:
    """
    Adaptation du widget "Top impactful events" du dashboard natif MDVM
    (tvm-dashboard-insights) : Microsoft l'alimente d'une timeline d'événements TVM
    dédiée (nouvelle vulnérabilité détectée, nouvel exploit public, etc.), sans équivalent
    documenté dans l'API MDE publique utilisée ici. Adapté sur la donnée déjà consommée
    ailleurs dans ce dashboard (RiskDevicesList, Vue d'ensemble) : les alertes MDE des
    `days` derniers jours (/api/alerts), regroupées par titre et classées par nombre de
    devices distincts touchés — même esprit ("quel évènement a le plus d'impact ?") mais
    PAS une reproduction exacte du widget Microsoft, qui couvre des événements de type
    vulnérabilité, pas des alertes de sécurité générales.
    """
    safe_top = max(1, min(int(top), 50))
    since = (datetime.now(timezone.utc) - timedelta(days=max(1, int(days)))).strftime("%Y-%m-%dT%H:%M:%SZ")
    alerts = client.get_all_pages("/api/alerts", params={"$filter": f"alertCreationTime ge {since}"})

    groups: dict = {}
    for a in alerts:
        title = a.get("title") or "Alerte sans titre"
        group = groups.setdefault(
            title,
            {"severity": a.get("severity"), "category": a.get("category"), "machine_ids": set(), "alert_count": 0},
        )
        group["alert_count"] += 1
        machine_id = a.get("machineId")
        if machine_id:
            group["machine_ids"].add(machine_id)
        if _SEVERITY_ORDER_ALERT.get(a.get("severity"), 0) > _SEVERITY_ORDER_ALERT.get(group["severity"], 0):
            group["severity"] = a.get("severity")

    ranked = sorted(groups.items(), key=lambda kv: len(kv[1]["machine_ids"]), reverse=True)[:safe_top]
    return [
        {
            "title": title,
            "severity": g["severity"],
            "category": g["category"],
            "device_count": len(g["machine_ids"]),
            "alert_count": g["alert_count"],
        }
        for title, g in ranked
    ]
