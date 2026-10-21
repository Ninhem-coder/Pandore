"""
Serveur MCP Microsoft Defender for Endpoint (stdio) — pour un usage avec Claude Desktop
ou tout autre client MCP, indépendamment du dashboard React/API REST.

Lancer : python -m defender.mcp_server

── Parité avec les modules defender/*.py (revue d'architecture du 2026-08-17) ───────────
`defender/tools.py` (721 lignes, un seul fichier pour machines/alertes/hunting/TVM) a été
scindé en `machines.py`, `alerts.py`, `hunting.py` et `vulnerabilities.py` — fonctions "nues"
réutilisées à la fois ici et par `api_server.py`. L'INTENTION est qu'une fonction ajoutée à
l'un de ces modules soit automatiquement disponible des deux côtés. En pratique, rien ne le
garantissait avant la revue du 2026-08-17 : au 17/08, 7 fonctions ajoutées entre le
2026-08-10 et le 2026-08-17 (get_alert, search_vulnerabilities, get_top_vulnerable_software,
get_expiring_certificates, get_top_active_alerts, get_top_vulnerable_apps_by_exposure,
get_device_vulnerable_software) n'étaient enregistrées que côté API REST, jamais ici —
Claude Desktop n'y avait donc pas accès, sans qu'aucune erreur ni avertissement ne le
signale.

`_TOOLS` liste maintenant EXPLICITEMENT toutes les fonctions enregistrées (au lieu d'un
empilement de `mcp.tool()(...)` sans vue d'ensemble), et `tests/test_mcp_tool_parity.py`
vérifie que chaque fonction publique de ces quatre modules est soit dans `_TOOLS`, soit
dans `EXCLUDED_FROM_MCP` (avec une raison) — pour que le prochain oubli soit détecté par
`python -m unittest discover tests` plutôt que découvert des mois plus tard.
"""
from fastmcp import FastMCP

from defender import alerts, hunting, machines, vulnerabilities

mcp = FastMCP("defender")

# Modules "outils" defender à vérifier pour la parité MCP/REST — voir
# tests/test_mcp_tool_parity.py, qui agrège les fonctions publiques de chacun.
TOOL_MODULES = [machines, alerts, hunting, vulnerabilities]

# Fonctions publiques des modules ci-dessus volontairement absentes de _TOOLS ci-dessous —
# chacune avec sa raison, pour qu'un futur cas particulier soit documenté ici plutôt que
# silencieusement oublié comme les 7 fonctions historiques mentionnées plus haut.
EXCLUDED_FROM_MCP: set[str] = {
    # get_vulnerability_inventory (2026-09-01) : renvoie TOUTES les CVE du parc sans plafond
    # (14 898 mesurées sur le tenant de production) — pensé pour alimenter un tableau
    # scrollable côté web (VulnerabilitiesTab.jsx), pas pour être déversé dans une conversation
    # Claude Desktop. `get_top_vulnerabilities`/`get_top_vulnerable_software` (déjà dans
    # _TOOLS, tous deux bornés par un paramètre `top`) restent la voie conversationnelle pour
    # "quelles sont les CVE/logiciels les plus critiques du parc ?".
    "get_vulnerability_inventory",
}

_TOOLS = [
    machines.get_defender_summary,
    machines.list_machines,
    machines.get_machine,
    alerts.list_alerts,
    alerts.get_machine_alerts,
    alerts.get_alert,
    machines.list_non_onboarded_machines,
    hunting.run_hunting_query,
    vulnerabilities.get_exposure_score,
    vulnerabilities.list_recommendations,
    vulnerabilities.search_vulnerabilities,
    vulnerabilities.get_top_vulnerabilities,
    vulnerabilities.get_top_vulnerable_software,
    vulnerabilities.get_expiring_certificates,
    alerts.get_top_active_alerts,
    vulnerabilities.get_top_vulnerable_apps_by_exposure,
    vulnerabilities.get_device_vulnerable_software,
    vulnerabilities.get_device_vulnerabilities,
]

for _fn in _TOOLS:
    mcp.tool()(_fn)

if __name__ == "__main__":
    mcp.run()
