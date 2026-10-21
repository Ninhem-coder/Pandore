"""
Exécution brute de requêtes KQL Advanced Hunting — extrait de `defender/tools.py` à la
revue d'architecture du 2026-08-17 (voir l'en-tête de `defender/machines.py`).

Module minimal et volontairement séparé de `defender/vulnerabilities.py` : `run_hunting_query`
est réutilisé tel quel par `defender/anssi.py` (rapprochement CERT-FR/ANSSI ↔ inventaire
logiciel) en plus des fonctions de `vulnerabilities.py` qui en dépendent — le regrouper avec
l'une ou l'autre aurait créé une dépendance artificielle dans le mauvais sens.
"""
from common.http_client import handle_tool_errors
from defender.client import client


@handle_tool_errors
def run_hunting_query(query: str) -> dict:
    """Exécute une requête KQL Advanced Hunting. Retourne {schema, results, stats}."""
    response = client.post("/api/advancedqueries/run", {"Query": query})
    return {
        "schema": response.get("Schema", []),
        "results": response.get("Results", []),
        "stats": response.get("Stats", {}),
    }
