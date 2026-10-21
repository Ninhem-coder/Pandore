"""
Serveur MCP Intune (stdio, Python) — remplace le MCP Node.js d'origine pour repartir
sur une base 100% Python, même comportement fonctionnel.

Lancer : python -m intune.mcp_server

── Découpage par domaine (revue d'architecture du 2026-08-17, deuxième passe) ──────────
`intune/tools.py` (1373 lignes) a été supprimé et éclaté en sous-modules par domaine :
`devices.py`, `compliance.py`, `compliance_detail.py`, `apps.py`, `users.py`,
`secure_score.py` (liste : `TOOL_MODULES` ci-dessous). `_TOOLS` liste explicitement
toutes les fonctions enregistrées, et `tests/test_mcp_tool_parity.py` vérifie que chaque
fonction publique de ces modules est soit dans `_TOOLS`, soit dans `EXCLUDED_FROM_MCP`
(avec une raison), pour qu'un futur oubli soit détecté par
`python -m unittest discover tests` plutôt que découvert des mois plus tard.
"""
from fastmcp import FastMCP

from intune import app_library, apps, compliance, compliance_detail, devices, secure_score, users

mcp = FastMCP("intune")

TOOL_MODULES = [devices, compliance, compliance_detail, apps, users, secure_score, app_library]

# Fonctions publiques des modules ci-dessus volontairement absentes de _TOOLS.
# `app_library.add_packaged_app`/`repackage_library_app` (2026-08-26) : prennent un `job_id` de
# l'assistant de packaging web (état éphémère du wizard, backend/.packaging_workdir/) — sans
# équivalent dans une conversation Claude Desktop, ce paramètre n'aurait aucune valeur valide à
# donner via MCP.
# `app_library.library_deliverable_path` : renvoie un `Path` (utilisée par la route de
# téléchargement pour construire une réponse fichier), pas un dict compatible outil MCP.
# `app_library.check_for_updates` (2026-08-27) : mute potentiellement PLUSIEURS entrées en une
# seule fois (repackaging réel, remplacement de livrable) sans confirmation par entrée — cadrée
# explicitement avec Nicolas comme un bouton manuel du dashboard web, pas une action à
# déclencher en conversation Claude Desktop pour l'instant.
EXCLUDED_FROM_MCP: set[str] = {
    "add_packaged_app",
    "repackage_library_app",
    "library_deliverable_path",
    "check_for_updates",
    # Brique interne (2026-10-21) : lignes BRUTES des rapports de conformité, partagées par
    # get_compliance_policy_summary/get_compliance_detail — déjà exposées sous forme exploitable
    # par ces deux outils, pas de sens à donner les ~8 000 lignes positionnelles telles quelles.
    "get_policy_report_rows",
}

_TOOLS = [
    devices.list_devices,
    devices.get_device,
    compliance.list_non_compliant_devices,
    compliance.get_compliance_policies,
    compliance.get_compliance_policy_summary,
    devices.get_configuration_profiles,
    apps.list_apps,
    apps.get_apps_catalog,
    compliance.get_device_compliance_status,
    users.list_users,
    devices.get_intune_summary,
    apps.get_discovered_apps,
    apps.get_discovered_app_devices,
    apps.get_device_detected_apps,
    apps.get_app_assignments,
    apps.get_app_install_status,
    apps.get_apps_install_summary,
    compliance.get_policy_device_statuses,
    compliance.get_device_all_policy_statuses,
    compliance_detail.get_compliance_detail,
    secure_score.get_secure_score,
    secure_score.list_secure_score_control_profiles,
    # Bibliothèque d'applications (2026-08-26) — voir intune/app_library.py.
    app_library.list_library_apps,
    app_library.add_manual_app,
    app_library.update_library_app,
    app_library.remove_library_app,
]

for _fn in _TOOLS:
    mcp.tool()(_fn)

if __name__ == "__main__":
    mcp.run()
