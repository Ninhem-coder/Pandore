"""
Garde-fou ajouté à la revue d'architecture du 2026-08-17, complété à la deuxième passe
(découpage de `defender/tools.py` et `intune/tools.py` en sous-modules par domaine — voir
les en-têtes de `defender/mcp_server.py` et `intune/mcp_server.py`) : les fonctions "nues"
qui composent chaque package sont réutilisées à la fois par l'API REST (api_server.py) et
par les serveurs MCP stdio (defender/mcp_server.py, intune/mcp_server.py). Rien n'impose
que les deux façades restent synchronisées : à la revue initiale, 7 fonctions Defender et 1
fonction Intune (get_compliance_detail) ajoutées côté REST n'avaient jamais été
enregistrées côté MCP, sans qu'aucune erreur ne le signale — Claude Desktop n'y avait tout
simplement pas accès.

Ce test échoue si une fonction publique de l'un des modules listés dans `TOOL_MODULES` du
mcp_server correspondant (pas de préfixe "_", définie dans ce module et pas juste importée
depuis common/http_client) n'est ni enregistrée dans `_TOOLS`, ni listée dans son
`EXCLUDED_FROM_MCP` (avec une raison) — pour qu'un futur oubli soit détecté ici plutôt que
découvert des mois plus tard.

Lancer depuis backend/ : python -m unittest tests.test_mcp_tool_parity
ou : python -m unittest discover tests
"""
import inspect
import unittest

from defender import mcp_server as defender_mcp_server
from intune import mcp_server as intune_mcp_server


def _public_tool_functions(module):
    """Fonctions publiques DÉFINIES dans `module` (pas simplement importées dans son
    namespace, ex. escape_odata_string/handle_tool_errors/tool_error/validate_graph_id
    importés depuis common.http_client dans chaque sous-module defender/*.py et
    intune/*.py)."""
    return {
        name: fn
        for name, fn in vars(module).items()
        if inspect.isfunction(fn) and not name.startswith("_") and fn.__module__ == module.__name__
    }


def _public_tool_functions_all(modules):
    """Union des fonctions publiques de plusieurs sous-modules (un package = plusieurs
    fichiers depuis le découpage par domaine, voir TOOL_MODULES de chaque mcp_server)."""
    merged: dict = {}
    for module in modules:
        merged.update(_public_tool_functions(module))
    return merged


class McpToolParityTestCase(unittest.TestCase):
    def _assert_parity(self, tool_modules, mcp_server_module, label):
        public_functions = _public_tool_functions_all(tool_modules)
        registered_names = {fn.__name__ for fn in mcp_server_module._TOOLS}
        excluded_names = mcp_server_module.EXCLUDED_FROM_MCP

        unaccounted = set(public_functions) - registered_names - excluded_names
        self.assertEqual(
            unaccounted,
            set(),
            f"{label} : fonction(s) publique(s) d'un sous-module ni enregistrée(s) dans "
            f"_TOOLS ni listée(s) dans EXCLUDED_FROM_MCP : {sorted(unaccounted)} — "
            f"soit les enregistrer dans {mcp_server_module.__name__}, soit les ajouter "
            f"explicitement à EXCLUDED_FROM_MCP avec une raison en commentaire.",
        )

        # Contrôle inverse : un nom enregistré dans _TOOLS qui ne correspond à AUCUNE
        # fonction publique des sous-modules signalerait une faute de frappe ou une
        # fonction renommée/supprimée dont l'enregistrement n'a pas suivi.
        stale = registered_names - set(public_functions)
        self.assertEqual(
            stale,
            set(),
            f"{label} : _TOOLS référence des fonctions absentes des sous-modules "
            f"(renommées ou supprimées sans mettre à jour l'enregistrement MCP) : {sorted(stale)}",
        )

    def test_defender_parity(self):
        self._assert_parity(defender_mcp_server.TOOL_MODULES, defender_mcp_server, "defender")

    def test_intune_parity(self):
        self._assert_parity(intune_mcp_server.TOOL_MODULES, intune_mcp_server, "intune")


if __name__ == "__main__":
    unittest.main()
