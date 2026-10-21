"""
Tests de caractérisation ajoutés à la revue d'architecture du 2026-08-17.

`intune/tools.py` (depuis découpé en sous-modules par domaine, voir
`intune/compliance.py` et `intune/apps.py`) contient plusieurs fonctions PURES (pas
d'appel réseau, juste de la logique de résolution) qui portent chacune un cas réel
documenté dans leur docstring (le cas DEMO-WKS-102, les compteurs
Secure Boot/BitLocker/isAutopilot du 2026-08-07, etc.) mais qui n'avaient jusqu'ici
AUCUN test : leur seule protection contre une régression était une relecture manuelle
du diff. Ces fonctions concentrent des règles métier tirées d'incidents réels sur le
tenant de production — une régression silencieuse ici reproduirait exactement les bugs
déjà corrigés (catégorie "Inconnu", comptes gonflés, faux "non conforme").

Ce sont des tests de CARACTÉRISATION : ils figent le comportement actuel, documenté par
les commentaires du code, plutôt que d'inventer une spécification indépendante.

Lancer depuis backend/ : python -m unittest tests.test_compliance_logic
ou : python -m unittest discover tests
"""
import unittest

from intune.apps import _normalize_version, _version_is_below
from intune.compliance import (
    _category_from_policy_status,
    _os_from_policy_name,
    _os_from_report,
    _report_status,
    _summary_counts,
    _zip_report,
    _os_from_policy_type,
    _policy_platform,
)


class NormalizeVersionTestCase(unittest.TestCase):
    def test_simple_dotted_version(self):
        self.assertEqual(_normalize_version("7.4.3"), [7, 4, 3])

    def test_hyphen_treated_as_separator(self):
        # Le MCP Node d'origine traite "-" comme un séparateur au même titre que "." —
        # certaines apps versionnent "1.0-2" (build après le tiret).
        self.assertEqual(_normalize_version("1.0-2"), [1, 0, 2])

    def test_non_numeric_segment_becomes_zero(self):
        self.assertEqual(_normalize_version("1.a.3"), [1, 0, 3])

    def test_none_becomes_single_zero(self):
        # (v or "").split(".") sur "" renvoie [""], et int("") lève ValueError -> un seul 0.
        # Contre-intuitif (on pourrait attendre une liste vide) mais c'est le comportement
        # actuel, et _version_is_below ne l'appelle jamais avec version=None (il court-circuite
        # avant via `if not version: return True`) donc ce cas ne s'observe en pratique que
        # côté `target` (version_below="" côté appelant, non atteignable depuis l'API).
        self.assertEqual(_normalize_version(None), [0])

    def test_empty_string_becomes_single_zero(self):
        self.assertEqual(_normalize_version(""), [0])


class VersionIsBelowTestCase(unittest.TestCase):
    """FortiClient < 7.4.3 est l'exemple documenté dans get_app_install_status."""

    def test_unknown_version_is_included(self):
        # Comportement explicitement voulu (commentaire ligne 364) : une version absente
        # est considérée comme potentiellement obsolète, donc incluse dans le résultat.
        self.assertTrue(_version_is_below(None, [7, 4, 3]))
        self.assertTrue(_version_is_below("", [7, 4, 3]))

    def test_strictly_lower_version(self):
        self.assertTrue(_version_is_below("7.4.2", [7, 4, 3]))
        self.assertTrue(_version_is_below("7.3.9", [7, 4, 3]))
        self.assertTrue(_version_is_below("6.9.9", [7, 4, 3]))

    def test_equal_version_is_not_below(self):
        self.assertFalse(_version_is_below("7.4.3", [7, 4, 3]))

    def test_higher_version_is_not_below(self):
        self.assertFalse(_version_is_below("7.4.4", [7, 4, 3]))
        self.assertFalse(_version_is_below("8.0.0", [7, 4, 3]))

    def test_shorter_version_padded_with_zeros(self):
        # "7.4" vs [7, 4, 3] -> le 3e segment manquant vaut 0, donc 7.4 < 7.4.3.
        self.assertTrue(_version_is_below("7.4", [7, 4, 3]))


class ReportParsingTestCase(unittest.TestCase):
    """
    API de rapports Intune (2026-10-21, voir intune/compliance.py) : réponse `Schema`/`Values`
    positionnelle, statut en code numérique. Formes relevées sur le tenant de production.
    """

    def test_zip_report_rebuilds_rows_and_total(self):
        body = {
            "Schema": [{"Column": "DeviceName"}, {"Column": "PolicyStatus"}],
            "Values": [["PC-1", 2], ["PC-2", 4]],
            "TotalRowCount": 2,
        }
        rows, total = _zip_report(body)
        self.assertEqual(rows, [{"DeviceName": "PC-1", "PolicyStatus": 2}, {"DeviceName": "PC-2", "PolicyStatus": 4}])
        self.assertEqual(total, 2)

    def test_zip_report_empty_body(self):
        self.assertEqual(_zip_report({}), ([], None))

    def test_numeric_code_wins(self):
        self.assertEqual(_report_status({"PolicyStatus": 4, "PolicyStatus_loc": "Compliant"}), "nonCompliant")
        self.assertEqual(_report_status({"PolicyStatus": "2"}), "compliant")

    def test_code_zero_is_unknown_not_missing(self):
        self.assertEqual(_report_status({"PolicyStatus": 0, "PolicyStatus_loc": "Compliant"}), "unknown")

    def test_falls_back_to_label(self):
        self.assertEqual(_report_status({"PolicyStatus_loc": "Not applicable"}), "notApplicable")
        self.assertEqual(_report_status({}), "unknown")

    def test_summary_counts_match_overview_keys(self):
        rows = [{"PolicyStatus": c} for c in (2, 2, 3, 4, 5, 6, 1, 0, 7)]
        self.assertEqual(
            _summary_counts(rows),
            {"successCount": 3, "failedCount": 1, "errorCount": 2, "notApplicableCount": 1, "pendingCount": 2},
        )

    def test_os_from_report(self):
        self.assertEqual(_os_from_report("Android (fully managed/dedicated)"), "Android")
        self.assertEqual(_os_from_report("Android (work profile)"), "Android")
        self.assertEqual(_os_from_report("macOS"), "macOS")
        self.assertEqual(_os_from_report("iOS"), "iOS")
        self.assertEqual(_os_from_report("Windows"), "Windows")
        self.assertIsNone(_os_from_report(""))


class OsFromPolicyTypeTestCase(unittest.TestCase):
    def test_windows10_compliance_policy(self):
        self.assertEqual(_os_from_policy_type("#microsoft.graph.windows10CompliancePolicy"), "Windows")

    def test_macos_compliance_policy(self):
        self.assertEqual(_os_from_policy_type("#microsoft.graph.macOSCompliancePolicy"), "macOS")

    def test_android_work_profile_compliance_policy(self):
        self.assertEqual(_os_from_policy_type("#microsoft.graph.androidWorkProfileCompliancePolicy"), "Android")

    def test_unknown_type_returns_none(self):
        self.assertIsNone(_os_from_policy_type("#microsoft.graph.somethingUnrelated"))

    def test_none_returns_none(self):
        self.assertIsNone(_os_from_policy_type(None))


class OsFromPolicyNameTestCase(unittest.TestCase):
    """Repli sur la convention de nommage du tenant, utilisé uniquement quand
    @odata.type est absent (commentaire ligne 497-501)."""

    def test_cns_android_prefix(self):
        self.assertEqual(_os_from_policy_name("[ORG] Android - Sécurité renforcée"), "Android")

    def test_cns_srv_windows_prefix(self):
        self.assertEqual(_os_from_policy_name("[ORG] SRV - Windows - Baseline serveurs"), "Windows")

    def test_no_match_returns_none(self):
        self.assertIsNone(_os_from_policy_name("Politique sans plateforme dans le nom"))

    def test_none_returns_none(self):
        self.assertIsNone(_os_from_policy_name(None))


class PolicyPlatformTestCase(unittest.TestCase):
    def test_odata_type_takes_priority_over_name(self):
        # Le type Graph passe avant le nom même si le nom suggérerait autre chose —
        # commentaire ligne 520 : "son type Graph d'abord, son nom en dernier recours".
        policy = {
            "odataType": "#microsoft.graph.macOSCompliancePolicy",
            "displayName": "[ORG] Android - legacy (nom pas à jour)",
        }
        self.assertEqual(_policy_platform(policy), "macOS")

    def test_falls_back_to_name_when_type_missing(self):
        policy = {"odataType": None, "displayName": "[ORG] iOS - Sécurité"}
        self.assertEqual(_policy_platform(policy), "iOS")

    def test_none_when_neither_resolves(self):
        policy = {"odataType": None, "displayName": "Politique générique"}
        self.assertIsNone(_policy_platform(policy))


class CategoryFromPolicyStatusTestCase(unittest.TestCase):
    """
    Quatre familles distinctes depuis la V13 (commentaire ligne 531-545) : le cas
    DEMO-WKS-102 (2026-08-07) est l'exemple documenté qui a motivé la suppression de la
    table globale complianceState -> catégorie, remplacée par cette résolution PAR POLITIQUE.
    """

    def test_noncompliant_maps_to_non_conforme(self):
        self.assertEqual(_category_from_policy_status("nonCompliant"), "Non conforme")

    def test_error_and_conflict_map_to_erreur(self):
        self.assertEqual(_category_from_policy_status("error"), "Erreur")
        self.assertEqual(_category_from_policy_status("conflict"), "Erreur")

    def test_notapplicable_maps_to_non_applicable(self):
        # Cas DEMO-WKS-102 : notApplicable sur "Check isAutopilot" ne doit jamais
        # retomber dans "Non conforme" à cause d'un état global inGracePeriod ailleurs.
        self.assertEqual(_category_from_policy_status("notApplicable"), "Non applicable")

    def test_unknown_and_notassigned_map_to_en_attente(self):
        self.assertEqual(_category_from_policy_status("unknown"), "En attente")
        self.assertEqual(_category_from_policy_status("notAssigned"), "En attente")

    def test_compliant_and_remediated_map_to_conforme(self):
        self.assertEqual(_category_from_policy_status("compliant"), "Conforme")
        self.assertEqual(_category_from_policy_status("remediated"), "Conforme")

    def test_case_insensitive(self):
        self.assertEqual(_category_from_policy_status("NONCOMPLIANT"), "Non conforme")

    def test_unrecognized_status_defaults_to_erreur(self):
        self.assertEqual(_category_from_policy_status("somethingNew"), "Erreur")

    def test_none_defaults_to_erreur(self):
        self.assertEqual(_category_from_policy_status(None), "Erreur")


if __name__ == "__main__":
    unittest.main()
