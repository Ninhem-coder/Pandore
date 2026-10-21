"""
Tests de device_overview.py — ajoutés lors du traitement du rapport de revue de code du
2026-08-20 (ce module, entièrement nouveau au 2026-08-18, n'avait encore aucun test).

`get_device_overview` orchestre deux appels indépendants (`intune.devices.get_device`,
`defender.machines.get_machine`) qui peuvent chacun : réussir, échouer (erreur réseau/auth),
ou ne rien trouver sans que ce soit une erreur (device Defender-only ou Intune-only, voir le
docstring de la fonction). Ces tests fixent ce contrat via des mocks sur les fonctions
importées dans le module (même approche que test_mcp_tool_parity.py : les fonctions
`get_device`/`get_machine`/... sont importées PAR NOM dans device_overview, donc patchées ici
directement dans son namespace plutôt que dans intune.devices/defender.machines).

⚠️ Revue de bugs du 2026-09-02 : ce fichier patchait encore `get_device_compliance_status`/
`get_device_vulnerable_software` (noms ORIGINAUX au moment où ces tests ont été écrits) alors
que `device_overview.py::get_device_overview` a depuis basculé sur `get_device_all_policy_
statuses`/`get_device_vulnerabilities` (2026-09-02, voir CLAUDE.md — bug du "je ne vois que la
conformité Default" puis remplacement du groupement par logiciel par une table de CVE) SANS que
ces tests ne soient mis à jour en conséquence. Deux effets, tous les deux réels :
1. `mock.patch.object(device_overview, "get_device_compliance_status")`/
   "get_device_vulnerable_software" ne levaient PAS d'`AttributeError` (ces deux noms restent
   importés dans le module pour d'autres usages, voir device_overview.py) mais ne patchaient
   PLUS rien d'utilisé par `get_device_overview` — les tests qui s'appuyaient dessus
   "passaient" en réalité en laissant `get_device_all_policy_statuses`/
   `get_device_detected_apps`/`get_device_vulnerabilities` RÉELS s'exécuter (vrais appels
   réseau Graph/Defender pendant un test censé être unitaire, ~80s pour toute la suite au lieu
   de quelques secondes).
2. `get_device_vulnerable_software`/`get_device_compliance_status` (des noms de fonction
   effectivement retirés/renommés entre-temps dans `intune.compliance`/`defender.
   vulnerabilities`, contrairement à ce que `device_overview.py` importe encore) ont fini par
   disparaître complètement d'un des deux modules source, ce qui a fait échouer 4 tests avec
   `AttributeError: <module 'device_overview'> does not have the attribute
   'get_device_vulnerable_software'` — la seule alerte visible, alors que le problème réel (des
   mocks silencieusement inefficaces) touchait aussi des tests qui ne l'affichaient pas.

Corrigé : tous les mocks visent maintenant les noms RÉELLEMENT appelés par
`get_device_overview` (`get_device_all_policy_statuses`, `get_device_detected_apps`,
`get_device_vulnerabilities`), et CHAQUE test où `intune_found`/`defender_found` peut valoir
`True` mocke bien LES QUATRE fonctions de la phase 3 (compliance/apps côté Intune,
alerts/vulnérabilités côté Defender) — plus aucun test de ce fichier ne doit pouvoir déclencher
un vrai appel réseau.

Lancer depuis backend/ : python -m unittest tests.test_device_overview
ou : python -m unittest discover tests
"""
import unittest
from unittest import mock

import device_overview


def _ok_intune_device(device_id="dev-1", **extra):
    return {"id": device_id, "deviceName": "DEMO-WKS-101", **extra}


def _ok_defender_machine(machine_id="mach-1", **extra):
    return {"id": machine_id, "computerDnsName": "DEMO-WKS-101", **extra}


def _not_found_error():
    # Même forme que intune.devices.get_device / defender.machines.get_machine quand
    # rien ne correspond (tool_error("...", "NotFound"), annotées -> dict donc nues, pas
    # dans une liste à un élément).
    return {"error": True, "type": "NotFound", "message": "Aucun appareil ne correspond."}


def _http_error():
    return {"error": True, "type": "HTTPStatusError", "message": "L'API a répondu 503."}


class GetDeviceOverviewTestCase(unittest.TestCase):
    def test_blank_device_name_is_a_bad_request(self):
        result = device_overview.get_device_overview(device_name="   ")
        self.assertTrue(result["error"])
        self.assertEqual(result["type"], "BadRequest")

    @mock.patch.object(device_overview, "get_device_vulnerabilities")
    @mock.patch.object(device_overview, "get_machine_alerts")
    @mock.patch.object(device_overview, "get_device_detected_apps")
    @mock.patch.object(device_overview, "get_device_all_policy_statuses")
    @mock.patch.object(device_overview, "get_machine")
    @mock.patch.object(device_overview, "get_device")
    def test_found_in_both_systems_merges_everything(
        self, mock_get_device, mock_get_machine, mock_compliance, mock_apps, mock_alerts, mock_vulns
    ):
        mock_get_device.return_value = _ok_intune_device()
        mock_get_machine.return_value = _ok_defender_machine()
        mock_compliance.return_value = [{"policy": "X", "status": "compliant"}]
        mock_apps.return_value = [{"id": "app-1", "displayName": "7-Zip"}]
        mock_alerts.return_value = [{"id": "alert-1"}]
        mock_vulns.return_value = [{"cve_code": "CVE-2026-1"}]

        result = device_overview.get_device_overview(device_name="DEMO-WKS-101")

        self.assertTrue(result["intune"]["found"])
        self.assertEqual(result["intune"]["device"]["id"], "dev-1")
        self.assertEqual(result["intune"]["complianceStatuses"], [{"policy": "X", "status": "compliant"}])
        self.assertEqual(result["intune"]["detectedApps"], [{"id": "app-1", "displayName": "7-Zip"}])
        self.assertIsNone(result["intune"]["error"])

        self.assertTrue(result["defender"]["found"])
        self.assertEqual(result["defender"]["machine"]["id"], "mach-1")
        self.assertEqual(result["defender"]["alerts"], [{"id": "alert-1"}])
        self.assertEqual(result["defender"]["vulnerabilities"], [{"cve_code": "CVE-2026-1"}])
        self.assertIsNone(result["defender"]["error"])

    @mock.patch.object(device_overview, "get_device_detected_apps")
    @mock.patch.object(device_overview, "get_device_all_policy_statuses")
    @mock.patch.object(device_overview, "get_machine")
    @mock.patch.object(device_overview, "get_device")
    def test_intune_only_device_is_not_an_error(self, mock_get_device, mock_get_machine, mock_compliance, mock_apps):
        # Téléphone jamais onboardé MDE : Defender ne trouve rien, ce n'est PAS un échec
        # (docstring de get_device_overview) — juste defender.found=False.
        mock_get_device.return_value = _ok_intune_device()
        mock_get_machine.return_value = _not_found_error()
        mock_compliance.return_value = []
        mock_apps.return_value = []

        result = device_overview.get_device_overview(device_name="PHONE-1")

        self.assertTrue(result["intune"]["found"])
        self.assertFalse(result["defender"]["found"])
        self.assertIsNone(result["defender"]["machine"])
        self.assertEqual(result["defender"]["error"], "Aucun appareil ne correspond.")

    @mock.patch.object(device_overview, "get_device_vulnerabilities")
    @mock.patch.object(device_overview, "get_machine_alerts")
    @mock.patch.object(device_overview, "get_machine")
    @mock.patch.object(device_overview, "get_device")
    def test_defender_only_device_is_not_an_error(
        self, mock_get_device, mock_get_machine, mock_alerts, mock_vulns
    ):
        # Serveur jamais géré par Intune : symétrique du cas précédent — intune_found=False,
        # donc get_device_all_policy_statuses/get_device_detected_apps ne sont jamais appelées
        # (voir `_fetch_intune_extra`), pas besoin de les mocker ici.
        mock_get_device.return_value = _not_found_error()
        mock_get_machine.return_value = _ok_defender_machine()
        mock_alerts.return_value = []
        mock_vulns.return_value = []

        result = device_overview.get_device_overview(device_name="SRV-1")

        self.assertFalse(result["intune"]["found"])
        self.assertIsNone(result["intune"]["device"])
        self.assertEqual(result["intune"]["error"], "Aucun appareil ne correspond.")
        self.assertTrue(result["defender"]["found"])

    @mock.patch.object(device_overview, "get_machine")
    @mock.patch.object(device_overview, "get_device")
    def test_not_found_anywhere_is_not_an_error_either(self, mock_get_device, mock_get_machine):
        mock_get_device.return_value = _not_found_error()
        mock_get_machine.return_value = _not_found_error()

        result = device_overview.get_device_overview(device_name="INTROUVABLE")

        self.assertFalse(result["intune"]["found"])
        self.assertFalse(result["defender"]["found"])
        # get_device_overview lui-même ne renvoie jamais d'erreur top-level dans ce cas :
        # c'est un résultat structuré "rien trouvé nulle part", à afficher tel quel.
        self.assertNotIn("error", result)

    @mock.patch.object(device_overview, "get_device_detected_apps")
    @mock.patch.object(device_overview, "get_device_all_policy_statuses")
    @mock.patch.object(device_overview, "get_machine")
    @mock.patch.object(device_overview, "get_device")
    def test_ambiguous_intune_match_propagates_through_unchanged(
        self, mock_get_device, mock_get_machine, mock_compliance, mock_apps
    ):
        # intune.devices.get_device signale un match ambigu (résolution insensible à la
        # casse, plusieurs candidats) via `ambiguousMatches` dans le dict device — cette
        # fonction ne doit ni le perdre ni le réinterpréter, juste le laisser passer.
        mock_get_device.return_value = _ok_intune_device(ambiguousMatches=2)
        mock_get_machine.return_value = _not_found_error()
        mock_compliance.return_value = []
        mock_apps.return_value = []

        result = device_overview.get_device_overview(device_name="amw-wks-ein-1")

        self.assertTrue(result["intune"]["found"])
        self.assertEqual(result["intune"]["device"]["ambiguousMatches"], 2)

    @mock.patch.object(device_overview, "get_device_detected_apps")
    @mock.patch.object(device_overview, "get_device_all_policy_statuses")
    @mock.patch.object(device_overview, "get_machine")
    @mock.patch.object(device_overview, "get_device")
    def test_compliance_fetch_failure_does_not_fail_whole_intune_side(
        self, mock_get_device, mock_get_machine, mock_compliance, mock_apps
    ):
        # get_device réussit mais l'appel de conformité suivant échoue (ex. Graph
        # indisponible) : intune.found doit rester True (l'appareil EXISTE), seul
        # complianceStatuses retombe à None plutôt que de faire échouer toute la vue.
        mock_get_device.return_value = _ok_intune_device()
        mock_get_machine.return_value = _not_found_error()
        mock_compliance.return_value = [_http_error()]  # liste à un élément (-> list[dict])
        mock_apps.return_value = []

        result = device_overview.get_device_overview(device_name="DEMO-WKS-101")

        self.assertTrue(result["intune"]["found"])
        self.assertIsNone(result["intune"]["complianceStatuses"])
        self.assertIsNone(result["intune"]["error"])  # l'erreur ne concerne que le sous-appel

    @mock.patch.object(device_overview, "get_device_vulnerabilities")
    @mock.patch.object(device_overview, "get_machine_alerts")
    @mock.patch.object(device_overview, "get_machine")
    @mock.patch.object(device_overview, "get_device")
    def test_alerts_and_vulns_failures_do_not_fail_whole_defender_side(
        self, mock_get_device, mock_get_machine, mock_alerts, mock_vulns
    ):
        mock_get_device.return_value = _not_found_error()
        mock_get_machine.return_value = _ok_defender_machine()
        mock_alerts.return_value = [_http_error()]
        mock_vulns.return_value = [_http_error()]

        result = device_overview.get_device_overview(device_name="SRV-1")

        self.assertTrue(result["defender"]["found"])
        self.assertIsNone(result["defender"]["alerts"])
        self.assertIsNone(result["defender"]["vulnerabilities"])
        self.assertIsNone(result["defender"]["error"])


if __name__ == "__main__":
    unittest.main()
