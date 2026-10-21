"""
Tests du jalon "détection d'activités suspectes sur les postes" côté Pandore : proxy
`vanitas/client.py`, routes `/api/vanitas/suspicious-events*` (`routers/vanitas.py`), gate de
permission du nouveau module "activites_suspectes" (`auth/vanitas_profiles.py`/`auth/__init__.py`)
et route de corrélation Defender native (réutilise `device_overview.get_device_overview`, PAS un
proxy Vanitas).

Même approche que le reste de ce dossier (`test_device_overview.py`) : tests unitaires directs
sur les fonctions Python (client/routes appelées comme de simples fonctions, mocks posés sur les
noms importés DANS le module testé), pas de `TestClient` FastAPI — ce projet n'a jusqu'ici aucun
test HTTP de bout en bout, uniquement des tests de caractérisation sur la logique métier ; les
routes elles-mêmes ne sont que de fines couches d'appel (`Depends(...)` + un relais vers
`vanitas_client`/`device_overview`), testables directement en appelant la fonction de route avec
des arguments construits à la main (`_perm=None`, un `Request` factice pour `request.state.user`).

Lancer depuis backend/ : python -m unittest tests.test_suspicious_activity
ou : python -m unittest discover tests
"""
import types
import unittest
from unittest import mock

import auth
import auth.vanitas_profiles as vanitas_profiles
import routers.vanitas as vanitas_router
import vanitas.client as vanitas_client


def _fake_request(user):
    """`require_vanitas_read/write` et les routes de mutation n'utilisent que
    `request.state.user` — un `SimpleNamespace` imbriqué suffit, pas besoin d'un vrai objet
    `fastapi.Request`."""
    return types.SimpleNamespace(state=types.SimpleNamespace(user=user))


def _admin_user():
    return {"username": "nicolas", "role": "admin", "profile_id": None}


def _viewer_user(profile_id=None):
    return {"username": "vviewer", "role": "viewer", "profile_id": profile_id}


class FakeResponse:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code

    def raise_for_status(self):
        pass

    def json(self):
        return self._json


class FakeHttpClient:
    """Stub minimal de `httpx.Client` — enregistre chaque appel (méthode/chemin/params/json)
    pour assertion, renvoie une `FakeResponse` fixée à l'avance. Même esprit que les mocks de
    `test_device_overview.py`, adapté au fait que `vanitas/client.py` appelle `_get_client()`
    plutôt que les fonctions Graph/MDE directement."""

    def __init__(self, response_json=None):
        self.calls = []
        self.response_json = response_json if response_json is not None else {}

    def get(self, path, params=None, headers=None):
        self.calls.append(("GET", path, params, None, headers))
        return FakeResponse(self.response_json)

    def put(self, path, json=None, headers=None):
        self.calls.append(("PUT", path, None, json, headers))
        return FakeResponse(self.response_json)


# ── vanitas/client.py — proxy vers le serveur Vanitas ──────────────────────────────────────────
class ListSuspiciousEventsTestCase(unittest.TestCase):
    @mock.patch.object(vanitas_client, "_get_client")
    def test_calls_expected_path_with_no_filters(self, mock_get_client):
        fake = FakeHttpClient(response_json=[{"id": "1"}])
        mock_get_client.return_value = fake

        result = vanitas_client.list_suspicious_events()

        self.assertEqual(result, [{"id": "1"}])
        method, path, params, body, headers = fake.calls[0]
        self.assertEqual((method, path), ("GET", "/suspicious-events"))
        self.assertEqual(params, {})

    @mock.patch.object(vanitas_client, "_get_client")
    def test_only_provided_filters_are_forwarded(self, mock_get_client):
        fake = FakeHttpClient(response_json=[])
        mock_get_client.return_value = fake

        vanitas_client.list_suspicious_events(severity="high", status="new")

        _, _, params, _, _ = fake.calls[0]
        self.assertEqual(params, {"severity": "high", "status": "new"})

    @mock.patch.object(vanitas_client, "_get_client")
    def test_invalid_agent_id_is_a_business_error_not_a_crash(self, mock_get_client):
        # `validate_graph_id` lève ValueError, capturée par `@handle_tool_errors` — jamais une
        # exception qui remonte brute jusqu'à l'appelant.
        result = vanitas_client.list_suspicious_events(agent_id="../etc/passwd")

        self.assertTrue(result[0]["error"])
        self.assertEqual(result[0]["type"], "ValueError")
        mock_get_client.assert_not_called()


class GetSuspiciousEventTestCase(unittest.TestCase):
    @mock.patch.object(vanitas_client, "_get_client")
    def test_fetches_detail_by_id(self, mock_get_client):
        fake = FakeHttpClient(response_json={"id": "evt-1", "hostname": "DEMO-WKS-101"})
        mock_get_client.return_value = fake

        result = vanitas_client.get_suspicious_event("evt-1")

        self.assertEqual(result["hostname"], "DEMO-WKS-101")
        self.assertEqual(fake.calls[0][:2], ("GET", "/suspicious-events/evt-1"))

    def test_invalid_id_never_reaches_the_network(self):
        result = vanitas_client.get_suspicious_event("bad/id")
        self.assertTrue(result["error"])


class UpdateSuspiciousEventStatusTestCase(unittest.TestCase):
    @mock.patch.object(vanitas_client, "_get_client")
    def test_puts_status_and_note_with_actor_header(self, mock_get_client):
        fake = FakeHttpClient(response_json={"id": "evt-1", "status": "acknowledged"})
        mock_get_client.return_value = fake

        result = vanitas_client.update_suspicious_event_status(
            "evt-1", status="acknowledged", note="Vu avec l'utilisateur.", actor="nicolas"
        )

        self.assertEqual(result["status"], "acknowledged")
        method, path, _, body, headers = fake.calls[0]
        self.assertEqual((method, path), ("PUT", "/suspicious-events/evt-1"))
        self.assertEqual(body, {"status": "acknowledged", "note": "Vu avec l'utilisateur."})
        self.assertEqual(headers, {"X-Actor": "nicolas"})

    @mock.patch.object(vanitas_client, "_get_client")
    def test_no_actor_means_no_actor_header(self, mock_get_client):
        fake = FakeHttpClient(response_json={"id": "evt-1"})
        mock_get_client.return_value = fake

        vanitas_client.update_suspicious_event_status("evt-1", status="false_positive")

        self.assertEqual(fake.calls[0][4], {})


class GetSuspiciousEventsSummaryTestCase(unittest.TestCase):
    @mock.patch.object(vanitas_client, "_get_client")
    def test_fetches_summary_endpoint(self, mock_get_client):
        fake = FakeHttpClient(response_json={"by_severity": {"low": 1, "med": 2, "high": 0}})
        mock_get_client.return_value = fake

        result = vanitas_client.get_suspicious_events_summary()

        self.assertEqual(result["by_severity"]["med"], 2)
        self.assertEqual(fake.calls[0][:2], ("GET", "/suspicious-events/summary"))


# ── routers/vanitas.py — proxy HTTP (routes appelées directement comme des fonctions) ──────────
class SuspiciousEventsRoutesTestCase(unittest.TestCase):
    @mock.patch.object(vanitas_router.vanitas_client, "list_suspicious_events")
    def test_list_route_forwards_query_params_unchanged(self, mock_list):
        mock_list.return_value = [{"id": "1"}]

        result = vanitas_router.vanitas_suspicious_events(
            agent_id="a1", signal_type="usb", severity="high", status="new", since="2026-09-01", until="2026-09-02"
        )

        self.assertEqual(result, [{"id": "1"}])
        mock_list.assert_called_once_with(
            agent_id="a1",
            signal_type="usb",
            severity="high",
            status="new",
            since="2026-09-01",
            until="2026-09-02",
        )

    @mock.patch.object(vanitas_router.vanitas_client, "get_suspicious_event")
    def test_detail_route_forwards_event_id(self, mock_get):
        mock_get.return_value = {"id": "evt-1"}

        result = vanitas_router.vanitas_suspicious_event_detail(event_id="evt-1")

        self.assertEqual(result["id"], "evt-1")
        mock_get.assert_called_once_with(event_id="evt-1")

    @mock.patch.object(vanitas_router.vanitas_client, "update_suspicious_event_status")
    def test_update_route_reads_actor_from_session(self, mock_update):
        mock_update.return_value = {"id": "evt-1", "status": "escalated"}
        body = vanitas_router.UpdateSuspiciousEventBody(status="escalated", note="Transmis au RSSI.")
        request = _fake_request(_viewer_user("profile-1"))

        result = vanitas_router.vanitas_suspicious_event_update(body, request, event_id="evt-1")

        self.assertEqual(result["status"], "escalated")
        mock_update.assert_called_once_with(
            event_id="evt-1", status="escalated", note="Transmis au RSSI.", actor="vviewer"
        )

    @mock.patch.object(vanitas_router.vanitas_client, "get_suspicious_events_summary")
    def test_summary_route_is_a_plain_relay(self, mock_summary):
        mock_summary.return_value = {"by_severity": {"low": 0, "med": 0, "high": 0}}

        result = vanitas_router.vanitas_suspicious_events_summary()

        self.assertEqual(result["by_severity"]["low"], 0)
        mock_summary.assert_called_once_with()


# ── Route de corrélation Defender — Pandore NATIVE (device_overview.get_device_overview), pas
#    un proxy Vanitas. ─────────────────────────────────────────────────────────────────────────
class SuspiciousEventCorrelationRouteTestCase(unittest.TestCase):
    @mock.patch.object(vanitas_router, "get_device_overview")
    @mock.patch.object(vanitas_router.vanitas_client, "get_suspicious_event")
    def test_correlation_looks_up_device_overview_by_hostname(self, mock_get_event, mock_overview):
        mock_get_event.return_value = {"id": "evt-1", "hostname": "DEMO-WKS-101"}
        mock_overview.return_value = {"deviceName": "DEMO-WKS-101", "defender": {"found": True}}

        result = vanitas_router.vanitas_suspicious_event_correlation(event_id="evt-1")

        self.assertEqual(result["defender"]["found"], True)
        mock_overview.assert_called_once_with(device_name="DEMO-WKS-101")

    @mock.patch.object(vanitas_router, "get_device_overview")
    @mock.patch.object(vanitas_router.vanitas_client, "get_suspicious_event")
    def test_event_lookup_error_short_circuits_before_calling_device_overview(
        self, mock_get_event, mock_overview
    ):
        mock_get_event.return_value = {"error": True, "type": "HTTPStatusError", "message": "L'API a répondu 404."}

        result = vanitas_router.vanitas_suspicious_event_correlation(event_id="missing")

        self.assertTrue(result["error"])
        mock_overview.assert_not_called()


# ── Gate de permission du nouveau module "activites_suspectes" ─────────────────────────────────
class SuspiciousActivityPermissionGateTestCase(unittest.TestCase):
    def setUp(self):
        # `vanitas_profiles` persiste sur disque (JSON) — ces tests créent un profil réel via
        # l'API du module plutôt que de mocker sa résolution interne, pour couvrir aussi
        # `has_access`/`resolved_perms` bout en bout sur le nouveau module. Nettoyé après chaque
        # test pour ne jamais laisser un profil de test dans `data/vanitas_profiles.json`.
        self._created_profile_ids = []

    def tearDown(self):
        for profile_id in self._created_profile_ids:
            try:
                vanitas_profiles.delete_profile(profile_id, assigned_count=0)
            except ValueError:
                pass

    def _make_profile(self, **perms):
        profile = vanitas_profiles.create_profile(
            f"test-activites-suspectes-{len(self._created_profile_ids)}", perms=perms
        )
        self._created_profile_ids.append(profile["id"])
        return profile["id"]

    def test_admin_always_passes_read_and_write(self):
        request = _fake_request(_admin_user())
        auth.require_vanitas_read("activites_suspectes")(request)
        auth.require_vanitas_write("activites_suspectes")(request)  # ne lève pas non plus

    def test_no_profile_is_refused_on_read(self):
        request = _fake_request(_viewer_user(profile_id=None))
        with self.assertRaises(Exception) as ctx:
            auth.require_vanitas_read("activites_suspectes")(request)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_profile_without_the_module_is_refused(self):
        profile_id = self._make_profile(postes="write")  # aucune perm sur activites_suspectes
        request = _fake_request(_viewer_user(profile_id))
        with self.assertRaises(Exception) as ctx:
            auth.require_vanitas_read("activites_suspectes")(request)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_profile_with_read_grants_read_but_not_write(self):
        profile_id = self._make_profile(activites_suspectes="read")
        request = _fake_request(_viewer_user(profile_id))

        auth.require_vanitas_read("activites_suspectes")(request)  # ne lève pas

        with self.assertRaises(Exception) as ctx:
            auth.require_vanitas_write("activites_suspectes")(request)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_profile_with_write_grants_both_read_and_write(self):
        profile_id = self._make_profile(activites_suspectes="write")
        request = _fake_request(_viewer_user(profile_id))

        auth.require_vanitas_read("activites_suspectes")(request)
        auth.require_vanitas_write("activites_suspectes")(request)  # ni l'un ni l'autre ne lève

    def test_module_is_registered_in_the_shared_modules_tuple(self):
        # Garde-fou "3 endroits à synchroniser" (backend + les 2 mappings frontend) — au moins
        # le premier des trois est vérifié ici par un test, pas seulement par relecture.
        self.assertIn("activites_suspectes", vanitas_profiles.MODULES)


if __name__ == "__main__":
    unittest.main()
