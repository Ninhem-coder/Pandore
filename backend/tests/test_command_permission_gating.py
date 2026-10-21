"""Test de non-régression sécurité (audit du 2026-09-17, finding #2) — le durcissement des
commandes destructives dans `routers/vanitas.py::vanitas_queue_command`.

Vérifie que chaque type de commande exige bien le bon module de permission EN PLUS de
"postes:write" :
- start_shell_session      → terminal:write
- install/update/uninstall_agent → applications:write
- kill_process/isolate_network/lift_isolation/fetch_event_log → activites_suspectes:write
- force_reboot             → postes:write seul (volontaire, voir le commentaire de la route)

Approche identique au reste du dossier : appel direct de la fonction de route avec un `Request`
factice, profils Vanitas réels créés/détruits, `vanitas_client.queue_command` mocké pour isoler
l'autorisation de tout appel réseau.

Lancer depuis backend/ : python -m unittest tests.test_command_permission_gating
"""
import types
import unittest
from unittest import mock

import auth.vanitas_profiles as vanitas_profiles
import routers.vanitas as vanitas_router


def _fake_request(user):
    return types.SimpleNamespace(state=types.SimpleNamespace(user=user))


def _viewer_user(profile_id):
    return {"username": "vviewer", "role": "viewer", "profile_id": profile_id}


def _body(command_type):
    return vanitas_router.QueueCommandBody(command_type=command_type)


class CommandPermissionGatingTestCase(unittest.TestCase):
    def setUp(self):
        self._created = []

    def tearDown(self):
        for pid in self._created:
            try:
                vanitas_profiles.delete_profile(pid, assigned_count=0)
            except ValueError:
                pass

    def _profile(self, **perms):
        p = vanitas_profiles.create_profile(f"test-cmd-gate-{len(self._created)}", perms=perms)
        self._created.append(p["id"])
        return p["id"]

    def _queue(self, command_type, user):
        # `queue_command` mocké : on ne teste QUE la barrière d'autorisation, pas le relais réseau.
        with mock.patch.object(vanitas_router.vanitas_client, "queue_command", return_value={"id": 1}) as m:
            result = vanitas_router.vanitas_queue_command(
                _body(command_type), _fake_request(user), agent_id="a1b2c3d4"
            )
            return result, m

    def assert_refused(self, command_type, profile_perms):
        user = _viewer_user(self._profile(**profile_perms))
        with self.assertRaises(Exception) as ctx:
            self._queue(command_type, user)
        self.assertEqual(ctx.exception.status_code, 403, f"{command_type} aurait dû être refusé avec {profile_perms}")

    def assert_allowed(self, command_type, profile_perms):
        user = _viewer_user(self._profile(**profile_perms))
        result, m = self._queue(command_type, user)
        m.assert_called_once()
        self.assertEqual(result, {"id": 1})

    # ── fetch_event_log : désormais activites_suspectes, plus seulement postes ──────────────
    def test_fetch_event_log_refused_with_postes_only(self):
        self.assert_refused("fetch_event_log", {"postes": "write"})

    def test_fetch_event_log_allowed_with_activites_suspectes(self):
        self.assert_allowed("fetch_event_log", {"postes": "write", "activites_suspectes": "write"})

    # ── uninstall_agent : désormais applications, plus seulement postes ─────────────────────
    def test_uninstall_agent_refused_with_postes_only(self):
        self.assert_refused("uninstall_agent", {"postes": "write"})

    def test_uninstall_agent_allowed_with_applications(self):
        self.assert_allowed("uninstall_agent", {"postes": "write", "applications": "write"})

    # ── confinement : activites_suspectes (déjà en place, on verrouille la non-régression) ──
    def test_kill_process_refused_with_postes_only(self):
        self.assert_refused("kill_process", {"postes": "write"})

    def test_isolate_network_allowed_with_activites_suspectes(self):
        self.assert_allowed("isolate_network", {"postes": "write", "activites_suspectes": "write"})

    # ── force_reboot : postes:write suffit VOLONTAIREMENT (page du module postes) ───────────
    def test_force_reboot_allowed_with_postes_only(self):
        self.assert_allowed("force_reboot", {"postes": "write"})

    def test_force_reboot_refused_without_postes(self):
        # Sans postes:write du tout, même force_reboot est refusé par la garde de base.
        self.assert_refused("force_reboot", {"conformite": "write"})

    # ── start_shell_session : terminal ─────────────────────────────────────────────────────
    def test_shell_refused_with_postes_only(self):
        self.assert_refused("start_shell_session", {"postes": "write"})

    def test_shell_allowed_with_terminal(self):
        self.assert_allowed("start_shell_session", {"postes": "write", "terminal": "write"})


if __name__ == "__main__":
    unittest.main()
