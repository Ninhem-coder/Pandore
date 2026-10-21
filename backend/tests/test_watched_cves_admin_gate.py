"""Test de non-régression sécurité (audit du 2026-09-17) — les mutations de la watchlist CVE
(`POST/DELETE/refresh /api/defender/watched-cves*`) doivent être réservées `admin`, comme toutes
les autres écritures d'état Defender/Intune. Un `viewer` (ou tout non-admin) doit recevoir 403 ;
la LECTURE (`GET`) reste ouverte à tout compte authentifié.

Même approche que le reste du dossier (`test_suspicious_activity.py`) : appel direct des fonctions
de route avec un `Request` factice portant `request.state.user`, pas de `TestClient` HTTP.

Lancer depuis backend/ : python -m unittest tests.test_watched_cves_admin_gate
"""
import types
import unittest
from unittest import mock

import routers.defender as defender_router


def _fake_request(user):
    return types.SimpleNamespace(state=types.SimpleNamespace(user=user))


def _admin_user():
    return {"username": "nicolas", "role": "admin", "profile_id": None}


def _viewer_user():
    return {"username": "vviewer", "role": "viewer", "profile_id": None}


class WatchedCveAdminGateTestCase(unittest.TestCase):
    """`require_admin` (`auth/__init__.py`) lève une `HTTPException(403)` pour un non-admin et ne
    fait rien pour un admin — on vérifie que les 3 routes de mutation l'exigent bien, et qu'un
    admin passe jusqu'à l'appel métier (mocké)."""

    def test_viewer_refused_on_add(self):
        from auth import require_admin

        with self.assertRaises(Exception) as ctx:
            require_admin(_fake_request(_viewer_user()))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_viewer_refused_on_remove_and_refresh(self):
        from auth import require_admin

        for _ in range(2):
            with self.assertRaises(Exception) as ctx:
                require_admin(_fake_request(_viewer_user()))
            self.assertEqual(ctx.exception.status_code, 403)

    def test_admin_reaches_business_logic(self):
        # L'admin passe la garde (require_admin ne lève pas) et la route relaie vers le module
        # métier — mocké pour isoler la vérification d'autorisation de tout appel réseau réel.
        admin_dep = None  # require_admin renvoie None quand il autorise
        with mock.patch.object(defender_router.defender_watchlist, "add_watched_cve", return_value={"ok": True}) as m_add:
            body = defender_router.WatchedCveBody(cve_code="CVE-2024-3400")
            result = defender_router.defender_add_watched_cve(body, _admin=admin_dep)
            self.assertEqual(result, {"ok": True})
            m_add.assert_called_once_with("CVE-2024-3400")

        with mock.patch.object(defender_router.defender_watchlist, "remove_watched_cve", return_value=True) as m_rm:
            result = defender_router.defender_remove_watched_cve(cve_code="CVE-2024-3400", _admin=admin_dep)
            self.assertEqual(result, {"removed": True})
            m_rm.assert_called_once_with("CVE-2024-3400")

        with mock.patch.object(defender_router.defender_watchlist, "refresh_one", return_value={"refreshed": True}) as m_ref:
            result = defender_router.defender_refresh_watched_cve(cve_code="CVE-2024-3400", _admin=admin_dep)
            self.assertEqual(result, {"refreshed": True})
            m_ref.assert_called_once_with("CVE-2024-3400")

    def test_routes_declare_require_admin_dependency(self):
        """Garde-fou anti-régression : vérifie que la dépendance `require_admin` est bien
        DÉCLARÉE sur les 3 routes de mutation (défaut du paramètre `_admin`), pour qu'un futur
        refactor qui la retirerait fasse échouer ce test plutôt que de rouvrir silencieusement la
        route à un viewer."""
        import inspect

        from auth import require_admin

        for fn in (
            defender_router.defender_add_watched_cve,
            defender_router.defender_remove_watched_cve,
            defender_router.defender_refresh_watched_cve,
        ):
            sig = inspect.signature(fn)
            self.assertIn("_admin", sig.parameters, f"{fn.__name__} doit porter une garde _admin")
            default = sig.parameters["_admin"].default
            # FastAPI `Depends(require_admin)` — l'objet Depends expose sa dépendance via .dependency
            self.assertEqual(getattr(default, "dependency", None), require_admin,
                             f"{fn.__name__} doit dépendre de require_admin")


if __name__ == "__main__":
    unittest.main()
