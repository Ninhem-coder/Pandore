"""
Historique quotidien (common/history.py) — harmonisation du taux de conformité Intune du
2026-10-21 : formule stricte marquée `complianceRateRule`, anciens taux écartés à la lecture,
point du jour partiel retenté. Fichier d'historique redirigé vers un dossier temporaire : le
vrai `data/history.json` n'est jamais touché.

Lancer depuis backend/ : python -m pytest tests/test_history.py
"""
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

from common import history


class HistoryTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "history.json"
        patcher = mock.patch.object(history, "HISTORY_FILE", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def _write(self, entries):
        self.path.write_text(json.dumps(entries), encoding="utf-8")

    def test_old_formula_rate_is_hidden_but_other_fields_kept(self):
        self._write([{"date": "2026-09-22", "intune": {"totalDevices": 999, "nonCompliantCount": 137, "complianceRate": 86.3}}])
        point = history.get_history()[0]["intune"]
        self.assertIsNone(point["complianceRate"])
        self.assertEqual(point["nonCompliantCount"], 137)

    def test_strict_formula_rate_is_kept(self):
        intune = {"totalDevices": 950, "complianceRate": 85.5, "complianceRateRule": history.COMPLIANCE_RATE_RULE}
        self._write([{"date": "2026-10-21", "intune": intune}])
        self.assertEqual(history.get_history()[0]["intune"]["complianceRate"], 85.5)

    def test_file_is_never_rewritten_on_read(self):
        entries = [{"date": "2026-09-22", "intune": {"complianceRate": 86.3}}]
        self._write(entries)
        history.get_history()
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8")), entries)

    def test_partial_snapshot_today_is_not_complete(self):
        today = date.today().isoformat()
        self._write([{"date": today, "intune": None, "defender": None, "vanitas": None}])
        self.assertTrue(history.has_snapshot_today())
        self.assertFalse(history.has_complete_snapshot_today())

    def test_complete_snapshot_without_vanitas(self):
        today = date.today().isoformat()
        self._write([{"date": today, "intune": {"totalDevices": 1}, "defender": {"totalMachines": 1}, "vanitas": None}])
        self.assertTrue(history.has_complete_snapshot_today())


if __name__ == "__main__":
    unittest.main()
