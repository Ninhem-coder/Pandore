"""Activités suspectes — jalon détection comportementale.

Couvre : l'ingestion batch côté agent (statut par défaut "new"), l'idempotence sur
`(agent_id, local_event_id)` (rejouer le même lot après un timeout réseau ne duplique rien),
les transitions de statut de triage (valides acceptées, invalides rejetées en 400), l'exclusion
de la purge de rétention (même traitement que `shell_sessions`), et le jeu de règles par défaut
servi tel quel à l'agent.

Les routes AGENT sont protégées par mTLS (`get_current_agent`, CN du certificat) — pas testable
via `TestClient` sans un vrai handshake TLS (voir `test_enrollment.py`), donc surchargée ici via
`app.dependency_overrides`, même mécanisme que `get_db` dans `conftest.py`. Un double léger
(`_FakeAgent`) est renvoyé plutôt que l'objet ORM lui-même, pour ne dépendre d'aucune session
SQLAlchemy particulière dans la fonction de substitution.
"""
from datetime import datetime

from app import models
from app.main import app
from app.security import get_current_agent


def _dt(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


class _FakeAgent:
    def __init__(self, id: str, hostname: str):
        self.id = id
        self.hostname = hostname


def _agent(db, hostname="PC-TEST"):
    a = models.Agent(hostname=hostname)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _authenticate_as(agent) -> None:
    app.dependency_overrides[get_current_agent] = lambda: _FakeAgent(agent.id, agent.hostname)


EVENT = {
    "local_event_id": "11111111-1111-1111-1111-111111111111",
    "occurred_at": "2026-09-14T10:32:11Z",
    "signal_type": "process",
    "severity": "high",
    "matched_rule": "process-lolbin-certutil-decode",
    "summary": "certutil.exe -decode invoqué depuis %TEMP%",
    "detail": {"command_line": "certutil.exe -decode a.txt b.exe", "pid": 4242},
}


class TestIngestion:
    def test_batch_is_inserted_with_default_status_new(self, client, db):
        agent = _agent(db)
        _authenticate_as(agent)

        r = client.post(f"/agents/{agent.id}/suspicious-events", json={"events": [EVENT]})
        assert r.status_code == 200
        assert r.json() == {"ok": True, "inserted": 1, "skipped": 0}

        rows = db.query(models.SuspiciousEvent).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.agent_id == agent.id
        assert row.hostname == agent.hostname  # dénormalisé à l'ingestion
        assert row.status == "new"
        assert row.signal_type == "process"
        assert row.severity == "high"
        assert row.matched_rule == "process-lolbin-certutil-decode"
        assert row.local_event_id == EVENT["local_event_id"]

    def test_wrong_agent_id_in_path_rejected(self, client, db):
        agent = _agent(db)
        other = _agent(db, hostname="PC-AUTRE")
        _authenticate_as(agent)

        r = client.post(f"/agents/{other.id}/suspicious-events", json={"events": [EVENT]})
        assert r.status_code == 403

    def test_empty_batch_ok(self, client, db):
        agent = _agent(db)
        _authenticate_as(agent)

        r = client.post(f"/agents/{agent.id}/suspicious-events", json={"events": []})
        assert r.status_code == 200
        assert r.json() == {"ok": True, "inserted": 0, "skipped": 0}


class TestIdempotence:
    def test_replay_same_local_event_id_does_not_duplicate(self, client, db):
        agent = _agent(db)
        _authenticate_as(agent)

        first = client.post(f"/agents/{agent.id}/suspicious-events", json={"events": [EVENT]})
        assert first.json()["inserted"] == 1

        # Rejeu exact du même lot (timeout réseau côté agent avant réception du 2xx) — skip
        # silencieux, jamais une erreur 409.
        second = client.post(f"/agents/{agent.id}/suspicious-events", json={"events": [EVENT]})
        assert second.status_code == 200
        assert second.json() == {"ok": True, "inserted": 0, "skipped": 1}

        assert db.query(models.SuspiciousEvent).count() == 1

    def test_same_local_event_id_different_agent_is_not_a_duplicate(self, client, db):
        agent_a = _agent(db, "PC-A")
        agent_b = _agent(db, "PC-B")

        _authenticate_as(agent_a)
        client.post(f"/agents/{agent_a.id}/suspicious-events", json={"events": [EVENT]})

        _authenticate_as(agent_b)
        r = client.post(f"/agents/{agent_b.id}/suspicious-events", json={"events": [EVENT]})
        assert r.json() == {"ok": True, "inserted": 1, "skipped": 0}

        assert db.query(models.SuspiciousEvent).count() == 2

    def test_duplicate_within_same_batch_inserted_once(self, client, db):
        agent = _agent(db)
        _authenticate_as(agent)

        r = client.post(f"/agents/{agent.id}/suspicious-events", json={"events": [EVENT, EVENT]})
        assert r.json() == {"ok": True, "inserted": 1, "skipped": 1}
        assert db.query(models.SuspiciousEvent).count() == 1


class TestStatusTransitions:
    def _seed(self, db, status="new"):
        e = models.SuspiciousEvent(
            agent_id="agt1",
            hostname="PC1",
            signal_type="process",
            severity="high",
            matched_rule="process-lolbin-certutil-decode",
            summary="test",
            local_event_id="abc",
            occurred_at=models._utcnow(),
            status=status,
        )
        db.add(e)
        db.commit()
        db.refresh(e)
        return e

    def test_new_to_acknowledged_accepted(self, client, db, auth_headers):
        e = self._seed(db, status="new")
        r = client.put(
            f"/suspicious-events/{e.id}", json={"status": "acknowledged", "note": "vu"}, headers=auth_headers
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "acknowledged"
        assert body["handled_note"] == "vu"
        assert body["handled_at"] is not None

    def test_new_to_false_positive_accepted(self, client, db, auth_headers):
        e = self._seed(db, status="new")
        r = client.put(f"/suspicious-events/{e.id}", json={"status": "false_positive"}, headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["status"] == "false_positive"

    def test_acknowledged_to_escalated_accepted(self, client, db, auth_headers):
        e = self._seed(db, status="acknowledged")
        r = client.put(f"/suspicious-events/{e.id}", json={"status": "escalated"}, headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["status"] == "escalated"

    def test_acknowledged_to_acknowledged_rejected(self, client, db, auth_headers):
        e = self._seed(db, status="acknowledged")
        r = client.put(f"/suspicious-events/{e.id}", json={"status": "acknowledged"}, headers=auth_headers)
        assert r.status_code == 400  # "acknowledged" est un statut valide en général, mais pas
        # une transition sortante autorisée DEPUIS "acknowledged" (voir _ALLOWED_TRANSITIONS).

    def test_terminal_false_positive_rejects_further_transition(self, client, db, auth_headers):
        e = self._seed(db, status="false_positive")
        r = client.put(f"/suspicious-events/{e.id}", json={"status": "escalated"}, headers=auth_headers)
        assert r.status_code == 400

    def test_terminal_escalated_rejects_further_transition(self, client, db, auth_headers):
        e = self._seed(db, status="escalated")
        r = client.put(f"/suspicious-events/{e.id}", json={"status": "false_positive"}, headers=auth_headers)
        assert r.status_code == 400

    def test_update_requires_auth(self, client, db):
        e = self._seed(db, status="new")
        r = client.put(f"/suspicious-events/{e.id}", json={"status": "acknowledged"})
        assert r.status_code == 401

    def test_actor_recorded_from_x_actor_header(self, client, db, auth_headers):
        e = self._seed(db, status="new")
        headers = {**auth_headers, "X-Actor": "nicolas.bertrand"}
        r = client.put(f"/suspicious-events/{e.id}", json={"status": "acknowledged"}, headers=headers)
        assert r.json()["handled_by"] == "nicolas.bertrand"


class TestDashboardReadRoutes:
    def test_list_filters_and_sorts_desc(self, client, db, auth_headers):
        old = models.SuspiciousEvent(
            agent_id="agt1", hostname="PC1", signal_type="usb", severity="low",
            matched_rule="usb-mass-copy", summary="ancien",
            local_event_id="a", occurred_at=_dt("2026-01-01T00:00:00+00:00"),
        )
        recent = models.SuspiciousEvent(
            agent_id="agt1", hostname="PC1", signal_type="process", severity="high",
            matched_rule="process-lolbin-certutil-decode", summary="récent",
            local_event_id="b", occurred_at=_dt("2026-09-01T00:00:00+00:00"),
        )
        db.add_all([old, recent])
        db.commit()

        r = client.get("/suspicious-events", headers=auth_headers)
        assert r.status_code == 200
        summaries = [e["summary"] for e in r.json()]
        assert summaries == ["récent", "ancien"]

        r = client.get("/suspicious-events?signal_type=usb", headers=auth_headers)
        assert [e["summary"] for e in r.json()] == ["ancien"]

        r = client.get("/suspicious-events?severity=high", headers=auth_headers)
        assert [e["summary"] for e in r.json()] == ["récent"]

    def test_detail_parses_json(self, client, db, auth_headers):
        agent = _agent(db)
        _authenticate_as(agent)
        client.post(f"/agents/{agent.id}/suspicious-events", json={"events": [EVENT]})
        event_id = db.query(models.SuspiciousEvent).one().id

        r = client.get(f"/suspicious-events/{event_id}", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["detail"] == EVENT["detail"]

    def test_detail_404_unknown(self, client, auth_headers):
        assert client.get("/suspicious-events/inconnu", headers=auth_headers).status_code == 404

    def test_summary_counts_by_severity_and_status(self, client, db, auth_headers):
        db.add_all(
            [
                models.SuspiciousEvent(
                    agent_id="agt1", hostname="PC1", signal_type="usb", severity="low",
                    matched_rule="r1", summary="s1", local_event_id="a",
                    occurred_at=_dt("2026-01-01T00:00:00+00:00"), status="new",
                ),
                models.SuspiciousEvent(
                    agent_id="agt1", hostname="PC1", signal_type="process", severity="high",
                    matched_rule="r2", summary="s2", local_event_id="b",
                    occurred_at=_dt("2026-01-01T00:00:00+00:00"), status="acknowledged",
                ),
                models.SuspiciousEvent(
                    agent_id="agt1", hostname="PC1", signal_type="process", severity="high",
                    matched_rule="r3", summary="s3", local_event_id="c",
                    occurred_at=_dt("2026-01-01T00:00:00+00:00"), status="new",
                ),
            ]
        )
        db.commit()

        r = client.get("/suspicious-events/summary", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["by_severity"] == {"low": 1, "high": 2}
        assert body["by_status"] == {"new": 2, "acknowledged": 1}

    def test_dashboard_routes_require_auth(self, client):
        assert client.get("/suspicious-events").status_code == 401
        assert client.get("/suspicious-events/summary").status_code == 401
        assert client.get("/suspicious-events/x").status_code == 401


class TestSuspiciousRules:
    def test_returns_default_ruleset(self, client, db):
        agent = _agent(db)
        _authenticate_as(agent)

        r = client.get(f"/agents/{agent.id}/suspicious-rules")
        assert r.status_code == 200
        body = r.json()
        assert set(body.keys()) == {"process", "eventLog", "network", "usb"}
        assert body["process"]["suspiciousPaths"] == ["%TEMP%", "%APPDATA%", "%LOCALAPPDATA%\\Temp"]
        lolbin_names = [b["name"] for b in body["process"]["lolbins"]]
        assert "certutil.exe" in lolbin_names
        assert body["eventLog"]["authFailureThreshold"] == 5
        assert body["network"]["allowedPorts"] == [80, 443, 53, 123, 445, 3389]
        assert body["usb"]["fileCopyAggregateThreshold"] == 20

    def test_wrong_agent_id_rejected(self, client, db):
        agent = _agent(db)
        other = _agent(db, hostname="PC-AUTRE")
        _authenticate_as(agent)

        assert client.get(f"/agents/{other.id}/suspicious-rules").status_code == 403


class TestPurgeExclusion:
    def test_purge_history_never_deletes_suspicious_events(self, client, db, auth_headers):
        # Événement délibérément "vieux" (bien au-delà de n'importe quel seuil de rétention
        # testable) — s'il existait la moindre logique de purge dessus, ce test la prendrait en
        # défaut.
        e = models.SuspiciousEvent(
            agent_id="agt1", hostname="PC1", signal_type="process", severity="high",
            matched_rule="r1", summary="très ancien", local_event_id="a",
            occurred_at=_dt("2000-01-01T00:00:00+00:00"),
        )
        db.add(e)
        db.commit()

        r = client.post("/maintenance/purge-history", json={"days": 7}, headers=auth_headers)
        assert r.status_code == 200
        # La route de purge ne connaît même pas cette table — son contrat de réponse n'a aucun
        # champ "suspicious_events_deleted" (voir routes/maintenance.py, jamais modifié pour ce
        # jalon).
        assert "suspicious_events_deleted" not in r.json()

        assert db.query(models.SuspiciousEvent).count() == 1
        assert db.get(models.SuspiciousEvent, e.id) is not None
