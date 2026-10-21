"""`get_current_agent` met à jour `Agent.last_seen` à chaque appel authentifié (2026-09-16,
retour de Nicolas : une commande "Journal d'événements" venait de réussir mais "vu il y a" ne
bougeait pas — avant ce correctif, seul `routes/inventory.py` touchait ce champ). Testé en
appelant la dépendance directement avec un `Request` factice exposant le certificat mTLS via
`scope["transport"]`, même mécanique que celle décrite dans le docstring de la fonction — pas
via `TestClient` (pas de vrai handshake TLS possible, voir `test_suspicious_activity.py`).
"""
from datetime import datetime, timedelta, timezone

from app import models
from app.security import get_current_agent


class _FakeSslObject:
    def __init__(self, agent_id: str):
        self._agent_id = agent_id

    def getpeercert(self):
        return {"subject": ((("commonName", self._agent_id),),), "serialNumber": None}


class _FakeTransport:
    def __init__(self, agent_id: str):
        self._ssl_object = _FakeSslObject(agent_id)

    def get_extra_info(self, name: str):
        return self._ssl_object if name == "ssl_object" else None


class _FakeRequest:
    def __init__(self, agent_id: str):
        self.scope = {"transport": _FakeTransport(agent_id)}


def test_get_current_agent_bumps_last_seen(db):
    stale = datetime.now(timezone.utc) - timedelta(hours=8)
    agent = models.Agent(hostname="TEST-LASTSEEN-HOST", last_seen=stale)
    db.add(agent)
    db.commit()
    db.refresh(agent)

    before = datetime.now(timezone.utc)
    result = get_current_agent(_FakeRequest(agent.id), db)
    after = datetime.now(timezone.utc)

    assert result.id == agent.id
    assert result.last_seen is not None
    last_seen = result.last_seen if result.last_seen.tzinfo else result.last_seen.replace(tzinfo=timezone.utc)
    assert before <= last_seen <= after


def test_get_current_agent_bumps_last_seen_even_when_never_seen_before(db):
    agent = models.Agent(hostname="TEST-LASTSEEN-HOST-2", last_seen=None)
    db.add(agent)
    db.commit()
    db.refresh(agent)

    result = get_current_agent(_FakeRequest(agent.id), db)

    assert result.last_seen is not None
