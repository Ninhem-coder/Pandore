"""Tests de `commands.build_event_log_parameters` — jalon "Journal d'événements Windows à la
demande" (2026-09-16). Fonction pure (pas de DB, pas d'app FastAPI) : ces paramètres viennent
directement d'une saisie utilisateur, cette validation est le seul garde-fou avant que l'agent
ne les interprète en requête XPath sur le poste — voir le commentaire de la fonction elle-même.
"""
import json
from datetime import datetime, timezone

import pytest

from app import commands, models
from app.routes.commands import _format_evtx_time


def test_build_event_log_parameters_valid_serializes_all_fields():
    raw = commands.build_event_log_parameters(
        channels=["Security"],
        since="2026-09-01T00:00:00Z",
        until="2026-09-15T23:59:59Z",
        event_ids_include=[4624, 4625],
        event_ids_exclude=[4634],
        levels=["audit_success", "audit_failure"],
        after_record_id=1000,
        max_events=500,
    )
    payload = json.loads(raw)
    assert payload == {
        "channels": ["Security"],
        "since": "2026-09-01T00:00:00Z",
        "until": "2026-09-15T23:59:59Z",
        "event_ids_include": [4624, 4625],
        "event_ids_exclude": [4634],
        "levels": ["audit_success", "audit_failure"],
        "after_record_id": 1000,
        "max_events": 500,
    }


def test_build_event_log_parameters_rejects_empty_channels():
    with pytest.raises(ValueError, match="au moins un canal"):
        commands.build_event_log_parameters(channels=[], since="2026-09-01T00:00:00Z", until="2026-09-15T00:00:00Z")


def test_build_event_log_parameters_rejects_unknown_channel():
    with pytest.raises(ValueError, match="Canal inconnu"):
        commands.build_event_log_parameters(
            channels=["Security", "PowerShell/Operational"],
            since="2026-09-01T00:00:00Z",
            until="2026-09-15T00:00:00Z",
        )


def test_build_event_log_parameters_rejects_since_after_until():
    with pytest.raises(ValueError, match="précéder"):
        commands.build_event_log_parameters(
            channels=["Security"], since="2026-09-15T00:00:00Z", until="2026-09-01T00:00:00Z"
        )


def test_build_event_log_parameters_rejects_since_equal_until():
    with pytest.raises(ValueError, match="précéder"):
        commands.build_event_log_parameters(
            channels=["Security"], since="2026-09-01T00:00:00Z", until="2026-09-01T00:00:00Z"
        )


def test_build_event_log_parameters_caps_max_events_even_if_client_asks_more():
    raw = commands.build_event_log_parameters(
        channels=["Security"], since="2026-09-01T00:00:00Z", until="2026-09-02T00:00:00Z", max_events=999_999
    )
    assert json.loads(raw)["max_events"] == commands.EVENT_LOG_MAX_EVENTS_CAP


def test_build_event_log_parameters_defaults_optional_lists_to_empty():
    raw = commands.build_event_log_parameters(
        channels=["System"], since="2026-09-01T00:00:00Z", until="2026-09-02T00:00:00Z"
    )
    payload = json.loads(raw)
    assert payload["event_ids_include"] == []
    assert payload["event_ids_exclude"] == []
    assert payload["levels"] == []
    assert payload["after_record_id"] is None
    assert payload["max_events"] == commands.EVENT_LOG_MAX_EVENTS_CAP


def test_fetch_event_log_in_command_types():
    assert "fetch_event_log" in commands.COMMAND_TYPES


# 🔧 Bug trouvé le 2026-09-16 (retour de Nicolas : une recherche sur 2 jours, tous niveaux
# cochés, sur "Security" — un canal qui a forcément des événements dans une telle fenêtre sur un
# poste actif — renvoyait 0 résultat). Cause : `datetime.isoformat()` produit un suffixe
# `+00:00`, mais le moteur EvtQuery n'interprète `@SystemTime>=/<=` comme une comparaison de DATE
# (et non une comparaison de chaîne lexicographique, qui ne matche jamais rien ici) que si la
# valeur se termine par `Z` — voir `_format_evtx_time`.
def test_format_evtx_time_uses_z_suffix_not_offset():
    dt = datetime(2026, 9, 16, 9, 13, 39, 123000, tzinfo=timezone.utc)
    assert _format_evtx_time(dt) == "2026-09-16T09:13:39.123Z"


def test_format_evtx_time_treats_naive_datetime_as_utc():
    dt = datetime(2026, 9, 16, 0, 0, 0)
    assert _format_evtx_time(dt) == "2026-09-16T00:00:00.000Z"


def test_format_evtx_time_converts_non_utc_offset_to_utc():
    from datetime import timedelta

    dt = datetime(2026, 9, 16, 10, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    assert _format_evtx_time(dt) == "2026-09-16T08:00:00.000Z"


def test_queue_fetch_event_log_command_stores_z_suffixed_times(client, db, auth_headers):
    """Test d'intégration bout en bout via la vraie route — c'est exactement le chemin où le
    bug vivait (`queue_command` convertissait le `datetime` Pydantic en chaîne AVANT
    `build_event_log_parameters`, jamais couvert par les tests unitaires ci-dessus qui passent
    déjà des chaînes `Z` toutes faites)."""
    agent = models.Agent(hostname="TEST-EVTX-HOST")
    db.add(agent)
    db.commit()
    db.refresh(agent)

    resp = client.post(
        f"/agents/{agent.id}/commands",
        json={
            "command_type": "fetch_event_log",
            "event_log_query": {
                "channels": ["Security"],
                "since": "2026-09-15T00:00:00+00:00",
                "until": "2026-09-16T23:59:59+00:00",
                "levels": ["audit_success", "audit_failure"],
            },
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    command_id = resp.json()["id"]

    command = db.get(models.AgentCommand, command_id)
    parameters = json.loads(command.parameters)
    assert parameters["since"] == "2026-09-15T00:00:00.000Z"
    assert parameters["until"] == "2026-09-16T23:59:59.000Z"
