"""Gating d'authentification des routes dashboard (2026-09-12).

Régression-test du correctif de sécurité CRITIQUE du 2026-09-07 : `GET /agents`,
`POST /agents/{id}/commands` (peut déclencher `start_shell_session` — RCE SYSTEM) et
`DELETE /agents/{id}` n'avaient AUCUNE authentification. On verrouille ici pour que ça ne
puisse jamais régresser silencieusement : chaque route dashboard exige `X-Shell-Token`, seuls
`/health` et `/enroll` (bootstrap) restent publics.
"""
from .conftest import TEST_SHELL_TOKEN


def test_health_is_public(client):
    assert client.get("/health").status_code == 200


def test_dashboard_routes_reject_missing_token(client):
    # Lecture
    assert client.get("/agents").status_code == 401
    assert client.get("/groups").status_code == 401
    assert client.get("/commands").status_code == 401
    assert client.get("/installers").status_code == 401
    assert client.get("/agent-package/history").status_code == 401
    # Mutations sensibles — les plus dangereuses doivent être gardées
    assert client.post("/enrollment-tokens").status_code == 401
    assert (
        client.post("/agents/whatever/commands", json={"command_type": "start_shell_session"}).status_code
        == 401
    )
    assert client.delete("/agents/whatever").status_code == 401
    assert client.post("/groups", json={"name": "x"}).status_code == 401


def test_wrong_token_rejected(client):
    headers = {"X-Shell-Token": "mauvais-jeton"}
    assert client.get("/agents", headers=headers).status_code == 401


def test_valid_token_grants_access(client, auth_headers):
    r = client.get("/agents", headers=auth_headers)
    assert r.status_code == 200
    assert r.json() == []
    assert client.get("/groups", headers=auth_headers).json() == []


def test_queue_command_passes_gate_then_404_on_unknown_agent(client, auth_headers):
    # Token OK → le gate laisse passer ; l'agent inconnu est refusé par la LOGIQUE (404),
    # pas par l'auth (401) : prouve que le gating et la validation métier sont bien distincts.
    r = client.post(
        "/agents/inconnu/commands", json={"command_type": "system_diagnostic"}, headers=auth_headers
    )
    assert r.status_code == 404


def test_token_constant_value_used(client):
    # Sanity : le token de test est bien celui injecté par la fixture.
    assert client.get("/agents", headers={"X-Shell-Token": TEST_SHELL_TOKEN}).status_code == 200
