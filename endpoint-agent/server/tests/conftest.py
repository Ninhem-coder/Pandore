"""Fixtures de test du serveur Vanitas (2026-09-12) — premier harnais de test de ce serveur
(auparavant : zéro couverture, alors que c'est le composant qui exécute du PowerShell SYSTEM
sur le parc — le plus gros décalage risque/couverture du projet, comblé ici).

Base SQLite EN MÉMOIRE isolée par test (`StaticPool` = une seule connexion partagée, pour que
la session directe `db` et les sessions des routes voient les mêmes données) — la vraie base
`data/endpoint_agent.db` n'est JAMAIS touchée (dépendance `get_db` surchargée). Le `TestClient`
n'est volontairement PAS utilisé comme context manager : ça évite de déclencher le `lifespan`
(qui lancerait la boucle de rafraîchissement CVE réseau) — inutile ici, tout l'état passe par
la base de test.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import config, models  # noqa: F401 — importe models pour enregistrer les tables sur Base
from app.db import Base, get_db
from app.main import app

TEST_SHELL_TOKEN = "test-shell-token"


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=eng)
    yield eng
    eng.dispose()


@pytest.fixture
def SessionFactory(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture
def db(SessionFactory):
    """Session directe pour préparer/inspecter la base dans un test (insertion d'agents/groupes,
    assertions post-appel)."""
    session = SessionFactory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(SessionFactory, monkeypatch):
    # require_shell_token lit config.SHELL_SESSION_TOKEN dynamiquement à chaque appel — un
    # monkeypatch de l'attribut suffit pour disposer d'un token de test connu.
    monkeypatch.setattr(config, "SHELL_SESSION_TOKEN", TEST_SHELL_TOKEN)

    def _override_get_db():
        s = SessionFactory()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers():
    return {"X-Shell-Token": TEST_SHELL_TOKEN}
