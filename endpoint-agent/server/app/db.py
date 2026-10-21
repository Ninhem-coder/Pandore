"""Connexion SQLAlchemy et session DB pour le serveur endpoint-agent.

SQLite pour ce jalon (quelques postes de test) — pas de verrou technique qui empêcherait
de migrer vers Postgres au jalon de passage à l'échelle, `DATABASE_URL` est le seul point
à changer.
"""
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
DATABASE_URL = f"sqlite:///{DATA_DIR / 'endpoint_agent.db'}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    """Applique les migrations Alembic jusqu'à la dernière (`upgrade head`) au démarrage —
    source UNIQUE de vérité pour le schéma depuis le 2026-09-12 (remplace l'ancien
    `Base.metadata.create_all()` + les scripts `scripts/migrate_add_*.py` faits main, voir
    `alembic/`). Sur une base neuve : crée tout le schéma via la migration de base. Sur la base
    de prod existante (stampée `head`) : no-op. Un changement de modèle passe désormais par
    `alembic revision --autogenerate -m "..."` puis est appliqué automatiquement ici au
    prochain démarrage, jamais par un ALTER TABLE écrit à la main."""
    from pathlib import Path as _Path

    from alembic import command
    from alembic.config import Config

    server_dir = _Path(__file__).resolve().parent.parent  # endpoint-agent/server/
    cfg = Config(str(server_dir / "alembic.ini"))
    # Chemins ABSOLUS : `init_db()` est appelé par le lifespan FastAPI, dont le répertoire de
    # travail n'est pas garanti être `server/` — ne jamais dépendre du CWD pour retrouver les
    # migrations.
    cfg.set_main_option("script_location", str(server_dir / "alembic"))
    command.upgrade(cfg, "head")


def get_db():
    """Dépendance FastAPI : une session DB par requête, toujours fermée après usage."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
