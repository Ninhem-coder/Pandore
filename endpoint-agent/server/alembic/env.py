"""Environnement de migration Alembic (2026-09-12) — serveur Vanitas.

L'URL de base vient de `app.db.DATABASE_URL` (source unique, pas de duplication dans
alembic.ini), avec un override optionnel `ALEMBIC_DATABASE_URL` pour l'outillage/les tests
(ex. générer la migration de base contre une base vide, ou tester une migration sur une copie
jetable). `target_metadata = Base.metadata` : `--autogenerate` compare le schéma réel aux
modèles de `app/models.py`. `render_as_batch=True` — indispensable sur SQLite, qui ne sait pas
faire d'`ALTER TABLE` complexe nativement (Alembic recrée alors la table en mode batch).
"""
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app import models  # noqa: F401 — enregistre toutes les tables sur Base.metadata
from app.db import DATABASE_URL, Base

config = context.config
config.set_main_option("sqlalchemy.url", os.environ.get("ALEMBIC_DATABASE_URL") or DATABASE_URL)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
