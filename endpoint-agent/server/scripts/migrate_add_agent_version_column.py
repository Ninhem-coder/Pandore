"""Migration manuelle : ajoute agent_version à `agents` (jalon "traçabilité de version",
2026-09-08). Même motif/précautions que `migrate_add_os_columns.py` (voir ce fichier pour le
raisonnement complet sur pourquoi `Base.metadata.create_all()` ne suffit pas ici) — idempotent,
`PRAGMA table_info` avant l'`ADD COLUMN`.

Usage (depuis `endpoint-agent/server/`, serveur ARRÊTÉ pendant la migration) :
    .venv/Scripts/python.exe scripts/migrate_add_agent_version_column.py
"""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import DATA_DIR  # noqa: E402

DB_PATH = DATA_DIR / "endpoint_agent.db"


def main() -> None:
    if not DB_PATH.exists():
        print(f"Base introuvable : {DB_PATH} — rien à migrer (elle sera créée à jour au premier démarrage).")
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        existing = {row[1] for row in conn.execute("PRAGMA table_info(agents)")}
        if "agent_version" in existing:
            print("Déjà à jour — aucune colonne à ajouter.")
            return
        conn.execute("ALTER TABLE agents ADD COLUMN agent_version TEXT")
        conn.commit()
        print("Colonne ajoutée : agent_version")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
