"""Migration manuelle : ajoute `pattern` à `device_groups` (groupes dynamiques + many-to-many,
2026-09-08). Même motif/précautions que les migrations précédentes — idempotent, `PRAGMA
table_info` avant l'`ADD COLUMN`. La table `agent_group_memberships` (many-to-many) n'a besoin
d'AUCUNE migration : table neuve, créée automatiquement par `Base.metadata.create_all()` au
prochain démarrage du serveur.

Défensif : si `agents.group_id` (colonne du jalon v1, retirée du modèle ORM mais toujours
présente en base) contient encore une valeur non nulle pour un agent, elle est reportée dans
`agent_group_memberships` avant de continuer — confirmé vide pour le seul agent réel au moment
d'écrire cette migration, gardé par prudence pour ne perdre aucune affectation si ce script est
rejoué plus tard sur un état différent.

Usage (depuis `endpoint-agent/server/`, serveur ARRÊTÉ pendant la migration) :
    .venv/Scripts/python.exe scripts/migrate_add_group_pattern_column.py
"""
import sqlite3
import sys
from datetime import datetime, timezone
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
        columns = {row[1] for row in conn.execute("PRAGMA table_info(device_groups)")}
        if "pattern" not in columns:
            conn.execute("ALTER TABLE device_groups ADD COLUMN pattern TEXT")
            conn.commit()
            print("Colonne ajoutée : device_groups.pattern")
        else:
            print("Colonne device_groups.pattern déjà présente.")

        agent_columns = {row[1] for row in conn.execute("PRAGMA table_info(agents)")}
        if "group_id" in agent_columns:
            legacy = conn.execute(
                "SELECT id, group_id FROM agents WHERE group_id IS NOT NULL"
            ).fetchall()
            if legacy:
                tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if "agent_group_memberships" not in tables:
                    conn.execute(
                        "CREATE TABLE agent_group_memberships ("
                        "agent_id TEXT NOT NULL, group_id TEXT NOT NULL, created_at TEXT NOT NULL, "
                        "PRIMARY KEY (agent_id, group_id))"
                    )
                now = datetime.now(timezone.utc).isoformat()
                for agent_id, group_id in legacy:
                    conn.execute(
                        "INSERT OR IGNORE INTO agent_group_memberships (agent_id, group_id, created_at) "
                        "VALUES (?, ?, ?)",
                        (agent_id, group_id, now),
                    )
                conn.commit()
                print(f"Adhésions reportées depuis l'ancien modèle (v1) : {len(legacy)}")
            else:
                print("Aucune adhésion group_id (v1) à reporter — colonne déjà vide, comme attendu.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
