"""Migration manuelle : ajoute `rules` à `device_groups` (règles dynamiques multi-critères +
groupes imbriqués, 2026-09-10 — voir app/group_membership.py). Même motif/précautions que les
migrations précédentes — idempotent, `PRAGMA table_info` avant l'`ADD COLUMN`.

Traduit aussi tout `pattern` existant (v1, motif glob sur le hostname) en une règle `rules`
JSON équivalente à un seul critère `{field: "hostname", operator: "glob", value: pattern}` —
`pattern` reste une colonne PHYSIQUE (jamais de `DROP COLUMN` dans ce projet) mais n'est plus
lue par le code applicatif après cette migration.

La table `device_group_links` (groupes imbriqués) n'a besoin d'AUCUNE migration : table neuve,
créée automatiquement par `Base.metadata.create_all()` au prochain démarrage du serveur.

Usage (depuis `endpoint-agent/server/`, serveur ARRÊTÉ pendant la migration) :
    .venv/Scripts/python.exe scripts/migrate_add_group_rules_column.py
"""
import json
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
        columns = {row[1] for row in conn.execute("PRAGMA table_info(device_groups)")}
        if "rules" not in columns:
            conn.execute("ALTER TABLE device_groups ADD COLUMN rules TEXT")
            conn.commit()
            print("Colonne ajoutée : device_groups.rules")
        else:
            print("Colonne device_groups.rules déjà présente.")

        if "pattern" in columns:
            legacy = conn.execute(
                "SELECT id, pattern FROM device_groups WHERE pattern IS NOT NULL AND rules IS NULL"
            ).fetchall()
            for group_id, pattern in legacy:
                rules = json.dumps(
                    {"combinator": "all", "conditions": [{"field": "hostname", "operator": "glob", "value": pattern}]}
                )
                conn.execute("UPDATE device_groups SET rules = ? WHERE id = ?", (rules, group_id))
            if legacy:
                conn.commit()
                print(f"Motifs (v1) traduits en règles : {len(legacy)}")
            else:
                print("Aucun motif (v1) à traduire — aucun groupe dynamique existant, comme attendu.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
