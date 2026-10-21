"""Migration manuelle : ajoute os_architecture/os_registered_user/os_install_date/os_utc_offset
à `inventory_snapshots` (panneau "Système d'exploitation" de la fiche poste, 2026-09-11, retour
de Nicolas — "possible d'avoir plus d'information ?"). Même besoin que
`migrate_add_os_columns.py` (os_caption/os_version/os_build_number) — voir ce script pour le
détail du raisonnement, repris à l'identique ici.

Idempotent — relancer ce script après une première exécution réussie ne fait rien de plus
(vérifie `PRAGMA table_info` avant chaque `ADD COLUMN`).

Usage (depuis `endpoint-agent/server/`, serveur ARRÊTÉ pendant la migration) :
    .venv/Scripts/python.exe scripts/migrate_add_os_detail_columns.py

Recommandé avant tout lancement contre la vraie base de production : faire d'abord une copie
de `data/endpoint_agent.db` et lancer ce script sur la copie pour vérifier le résultat.
"""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import DATA_DIR  # noqa: E402

DB_PATH = DATA_DIR / "endpoint_agent.db"

_NEW_COLUMNS = {
    "os_architecture": "TEXT",
    "os_registered_user": "TEXT",
    "os_install_date": "DATETIME",
    "os_utc_offset": "TEXT",
}


def main() -> None:
    if not DB_PATH.exists():
        print(f"Base introuvable : {DB_PATH} — rien à migrer (elle sera créée à jour au premier démarrage).")
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        existing = {row[1] for row in conn.execute("PRAGMA table_info(inventory_snapshots)")}
        added = []
        for column, sql_type in _NEW_COLUMNS.items():
            if column in existing:
                continue
            conn.execute(f"ALTER TABLE inventory_snapshots ADD COLUMN {column} {sql_type}")
            added.append(column)
        conn.commit()
        if added:
            print(f"Colonnes ajoutées : {', '.join(added)}")
        else:
            print("Déjà à jour — aucune colonne à ajouter.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
