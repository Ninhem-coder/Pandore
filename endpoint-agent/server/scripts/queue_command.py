"""Met une commande en file pour un agent — jalon 4 (canal de commande).

Usage (depuis `endpoint-agent/server/`) :
    .venv/Scripts/python.exe scripts/queue_command.py <agent_id> force_inventory
    .venv/Scripts/python.exe scripts/queue_command.py <agent_id> system_diagnostic
    .venv/Scripts/python.exe scripts/queue_command.py --all check_windows_updates

Le type de commande est validé contre le catalogue fixe (`app/commands.py::COMMAND_TYPES`) —
un type inconnu est refusé ici plutôt que d'être silencieusement ignoré par l'agent.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.commands import COMMAND_TYPES, create_command  # noqa: E402
from app.db import SessionLocal, init_db  # noqa: E402
from app.models import Agent  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("agent_id", nargs="?", help="Identifiant de l'agent ciblé (omis avec --all).")
    parser.add_argument("command_type", choices=sorted(COMMAND_TYPES))
    parser.add_argument(
        "--all", action="store_true", help="Mettre la commande en file pour TOUS les agents enrôlés."
    )
    args = parser.parse_args()

    if args.all == bool(args.agent_id):
        parser.error("Fournir soit un agent_id, soit --all (pas les deux, pas ni l'un ni l'autre).")

    init_db()
    db = SessionLocal()
    try:
        if args.all:
            targets = db.query(Agent).all()
            if not targets:
                print("Aucun agent enrôlé — rien à faire.")
                return
        else:
            agent = db.get(Agent, args.agent_id)
            if agent is None:
                print(f"Agent inconnu : {args.agent_id}")
                sys.exit(1)
            targets = [agent]

        for agent in targets:
            command = create_command(db, agent, args.command_type)
            print(f"Commande {command.id} ({args.command_type}) mise en file pour {agent.id} ({agent.hostname}).")
    finally:
        db.close()


if __name__ == "__main__":
    main()
