"""Génère un ou plusieurs tokens d'enrôlement à usage unique.

Un token généré ici est à donner à UN agent pour son tout premier lancement (`--enroll`) —
voir le README de `agent/`. Il est invalidé dès qu'il a servi une fois.

Usage (depuis `endpoint-agent/server/`) :
    .venv/Scripts/python.exe scripts/create_enrollment_token.py
    .venv/Scripts/python.exe scripts/create_enrollment_token.py --count 5
"""
import argparse
import sys
from pathlib import Path

# Permet d'exécuter ce script directement (`python scripts/create_enrollment_token.py`)
# sans avoir à installer `app` comme package : Python ne met par défaut que le dossier du
# script lui-même sur sys.path, pas son parent.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import SessionLocal, init_db  # noqa: E402
from app.models import EnrollmentToken  # noqa: E402
from app.security import generate_token, hash_token  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--count", type=int, default=1, help="Nombre de tokens à générer (défaut : 1)."
    )
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        for _ in range(args.count):
            token = generate_token()
            db.add(EnrollmentToken(token_hash=hash_token(token)))
            db.commit()
            print(token)
    finally:
        db.close()


if __name__ == "__main__":
    main()
