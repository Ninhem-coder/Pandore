"""Gestion des comptes du dashboard Pandore (2026-09-07) — pas d'UI self-service ni d'écran
d'admin dans le dashboard web pour cette v1 : la création de COMPTES eux-mêmes est un cran plus
sensible que le reste de ce qui se gère déjà en ligne (packaging, bibliothèque d'app...), gardée
hors du dashboard. Même précédent que `endpoint-agent/server/scripts/create_enrollment_token.py`
pour ce choix.

Usage (depuis `backend/`) :
    .venv/Scripts/python.exe manage_users.py create nicolas admin
    .venv/Scripts/python.exe manage_users.py create testeur viewer
    .venv/Scripts/python.exe manage_users.py list
    .venv/Scripts/python.exe manage_users.py passwd nicolas
    .venv/Scripts/python.exe manage_users.py delete testeur
"""
import argparse
import getpass
import sys

from auth import store
from auth.passwords import hash_password


def _prompt_password() -> str:
    while True:
        pw = getpass.getpass("Mot de passe : ")
        if len(pw) < 8:
            print("Le mot de passe doit faire au moins 8 caractères.", file=sys.stderr)
            continue
        confirm = getpass.getpass("Confirmer : ")
        if pw != confirm:
            print("Les deux saisies ne correspondent pas, réessaie.", file=sys.stderr)
            continue
        return pw


def cmd_create(args) -> None:
    password = _prompt_password()
    user = store.create_user(args.username, hash_password(password), args.role)
    print(f"Compte « {user['username']} » créé (rôle : {user['role']}).")


def cmd_list(_args) -> None:
    users = store.list_users()
    if not users:
        print("Aucun compte enregistré.")
        return
    for user in users:
        print(f"{user['username']:<24} {user['role']:<8} créé le {user['created_at']}")


def cmd_passwd(args) -> None:
    password = _prompt_password()
    store.set_password(args.username, hash_password(password))
    print(f"Mot de passe de « {args.username} » mis à jour.")


def cmd_delete(args) -> None:
    store.delete_user(args.username)
    print(f"Compte « {args.username} » supprimé (sessions actives invalidées).")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)

    p_create = sub.add_parser("create", help="Créer un compte")
    p_create.add_argument("username")
    p_create.add_argument("role", choices=store.VALID_ROLES)
    p_create.set_defaults(func=cmd_create)

    p_list = sub.add_parser("list", help="Lister les comptes")
    p_list.set_defaults(func=cmd_list)

    p_passwd = sub.add_parser("passwd", help="Changer le mot de passe d'un compte")
    p_passwd.add_argument("username")
    p_passwd.set_defaults(func=cmd_passwd)

    p_delete = sub.add_parser("delete", help="Supprimer un compte")
    p_delete.add_argument("username")
    p_delete.set_defaults(func=cmd_delete)

    args = parser.parse_args()
    try:
        args.func(args)
    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
