"""Configuration chargée depuis `.env` (jamais de secret en dur dans le code).

`.env` est gitignoré ; `.env.example` (versionné) documente les variables attendues.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

NVD_API_KEY: str | None = os.environ.get("NVD_API_KEY") or None
CVE_REFRESH_INTERVAL_HOURS: float = float(os.environ.get("CVE_REFRESH_INTERVAL_HOURS", "12"))

# Passphrase protégeant la clé privée de la CA au repos (voir scripts/generate_ca.py et
# app/ca.py) — le secret le plus sensible de tout le projet, jamais en dur.
CA_KEY_PASSPHRASE: str | None = os.environ.get("CA_KEY_PASSPHRASE") or None

# Jalon 9 (terminal PowerShell interactif) — les routes dashboard qui permettent d'OBSERVER/
# PILOTER une session déjà ouverte (app/routes/shell.py::require_shell_token) exigent ce secret
# en header `X-Shell-Token`. Généralisé le 2026-09-08 (revue de sécurité) à TOUTES les routes
# dashboard-facing de ce serveur (`routes/agents.py`/`commands.py`/`vulnerabilities.py`/
# `compliance.py`) — l'ancien modèle "loopback uniquement" pour le reste de Vanitas s'est avéré
# faux en pratique (serveur réellement joignable par tout le parc), et `POST /agents/{id}/
# commands` en particulier peut déclencher `start_shell_session` (RCE niveau SYSTEM) tout comme
# les routes déjà protégées. Ne protège JAMAIS les routes agent (mTLS, déjà authentifiées bien
# plus fort qu'un secret partagé) ni `/enroll`/`/health` (bootstrap/health-check, par design).
SHELL_SESSION_TOKEN: str | None = os.environ.get("SHELL_SESSION_TOKEN") or None

# Lancement du serveur (2026-09-08, revue de sécurité — voir scripts/run_server.py) : jusqu'ici
# le one-liner uvicorn.run(...) exact (host/port/certificats TLS/CERT_OPTIONAL) n'existait dans
# AUCUN fichier du repo, retrouvé une fois via `Get-CimInstance Win32_Process` sur le process
# déjà en cours — risque opérationnel réel (un redémarrage sans cette connaissance tribale
# pourrait démarrer le serveur sans TLS client-cert, ou pas du tout). `HOST`/`PORT` overridables,
# les chemins de certificats restent relatifs à `endpoint-agent/server/` (répertoire de travail
# attendu pour lancer ce script, comme les autres scripts de ce dossier).
HOST: str = os.environ.get("HOST", "127.0.0.1")
PORT: int = int(os.environ.get("PORT", "8443"))
