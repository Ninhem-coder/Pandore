"""Lance le serveur Vanitas avec la configuration TLS réelle (mTLS optionnel côté client).

Capture le one-liner qui faisait tourner ce serveur en production jusqu'ici SANS être committé
nulle part (retrouvé le 2026-09-08 via `Get-CimInstance Win32_Process` sur le process déjà en
cours, pendant une revue de sécurité) — un risque opérationnel réel : un futur redémarrage sans
cette connaissance tribale aurait pu démarrer le serveur sans TLS client-cert du tout, ou pas du
tout.

`ssl_cert_reqs=ssl.CERT_OPTIONAL` (PAS `CERT_REQUIRED`) est INTENTIONNEL, pas un réglage
provisoire à durcir : les routes "dashboard" (`X-Shell-Token`) sont appelées par le backend
Pandore SANS certificat client, seulement les routes "agent" présentent un certificat mTLS
(vérifié applicativement par `app.security.get_current_agent`, PAS par la couche TLS elle-même).
Passer en `CERT_REQUIRED` casserait tout le proxy Pandore→Vanitas.

Usage (depuis `endpoint-agent/server/`) :
    .venv/Scripts/python.exe scripts/run_server.py
    HOST=0.0.0.0 PORT=8443 .venv/Scripts/python.exe scripts/run_server.py   # override
"""
import ssl
import sys
from pathlib import Path

# Même motif que scripts/create_enrollment_token.py — permet l'exécution directe sans installer
# `app` comme package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn  # noqa: E402

from app import config  # noqa: E402

CA_DIR = Path(__file__).resolve().parent.parent / "data" / "ca"


def main() -> None:
    uvicorn.run(
        "app.main:app",
        host=config.HOST,
        port=config.PORT,
        ssl_keyfile=str(CA_DIR / "server-key.pem"),
        ssl_certfile=str(CA_DIR / "server.pem"),
        ssl_ca_certs=str(CA_DIR / "ca.pem"),
        ssl_cert_reqs=ssl.CERT_OPTIONAL,
    )


if __name__ == "__main__":
    main()
