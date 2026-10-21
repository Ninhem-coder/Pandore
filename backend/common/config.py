"""
Configuration partagée (chargement .env, endpoints, mode d'auth) pour les deux serveurs
MCP (Defender, Intune). Les identifiants propres à chaque ressource (tenant/client/secret)
sont dans defender/config.py et intune/config.py — voir ce module pour AUTH_MODE.
"""
import os
import sys
from pathlib import Path

from dotenv import dotenv_values

BACKEND_DIR = Path(__file__).resolve().parent.parent

# Charger backend/.env si présent (développement local uniquement). dotenv_values() (et non
# load_dotenv(), qui écrirait directement dans os.environ) pour garder la même logique
# explicite de priorité qu'avant : un .env ne doit JAMAIS écraser une variable déjà exportée
# dans le shell. python-dotenv gère correctement les guillemets, les commentaires en fin de
# ligne et un signe "=" supplémentaire dans une valeur (ex: un secret Azure AD contenant "#"
# ou "=") — un point sur lequel le parseur maison précédent (str.partition("=") ligne par
# ligne) échouait silencieusement (revue de code du 2026-08-17).
_env_file = BACKEND_DIR / ".env"
if _env_file.exists():
    for key, value in dotenv_values(_env_file).items():
        if value is None:
            continue
        # setdefault() ignore silencieusement le .env si la variable est déjà exportée
        # dans le shell (résidu d'un test précédent, variable globale du poste) — pour
        # un outil dont le workflow de debug est "je change le .env et je relance",
        # avertir explicitement évite de perdre du temps à comprendre pourquoi le
        # changement n'a aucun effet.
        existing = os.environ.get(key)
        if existing is not None and existing != value:
            print(
                f"[common.config] Variable d'environnement '{key}' déjà définie dans le "
                f"shell — la valeur de backend/.env est IGNORÉE pour cette variable.",
                file=sys.stderr,
            )
        os.environ.setdefault(key, value)


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise EnvironmentError(
            f"Variable d'environnement manquante : {name}\n"
            f"Créer backend/.env à partir de backend/.env.example et renseigner {name}."
        )
    return value


# Mode d'authentification :
#   "client_credentials" (défaut) — app-only avec secret, réutilise les mêmes app
#       registrations que les MCP existants côté Claude Desktop (Defender MCP, Intune
#       MCP). Pas d'interaction utilisateur, adapté à un usage local run-and-forget.
#   "interactive" — flux délégué (popup navigateur / device code), à activer si besoin
#       de restreindre l'accès aux droits d'un utilisateur plutôt qu'à ceux de l'app.
AUTH_MODE = os.environ.get("AUTH_MODE", "client_credentials").strip().lower()

# App registration "public client" — uniquement nécessaire en AUTH_MODE=interactive
# (voir README §1bis). Non requis en client_credentials, où chaque ressource a son
# propre tenant/client/secret (defender/config.py, intune/config.py).
if AUTH_MODE == "interactive":
    AZURE_TENANT_ID = require_env("AZURE_TENANT_ID")
    AZURE_CLIENT_ID = require_env("AZURE_CLIENT_ID")
else:
    AZURE_TENANT_ID = None
    AZURE_CLIENT_ID = None

# Dossier de cache des tokens MSAL (mode interactive uniquement), local et ignoré par git
TOKEN_CACHE_DIR = BACKEND_DIR / ".token_cache"
TOKEN_CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Assistant de packaging Win32 pour Intune (2026-08-26, demande de Nicolas — voir
# intune/packaging.py) : répertoire scratch racine, un sous-dossier par job (nommé par son
# UUID), local et ignoré par git comme TOKEN_CACHE_DIR ci-dessus. `INTUNEWIN_TOOL_PATH` pointe
# vers le binaire Microsoft Win32 Content Prep Tool (Windows uniquement) — pas de valeur par
# défaut plausible multi-poste, `require_env` lève une erreur explicite si absent au moment où
# packaging.py en a réellement besoin (pas au chargement de ce module, pour ne pas empêcher le
# reste du dashboard de démarrer sur un poste qui n'a pas l'outil installé).
PACKAGING_WORKDIR = BACKEND_DIR / ".packaging_workdir"
PACKAGING_WORKDIR.mkdir(parents=True, exist_ok=True)
INTUNEWIN_TOOL_PATH = os.environ.get("INTUNEWIN_TOOL_PATH")

# Intégration "Vanitas" (2026-09-04, jalon 5 — projet personnel séparé `endpoint-agent/`, voir
# son propre README ; nommé "Vanitas" côté dashboard pour ne pas se confondre avec "Pandore",
# qui est le nom/la marque du dashboard lui-même) : le serveur tourne en HTTPS avec sa propre
# CA auto-signée (pas celle de Windows) — jamais `verify=False`, `VANITAS_CA_CERT_PATH` pointe
# vers le certificat PUBLIC de cette CA (`ca.pem`, pas la clé privée) pour que httpx puisse le
# valider explicitement, comme n'importe quel autre appel de ce backend. Défaut : le chemin
# relatif au sein de CE MÊME repo (les deux projets sont côte à côte, `endpoint-agent/` à la
# racine) — fonctionne pour Nicolas sans rien configurer, overridable si le serveur tourne
# ailleurs.
VANITAS_SERVER_URL = os.environ.get("VANITAS_SERVER_URL", "https://localhost:8443")
VANITAS_CA_CERT_PATH = os.environ.get(
    "VANITAS_CA_CERT_PATH",
    str(BACKEND_DIR.parent / "endpoint-agent" / "server" / "data" / "ca" / "ca.pem"),
)
# Jalon 9 (terminal PowerShell interactif) — MÊME valeur que `SHELL_SESSION_TOKEN` côté serveur
# Vanitas (endpoint-agent/server/.env), copiée une fois à la main : ce backend l'attache en
# header sortant sur CHAQUE appel Vanitas (vanitas/client.py), le navigateur ne le connaît
# jamais. `None` si non configuré — les 4 routes concernées répondent alors 401 côté serveur
# Vanitas, jamais un accès ouvert par défaut.
VANITAS_SHELL_TOKEN = os.environ.get("VANITAS_SHELL_TOKEN") or None

# Page "Ajouter un poste" (2026-09-11) — URL que les AGENTS (pas ce backend) doivent utiliser
# pour joindre le serveur Vanitas, DISTINCTE de VANITAS_SERVER_URL ci-dessus : ce backend et le
# serveur Vanitas tournent sur la même machine (localhost y convient), mais un poste sur le
# réseau a besoin d'une adresse réellement joignable (hostname/IP LAN). Pas de valeur par
# défaut utilisable en pratique — un repli sur `localhost` produirait une commande d'install
# qui SEMBLE correcte mais ne fonctionnerait jamais hors de cette machine ; `None` signale
# explicitement "à configurer" plutôt qu'une valeur fausse mais plausible.
VANITAS_AGENT_SERVER_URL = os.environ.get("VANITAS_AGENT_SERVER_URL") or None

# Endpoints
MDE_API_BASE = os.environ.get("MDE_API_BASE", "https://api.securitycenter.microsoft.com")
GRAPH_API_BASE = os.environ.get("GRAPH_API_BASE", "https://graph.microsoft.com/v1.0")
GRAPH_API_BETA = os.environ.get("GRAPH_API_BETA", "https://graph.microsoft.com/beta")

CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "http://localhost:5173")

# Authentification multi-comptes (2026-09-07) : le cookie de session (`backend/auth/`,
# `api_server.py::_auth_middleware`) est posé `Secure=False` par défaut, cohérent avec le fait
# que ce dashboard tourne aujourd'hui en HTTP local/LAN (voir le commentaire au-dessus de
# `uvicorn.run(...)` dans api_server.py) — un cookie `Secure=True` ne serait tout simplement
# jamais renvoyé par le navigateur sur une connexion HTTP. À passer à `true` dans `.env`
# uniquement si ce backend est un jour servi derrière HTTPS (reverse proxy, certificat...).
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").strip().lower() == "true"

# Scope ".default" : reprend tel quel les permissions statiquement consenties sur l'app
# registration, que ce soit en app-only (client_credentials) ou en délégué (interactive).
MDE_SCOPES = ["https://api.securitycenter.microsoft.com/.default"]
GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]

# Notifications email (2026-09-08, jalons Vanitas — agent silencieux / nouvelle vuln critique /
# nouvel échec de conformité, voir common/notify.py). Tous optionnels : Nicolas a choisi
# l'email comme canal mais ne le configure pas tout de suite — `send_email` dégrade en no-op
# tant que SMTP_HOST/SMTP_TO sont absents, jamais une erreur au chargement de ce module.
SMTP_HOST = os.environ.get("SMTP_HOST") or None
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME") or None
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD") or None
SMTP_FROM = os.environ.get("SMTP_FROM") or None
SMTP_TO = os.environ.get("SMTP_TO") or None
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").strip().lower() == "true"
