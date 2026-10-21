"""Génération/vérification du token d'enrôlement + résolution de l'agent authentifié.

Depuis le jalon 3, l'identité d'un agent pour toutes les routes (sauf `/enroll`) est prouvée
par certificat mTLS (CN = agent_id), plus par un token API partagé — voir `get_current_agent`.
Le token d'enrôlement à usage unique (bootstrap de confiance initial) reste inchangé.
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from . import config
from .db import get_db
from .models import Agent, RevokedCertificate


def generate_token() -> str:
    """Secret aléatoire cryptographiquement sûr, url-safe (facile à transporter en JSON/headers)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_match(token: str, token_hash: str) -> bool:
    """Comparaison à temps constant, pour ne pas exposer d'oracle de timing sur le hash."""
    return hmac.compare_digest(hash_token(token), token_hash)


def _extract_cn(peercert: dict) -> str | None:
    """`peercert["subject"]` est un tuple de RDN imbriqués (format renvoyé par
    `ssl.SSLSocket.getpeercert()`), ex. `(((("commonName", "abc123"),),))` — cherche la
    première `commonName` trouvée."""
    for rdn in peercert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def get_current_agent(request: Request, db: Session = Depends(get_db)) -> Agent:
    """Résout l'agent authentifié depuis le certificat mTLS présenté à la connexion TLS
    (CN du certificat = agent_id, imposé par la CA à la signature — voir ca.py).

    Nécessite le monkeypatch de main.py qui glisse le transport brut dans le scope ASGI —
    uvicorn ne l'expose pas nativement (vérifié en conditions réelles au jalon 3).

    🔧 Vérification de révocation ajoutée le 2026-09-08 (revue de sécurité) : `db.get(Agent,
    agent_id)` seul ne suffisait qu'IMPLICITEMENT à couper l'accès d'un poste retiré via
    `DELETE /agents/{id}` (la ligne Agent disparaît, `db.get` renvoie `None`) — mais la couche
    TLS elle-même n'a jamais connaissance de ce retrait : un attaquant en possession de la clé
    privée d'un poste décommissionné pourrait toujours COMPLÉTER le handshake mTLS (le
    certificat chaîne encore jusqu'à la CA, valide jusqu'à expiration naturelle, 90 jours) et
    tenter des requêtes. Vérifié explicitement ici plutôt que de compter sur l'absence de la
    ligne Agent comme seule protection — voir `models.RevokedCertificate`/`routes/agents.py::
    remove_agent`."""
    transport = request.scope.get("transport")
    ssl_object = transport.get_extra_info("ssl_object") if transport else None
    peercert = ssl_object.getpeercert() if ssl_object else None
    agent_id = _extract_cn(peercert) if peercert else None

    if agent_id is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Certificat client mTLS manquant ou invalide."
        )

    serial = (peercert.get("serialNumber") or "").lower()
    if serial and db.get(RevokedCertificate, serial) is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Ce certificat a été révoqué.")

    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Certificat valide mais agent inconnu.")

    # `last_seen` — centralisé ICI plutôt que dans chaque route (2026-09-16, retour de Nicolas :
    # une commande "Journal d'événements" venait de réussir mais "vu il y a" ne bougeait pas).
    # AVANT ce correctif, seul `routes/inventory.py` mettait à jour ce champ — un poll de
    # commande (5 min) ou un rapport de résultat prouvaient pourtant tout autant que l'agent
    # était joignable. `get_current_agent` est le SEUL point de passage commun à toutes les
    # routes authentifiées par certificat agent (inventaire, commandes, activités suspectes,
    # shell...), donc le bon endroit pour que "vu il y a" reflète le dernier contact réel,
    # quelle que soit la route appelée.
    agent.last_seen = datetime.now(timezone.utc)
    db.commit()
    return agent


def get_actor(x_actor: str | None = Header(default=None)) -> str | None:
    """Journal d'activité (2026-09-09) — Vanitas n'a lui-même aucune notion de compte (voir
    `require_shell_token` juste en dessous, un simple secret partagé) : c'est Pandore, qui
    connaît le compte connecté via sa propre session (`request.state.user`), qui transmet ce
    nom dans l'en-tête `X-Actor` à chaque appel de mutation. `None` si absent (route appelée
    sans cet en-tête, ex. un script CLI local) — jamais une erreur, l'acteur affiché retombe
    alors sur "inconnu" côté dashboard plutôt que de bloquer l'action elle-même pour ce
    seul champ d'attribution."""
    return x_actor or None


def require_shell_token(x_shell_token: str | None = Header(default=None)) -> None:
    """Garde-fou jalon 9 — SEULES les routes dashboard qui permettent d'observer/piloter une
    session de terminal déjà ouverte passent par ici (jamais les routes agent, déjà protégées
    par mTLS, ni la simple mise en file de `start_shell_session` qui suit le même modèle que
    les 6 autres commandes). Comparaison à temps constant, même raisonnement que
    `tokens_match` ci-dessus — un secret partagé reste un secret, même simple.

    Réutilisé tel quel au jalon 11 pour gater la LECTURE COMPLÈTE (avec `script_content`) et
    la gestion (création/édition/suppression) du catalogue de règles de conformité
    (`routes/compliance.py`) — définir du code PowerShell qui s'exécute en SYSTEM sur tout le
    parc, sans surveillance, en continu, est au moins aussi sensible qu'une session shell
    observée par un humain, arguably plus. Pas de secret séparé : même backend, même
    utilisateur unique, une deuxième valeur n'isolerait aucune population de confiance
    supplémentaire.

    Si `SHELL_SESSION_TOKEN` n'est pas configuré, refuse tout plutôt que d'ouvrir grand : un
    admin qui active ce jalon doit explicitement définir ce secret dans `.env`, jamais un
    défaut qui laisserait la fonctionnalité la plus puissante du projet sans aucune protection
    par accident."""
    expected = config.SHELL_SESSION_TOKEN
    if not expected or not x_shell_token or not hmac.compare_digest(x_shell_token, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton de session terminal invalide ou manquant.")
