"""Génération de tokens d'enrôlement depuis le dashboard (2026-09-11, demande de Nicolas —
"que se soit plus simple à mettre en place via une page sur Vanitas directement").

Distinct de `routes/enrollment.py` (qui expose `/enroll`, la route PUBLIQUE consommée par
l'agent lui-même pour échanger le token contre un certificat) — cette route-ci est côté
DASHBOARD, protégée par `require_shell_token` comme le reste des routes de gestion du parc, et
ne fait que GÉNÉRER le token. Remplace l'usage courant de `scripts/create_enrollment_token.py`
(toujours disponible, utile hors réseau ou pour un usage scripté) par un bouton web — même
logique de génération (`generate_token`/`hash_token`), pas un second mécanisme.

Le token en clair n'est JAMAIS stocké — seul son hash SHA-256 (`EnrollmentToken.token_hash`,
vérifié par `enrollment.py::enroll`). Cette route est le SEUL moment où il existe en clair :
renvoyé une fois dans la réponse, jamais consultable après coup — même contrat qu'un jeton
d'API classique ("copie-le maintenant, il ne sera plus jamais affiché")."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..models import EnrollmentToken
from ..security import generate_token, get_actor, hash_token, require_shell_token

router = APIRouter(tags=["enrollment-tokens"])


class EnrollmentTokenOut(BaseModel):
    token: str


@router.post(
    "/enrollment-tokens",
    response_model=EnrollmentTokenOut,
    dependencies=[Depends(require_shell_token)],
)
def create_enrollment_token(
    db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> EnrollmentTokenOut:
    token = generate_token()
    db.add(EnrollmentToken(token_hash=hash_token(token)))
    # Label du journal : derniers caractères du token seulement (jamais le token entier en
    # clair dans une table lue par n'importe quel compte ayant accès au Journal d'activité) —
    # ~48 bits de ce fragment ne réduisent pas matériellement les 256 bits d'entropie du token
    # généré par `secrets.token_urlsafe(32)`, juste assez pour distinguer deux générations dans
    # le journal.
    audit.record_event(db, "poste", "enrollment_token_created", f"Token d'enrôlement (…{token[-8:]})", actor=actor)
    db.commit()
    return EnrollmentTokenOut(token=token)
