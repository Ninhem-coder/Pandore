"""Endpoint d'enrôlement : échange un token à usage unique contre un certificat mTLS signé.

La clé privée de l'agent ne transite JAMAIS ici — seule sa CSR (clé publique + demande de
signature) est envoyée ; le certificat renvoyé est apparié à une clé que l'agent a déjà en sa
possession (magasin de certificats Windows, voir agent/Communication/CertificateStore.cs).
"""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import update
from sqlalchemy.orm import Session

from .. import ca
from ..db import get_db
from ..models import Agent, EnrollmentToken
from ..security import hash_token

router = APIRouter(tags=["enrollment"])

# Durée de validité d'un token d'enrôlement (audit sécurité du 2026-09-17, finding #7). Avant, un
# token n'expirait JAMAIS tant qu'il n'était pas consommé : un token généré puis fuité (email,
# presse-papier, capture, journal) restait échangeable indéfiniment contre une identité agent mTLS
# complète. Dérivé de `created_at` (déjà présent en base) plutôt qu'une colonne `expires_at`
# dédiée → aucune migration nécessaire. 72 h couvre largement un enrôlement légitime (génération
# puis installation sur le poste) tout en bornant la fenêtre d'un token fuité.
ENROLLMENT_TOKEN_TTL = timedelta(hours=72)


class EnrollRequest(BaseModel):
    enrollment_token: str
    hostname: str
    csr_pem: str


class EnrollResponse(BaseModel):
    agent_id: str
    certificate_pem: str
    ca_certificate_pem: str


@router.post("/enroll", response_model=EnrollResponse)
def enroll(payload: EnrollRequest, db: Session = Depends(get_db)) -> EnrollResponse:
    token_hash = hash_token(payload.enrollment_token)
    enrollment_token = (
        db.query(EnrollmentToken).filter(EnrollmentToken.token_hash == token_hash).first()
    )

    if enrollment_token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token d'enrôlement invalide.")
    if enrollment_token.used_at is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token d'enrôlement déjà utilisé.")

    # Expiration (audit 2026-09-17, finding #7) — vérifiée AVANT la consommation atomique
    # ci-dessous. `created_at` est stocké aware/UTC (UTCDateTime), on compare donc en UTC.
    created_at = enrollment_token.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - created_at > ENROLLMENT_TOKEN_TTL:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token d'enrôlement expiré.")

    # 🔧 Bug de sécurité corrigé le 2026-09-07 : la vérification `used_at is not None` ci-dessus
    # n'était qu'un SELECT en mémoire, sans verrou ni contrainte — deux requêtes `/enroll`
    # quasi simultanées avec le MÊME token pouvaient toutes les deux la passer avant qu'aucune
    # des deux n'ait encore marqué le token consommé, obtenant chacune un certificat mTLS
    # valide + un agent enrôlé, défaisant la garantie "un token, un usage, un poste". Consommé
    # ICI via un UPDATE conditionnel atomique (`WHERE used_at IS NULL`) et commité SÉPARÉMENT
    # AVANT toute émission de certificat : `rowcount == 1` garantit qu'un seul appelant a pu
    # gagner la course, peu importe le timing. Contrepartie assumée : si la signature du
    # certificat échoue APRÈS ce point, le token reste définitivement consommé (pas de nouvelle
    # tentative avec le même token) — compromis correct pour un jeton à usage unique, plutôt
    # que de rouvrir la fenêtre de course pour permettre un retry.
    now = datetime.now(timezone.utc)
    result = db.execute(
        update(EnrollmentToken)
        .where(EnrollmentToken.token_hash == token_hash, EnrollmentToken.used_at.is_(None))
        .values(used_at=now)
    )
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token d'enrôlement déjà utilisé.")
    db.commit()

    agent = Agent(hostname=payload.hostname)
    db.add(agent)
    db.flush()  # attribue agent.id avant de l'utiliser comme CN du certificat

    try:
        cert_pem = ca.sign_csr(payload.csr_pem.encode("utf-8"), common_name=agent.id)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except ca.CaNotConfigured as exc:
        db.rollback()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc

    cert = x509.load_pem_x509_certificate(cert_pem)
    agent.cert_serial = format(cert.serial_number, "x")
    agent.cert_not_after = cert.not_valid_after_utc

    db.execute(
        update(EnrollmentToken)
        .where(EnrollmentToken.token_hash == token_hash)
        .values(used_by_agent_id=agent.id)
    )

    db.commit()

    return EnrollResponse(
        agent_id=agent.id,
        certificate_pem=cert_pem.decode("utf-8"),
        ca_certificate_pem=ca.get_ca_certificate_pem().decode("utf-8"),
    )
