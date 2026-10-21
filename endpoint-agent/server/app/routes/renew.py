"""Renouvellement du certificat d'un agent — authentifié par son certificat mTLS ACTUEL
(encore valide), pas par un token. Même mécanisme d'identification que le reste des routes
protégées (`get_current_agent`) — pas un chemin d'auth séparé."""
from cryptography import x509
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import ca
from ..db import get_db
from ..models import Agent
from ..security import get_current_agent

router = APIRouter(tags=["renew"])


class RenewRequest(BaseModel):
    csr_pem: str


class RenewResponse(BaseModel):
    certificate_pem: str


@router.post("/agents/{agent_id}/renew", response_model=RenewResponse)
def renew(
    agent_id: str,
    payload: RenewRequest,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> RenewResponse:
    # Même contrôle anti-usurpation que /inventory : le certificat présenté doit correspondre
    # à L'AGENT du chemin, pas juste être un certificat valide quelconque.
    if agent.id != agent_id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Ce certificat ne correspond pas à cet agent."
        )

    try:
        cert_pem = ca.sign_csr(payload.csr_pem.encode("utf-8"), common_name=agent.id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except ca.CaNotConfigured as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc

    cert = x509.load_pem_x509_certificate(cert_pem)
    agent.cert_serial = format(cert.serial_number, "x")
    agent.cert_not_after = cert.not_valid_after_utc
    db.commit()

    return RenewResponse(certificate_pem=cert_pem.decode("utf-8"))
