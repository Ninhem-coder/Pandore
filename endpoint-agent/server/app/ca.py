"""Chargement de la CA et signature de CSR — cœur du mTLS (jalon 3).

La CA elle-même (clé + certificat) est générée une seule fois par `scripts/generate_ca.py`,
jamais par ce module. `load_ca()` se contente de la charger depuis le disque pour signer des
CSR à la demande (enrôlement, renouvellement).
"""
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from . import config

CA_DIR = Path(__file__).resolve().parent.parent / "data" / "ca"
CA_KEY_PATH = CA_DIR / "ca-key.pem"
CA_CERT_PATH = CA_DIR / "ca.pem"

AGENT_CERT_VALIDITY_DAYS = 90


class CaNotConfigured(RuntimeError):
    """La CA n'a pas encore été générée (voir scripts/generate_ca.py)."""


def load_ca():
    """Renvoie (clé privée, certificat) de la CA, déchiffrée avec CA_KEY_PASSPHRASE."""
    if not CA_KEY_PATH.exists() or not CA_CERT_PATH.exists():
        raise CaNotConfigured(
            "CA absente — lancer scripts/generate_ca.py avant le premier enrôlement mTLS."
        )
    if not config.CA_KEY_PASSPHRASE:
        raise CaNotConfigured("CA_KEY_PASSPHRASE n'est pas renseignée dans .env.")

    ca_key = serialization.load_pem_private_key(
        CA_KEY_PATH.read_bytes(), password=config.CA_KEY_PASSPHRASE.encode("utf-8")
    )
    ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
    return ca_key, ca_cert


def get_ca_certificate_pem() -> bytes:
    """Le certificat de la CA (public, jamais la clé) — donné aux agents pour qu'ils
    vérifient à leur tour le certificat du serveur."""
    return CA_CERT_PATH.read_bytes()


def sign_csr(csr_pem: bytes, common_name: str) -> bytes:
    """Signe une CSR avec la CA, en imposant NOTRE PROPRE `common_name` (le sujet demandé
    dans la CSR par l'agent n'a aucune valeur — c'est la CA qui décide de l'identité finale,
    toujours `agent_id`, jamais ce que l'agent a demandé). Renvoie le certificat signé en PEM.
    """
    ca_key, ca_cert = load_ca()
    csr = x509.load_pem_x509_csr(csr_pem)

    if not csr.is_signature_valid:
        raise ValueError("CSR invalide (signature incorrecte).")

    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=AGENT_CERT_VALIDITY_DAYS))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.PEM)
