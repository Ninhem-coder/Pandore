"""Génère la CA racine + le certificat serveur — à lancer UNE SEULE FOIS.

⚠️ Régénérer la CA invalide TOUS les certificats déjà émis (agents ET serveur) — refuse de
s'exécuter si une CA existe déjà, sauf `--force` explicite.

Usage (depuis `endpoint-agent/server/`) :
    .venv/Scripts/python.exe scripts/generate_ca.py
    .venv/Scripts/python.exe scripts/generate_ca.py --force  # regénère et invalide tout
"""
import argparse
import datetime
import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID  # noqa: E402

CA_DIR = Path(__file__).resolve().parent.parent / "data" / "ca"
CA_VALIDITY_DAYS = 3650  # 10 ans — c'est la CA elle-même, pas un certificat agent
SERVER_CERT_VALIDITY_DAYS = 825  # ~2 ans, généreux pour un serveur qu'on ne renouvelle pas
SERVER_COMMON_NAME = "localhost"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force", action="store_true", help="Regénérer même si une CA existe déjà (DANGEREUX)."
    )
    args = parser.parse_args()

    ca_key_path = CA_DIR / "ca-key.pem"
    ca_cert_path = CA_DIR / "ca.pem"

    if ca_key_path.exists() and not args.force:
        print(
            f"Une CA existe déjà ({ca_cert_path}). Relancer avec --force pour la remplacer "
            "(invalide alors TOUS les certificats déjà émis)."
        )
        sys.exit(1)

    if not config.CA_KEY_PASSPHRASE:
        print("CA_KEY_PASSPHRASE n'est pas renseignée dans .env — impossible de continuer.")
        sys.exit(1)

    CA_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    # --- CA racine ---
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "EndpointAgent Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(config.CA_KEY_PASSPHRASE.encode("utf-8")),
        )
    )
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    # --- Certificat serveur (utilisé par uvicorn pour le TLS de la connexion elle-même) ---
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, SERVER_COMMON_NAME)])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=SERVER_CERT_VALIDITY_DAYS))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    (CA_DIR / "server-key.pem").write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    (CA_DIR / "server.pem").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

    print(f"CA générée dans {CA_DIR}")
    print(" - ca.pem / ca-key.pem (chiffrée)")
    print(" - server.pem / server-key.pem")


if __name__ == "__main__":
    main()
