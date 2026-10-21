"""Token d'enrôlement (2026-09-12) — génération (jamais stocké en clair) et usage unique.

Régression-test du correctif de sécurité du 2026-09-07 (consommation atomique `WHERE used_at
IS NULL`) : un token ne doit être exploitable qu'UNE fois. `/enroll` n'exige pas de mTLS
(c'est le bootstrap de confiance), il est donc testable via TestClient — contrairement aux
routes agent authentifiées par certificat client."""
from datetime import datetime, timedelta, timezone

from app import models
from app.security import hash_token


def test_create_token_requires_auth(client):
    assert client.post("/enrollment-tokens").status_code == 401


def test_created_token_is_stored_hashed_only(client, db, auth_headers):
    r = client.post("/enrollment-tokens", headers=auth_headers)
    assert r.status_code == 200
    token = r.json()["token"]
    assert token  # renvoyé une fois, en clair, dans la réponse

    rows = db.query(models.EnrollmentToken).all()
    assert len(rows) == 1
    # jamais le token en clair en base — seulement son SHA-256
    assert rows[0].token_hash == hash_token(token)
    assert token not in {rows[0].token_hash}
    assert rows[0].used_at is None


def test_enroll_unknown_token_rejected(client):
    r = client.post(
        "/enroll", json={"enrollment_token": "inexistant", "hostname": "PC", "csr_pem": "x"}
    )
    assert r.status_code == 401


def test_enroll_token_is_single_use(client, auth_headers):
    token = client.post("/enrollment-tokens", headers=auth_headers).json()["token"]
    body = {"enrollment_token": token, "hostname": "PC-TEST", "csr_pem": "pas-une-vraie-csr"}

    # 1er appel : le token est consommé (used_at posé, committé) AVANT la signature du certificat
    # — l'issue exacte dépend de l'état de la CA (503 non configurée / 400 CSR invalide / 200
    # signée), mais JAMAIS 401 : le token était valide et inutilisé.
    first = client.post("/enroll", json=body)
    assert first.status_code != 401

    # 2e appel, même token → rejeté "déjà utilisé", quelle qu'ait été l'issue du 1er.
    second = client.post("/enroll", json=body)
    assert second.status_code == 401


def test_enroll_expired_token_rejected(client, db, auth_headers):
    """Audit sécurité du 2026-09-17 (finding #7) — un token dont `created_at` dépasse le TTL
    (72 h) est refusé AVANT consommation, et reste inutilisé en base (pas de `used_at` posé)."""
    token = client.post("/enrollment-tokens", headers=auth_headers).json()["token"]
    row = db.query(models.EnrollmentToken).filter(
        models.EnrollmentToken.token_hash == hash_token(token)
    ).first()
    # Antidater la création au-delà du TTL.
    row.created_at = datetime.now(timezone.utc) - timedelta(hours=73)
    db.commit()

    r = client.post(
        "/enroll", json={"enrollment_token": token, "hostname": "PC-TEST", "csr_pem": "x"}
    )
    assert r.status_code == 401
    assert "expir" in r.json()["detail"].lower()

    # Token expiré = jamais consommé : `used_at` reste nul (pas de faux "déjà utilisé").
    db.refresh(row)
    assert row.used_at is None


def test_enroll_fresh_token_within_ttl_not_rejected_for_expiry(client, db, auth_headers):
    """Un token récent (bien dans le TTL) ne doit JAMAIS être rejeté pour expiration — garde-fou
    anti-régression contre un TTL trop court ou une comparaison de fuseau inversée."""
    token = client.post("/enrollment-tokens", headers=auth_headers).json()["token"]
    body = {"enrollment_token": token, "hostname": "PC-TEST", "csr_pem": "pas-une-vraie-csr"}
    r = client.post("/enroll", json=body)
    # L'issue dépend de l'état de la CA (503/400/200) mais JAMAIS 401 pour un token frais valide.
    assert r.status_code != 401
