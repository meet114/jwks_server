
import time

import jwt
from fastapi.testclient import TestClient

from app.main import app, store

client = TestClient(app)


def test_root():
    r = client.get("/")
    assert r.status_code == 200
    assert "/jwks.json" in r.json()["endpoints"]


def test_jwks_only_unexpired():
    r = client.get("/jwks.json")
    assert r.status_code == 200
    data = r.json()
    # Only active (unexpired) key should be present
    assert isinstance(data.get("keys"), list)
    assert len(data["keys"]) == 1
    k = data["keys"][0]
    assert k["kty"] == "RSA"
    assert k["use"] == "sig"
    assert k["alg"] == "RS256"
    assert "kid" in k and "n" in k and "e" in k


def test_auth_issues_token_with_kid_in_header():
    r = client.post("/auth")
    assert r.status_code == 200
    token = r.json()["token"]
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers
    # kid should match the store's active key kid
    assert headers["kid"] == store.active.kid


def test_auth_token_verifies_with_jwks_public_key():
    # Get token
    r = client.post("/auth")
    token = r.json()["token"]

    # Build public key from store.active (PEM already holds it)
    pub_pem = store.active.public_pem
    payload = jwt.decode(token, pub_pem, algorithms=["RS256"])
    assert payload["sub"] == "fake-user-123"
    assert payload["scope"] == "demo"
    assert payload["exp"] > int(time.time())


def test_expired_param_uses_expired_key_and_past_exp():
    r = client.post("/auth?expired=1")
    assert r.status_code == 200
    token = r.json()["token"]
    headers = jwt.get_unverified_header(token)
    assert headers["kid"] == store.expired.kid

    # Token should be expired; verify() should raise
    import pytest

    with pytest.raises(jwt.exceptions.ExpiredSignatureError):
        jwt.decode(token, store.expired.public_pem, algorithms=["RS256"])


def test_blackbox_no_body_ok():
    # The spec says: tester will POST /auth with no body; ensure 200 JSON with token
    r = client.post("/auth")
    assert r.status_code == 200
    assert "token" in r.json()
