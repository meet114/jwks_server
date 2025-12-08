
import time

import jwt
import pytest
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


def test_register_creates_user_and_returns_password():
    """Test that /register creates a user and returns a UUIDv4 password."""
    r = client.post("/register", json={"username": "testuser1", "email": "test1@example.com"})
    assert r.status_code == 201
    data = r.json()
    assert "password" in data
    # Verify password looks like a UUID
    password = data["password"]
    assert len(password) == 36  # UUIDv4 format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    assert password.count("-") == 4


def test_register_duplicate_username_fails():
    """Test that registering a duplicate username returns 400."""
    # Register first user
    client.post("/register", json={"username": "duplicate_user", "email": "dup1@example.com"})
    # Try to register with same username
    r = client.post("/register", json={"username": "duplicate_user", "email": "dup2@example.com"})
    assert r.status_code == 400


def test_register_without_email():
    """Test that registration works without providing an email."""
    r = client.post("/register", json={"username": "no_email_user"})
    assert r.status_code == 201
    assert "password" in r.json()


def test_auth_logs_request():
    """Test that /auth logs the authentication request."""
    # Get initial count of auth logs
    cur = store.conn.execute("SELECT COUNT(*) FROM auth_logs")
    initial_count = cur.fetchone()[0]

    # Make an auth request
    client.post("/auth")

    # Check that a new log entry was created
    cur = store.conn.execute("SELECT COUNT(*) FROM auth_logs")
    new_count = cur.fetchone()[0]
    assert new_count == initial_count + 1

    # Verify the log entry has the expected fields
    cur = store.conn.execute("SELECT request_ip, user_id FROM auth_logs ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    assert row[0] == "testclient"  # TestClient uses "testclient" as the IP
    # user_id should be None since we don't have auth yet
    assert row[1] is None


def test_rate_limiter_blocks_excessive_requests():
    """Test that the rate limiter blocks requests exceeding 10 per second."""
    from unittest.mock import patch
    from app.main import rate_limit_store

    # Clear rate limit store for this test to start fresh
    rate_limit_store.clear()

    # Mock time to return a fixed value so all requests happen "simultaneously"
    fixed_time = 1700000000.0
    with patch('app.main.time', return_value=fixed_time):
        # Make 10 requests (should all succeed)
        for i in range(10):
            r = client.post("/auth")
            assert r.status_code == 200, f"Request {i+1} failed with status {r.status_code}"

        # The 11th request should be rate limited
        r = client.post("/auth")
        assert r.status_code == 429, f"Expected 429, got {r.status_code}"
        assert "rate limit" in r.json()["detail"].lower()


def test_rate_limiter_resets_after_window():
    """Test that the rate limiter resets after the time window."""
    from unittest.mock import patch
    from app.main import rate_limit_store

    # Clear rate limit store for this test
    rate_limit_store.clear()

    # Make 10 requests at time T
    fixed_time = 1700000000.0
    with patch('app.main.time', return_value=fixed_time):
        for _ in range(10):
            r = client.post("/auth")
            assert r.status_code == 200

    # Try at time T+1.1 seconds (after the window)
    with patch('app.main.time', return_value=fixed_time + 1.1):
        r = client.post("/auth")
        assert r.status_code == 200


def test_private_keys_are_encrypted():
    """Test that private keys in the database are encrypted (not plain PEM)."""
    cur = store.conn.execute("SELECT key FROM keys LIMIT 1")
    encrypted_key = cur.fetchone()[0]

    # Encrypted data should not start with "-----BEGIN" like a PEM key
    assert not encrypted_key.startswith(b"-----BEGIN")

    # Encrypted data should be longer than 16 bytes (IV + ciphertext)
    assert len(encrypted_key) > 16
