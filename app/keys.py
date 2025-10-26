
"""SQLite-backed JWKS key store.

This module persists RSA private keys (PEM-encoded) into a local SQLite database
(totally_not_my_privateKeys.db) with an expiry timestamp (epoch seconds). It returns JWKS
constructed from valid (non-expired) keys and signs JWTs with either valid or expired keys.

Security: All SQL statements use parameterized queries to prevent SQL injection.
Schema:
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
"""

import base64
import hashlib
import sqlite3
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ----- Helpers -----

def _b64url_uint(data: int) -> str:
    """Base64url encode an unsigned big-endian integer without padding."""
    # Convert int -> big-endian bytes
    nbytes = (data.bit_length() + 7) // 8
    b = data.to_bytes(nbytes, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii") if b else "AA"


def _thumbprint_jwk_rsa(n: int, e: int) -> str:
    """Create deterministic kid from JWK SHA-256 thumbprint (RFC 7638)."""
    # Canonical JSON string with ordered keys
    obj = f'{{"e":"{_b64url_uint(e)}","kty":"RSA","n":"{_b64url_uint(n)}"}}'
    digest = hashlib.sha256(obj.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass
class RSAKeyRecord:
    """In-memory representation of a single RSA key with expiry and kid."""
    private_pem: bytes
    public_pem: bytes
    kid: str
    not_after: int  # epoch seconds

    def public_jwk(self) -> Dict[str, str]:
        """Return the public JWK dict for this RSA key suitable for JWKS output."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        pub = serialization.load_pem_public_key(self.public_pem)
        assert isinstance(pub, rsa.RSAPublicKey)
        numbers = pub.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "kid": self.kid,
            "alg": "RS256",
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }


class KeyStore:
    """SQLite-backed key store.

    - Creates/opens the DB file `totally_not_my_privateKeys.db` at startup.
    - Ensures at least one expired key and one valid key exist.
    - Provides JWKS (only valid keys) and JWT signing (valid/expired).
    """

    def __init__(self) -> None:
        # Open/create the SQLite DB in the current working directory
        self.db_path = "totally_not_my_privateKeys.db"
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()
        self._ensure_keys()

        # Cache one active and one expired record for tests and convenience
        now = int(time.time())
        self.active = self._select_one(exp_comparison=">", now_value=now)
        self.expired = self._select_one(exp_comparison="<=", now_value=now)

    def _init_db(self) -> None:
        """Create the required table schema if it does not exist."""
        # Use a static DDL string; no user inputs involved here
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )
        self.conn.commit()

    def _ensure_keys(self) -> None:
        """Ensure the DB has at least one expired and one valid key persisted."""
        cur = self.conn.execute("SELECT COUNT(*) FROM keys")
        (count,) = cur.fetchone()
        if count == 0:
            now = int(time.time())
            # Generate active (valid for >=1 hour) and expired (expired 1 hour ago)
            active_rec = self._generate_keypair(not_after=now + 3600)
            expired_rec = self._generate_keypair(not_after=now - 3600)
            # Persist private key PEM and expiry using parameterized queries
            self.conn.execute(
                "INSERT INTO keys(key, exp) VALUES(?, ?)",
                (active_rec.private_pem, active_rec.not_after),
            )
            self.conn.execute(
                "INSERT INTO keys(key, exp) VALUES(?, ?)",
                (expired_rec.private_pem, expired_rec.not_after),
            )
            self.conn.commit()

    def _select_one(self, *, exp_comparison: str, now_value: int) -> RSAKeyRecord:
        """Select one key by expiry policy.

        Args:
            exp_comparison: Internal operator ('>' for valid, '<=' for expired).
            now_value: The current epoch seconds used for comparison.

        Returns:
            RSAKeyRecord for a matching DB key; regenerates if none found.
        """
        # Control the operator internally; bind values as parameters
        order = "ASC" if exp_comparison == ">" else "DESC"
        query = (
            "SELECT key, exp FROM keys WHERE exp "
            f"{exp_comparison} ? ORDER BY exp {order} LIMIT 1"
        )
        cur = self.conn.execute(query, (now_value,))
        row = cur.fetchone()
        if not row:
            # Fallback: regenerate a key with a suitable expiry
            regen = self._generate_keypair(
                not_after=now_value + (3600 if exp_comparison == ">" else -3600)
            )
            return regen
        private_pem, exp = row[0], row[1]
        return self._record_from_private_pem(private_pem=private_pem, not_after=exp)

    def _record_from_private_pem(self, *, private_pem: bytes, not_after: int) -> RSAKeyRecord:
        """Build an RSAKeyRecord from a PEM private key and expiry."""
        priv = serialization.load_pem_private_key(private_pem, password=None)
        pub = priv.public_key()
        public_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        numbers = pub.public_numbers()
        kid = _thumbprint_jwk_rsa(numbers.n, numbers.e)
        return RSAKeyRecord(
            private_pem=private_pem,
            public_pem=public_pem,
            kid=kid,
            not_after=not_after,
        )

    # ---- Public API ----

    def jwks(self) -> List[Dict[str, str]]:
        """Return public JWKs for all valid (non-expired) keys from the database."""
        now = int(time.time())
        keys: List[Dict[str, str]] = []
        cur = self.conn.execute("SELECT key, exp FROM keys WHERE exp > ?", (now,))
        for private_pem, exp in cur.fetchall():
            rec = self._record_from_private_pem(private_pem=private_pem, not_after=exp)
            keys.append(rec.public_jwk())
        return keys

    def sign_jwt(self, *, use_expired: bool = False) -> Tuple[str, str]:
        """Sign and return a JWT using a DB-backed key.

        If use_expired=True, pick an expired key and set token exp in the past.
        Otherwise, pick a valid key and set exp in the future.
        """
        now = int(time.time())
        if use_expired:
            rec = self._select_one(exp_comparison="<=", now_value=now)
            exp = now - 600  # already expired
        else:
            rec = self._select_one(exp_comparison=">", now_value=now)
            exp = now + 900  # 15 min

        headers = {"kid": rec.kid, "alg": "RS256"}
        payload = {"sub": "fake-user-123", "iat": now, "exp": exp, "scope": "demo"}
        token = jwt.encode(
            payload,
            rec.private_pem,
            algorithm="RS256",
            headers=headers,
        )
        return token, rec.kid

    def _generate_keypair(self, *, not_after: int) -> RSAKeyRecord:
        """Generate an RSA keypair and return an RSAKeyRecord with expiry."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = priv.public_key()
        public_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        numbers = pub.public_numbers()
        kid = _thumbprint_jwk_rsa(numbers.n, numbers.e)
        return RSAKeyRecord(
            private_pem=private_pem,
            public_pem=public_pem,
            kid=kid,
            not_after=not_after,
        )
