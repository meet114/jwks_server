
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
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import jwt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

# ----- AES Encryption Helpers -----

def _get_aes_key() -> bytes:
    """Get the AES encryption key from environment variable NOT_MY_KEY.

    Returns a 32-byte key derived from the environment variable.
    Falls back to a default key if NOT_MY_KEY is not set (for development only).
    """
    key_str = os.environ.get("NOT_MY_KEY", "default-key-for-development-only-never-use-in-production")
    # Derive a 32-byte key using SHA-256
    return hashlib.sha256(key_str.encode()).digest()


def _encrypt_aes(plaintext: bytes) -> bytes:
    """Encrypt plaintext using AES-256-CBC with PKCS7 padding.

    Args:
        plaintext: The data to encrypt (typically a PEM private key).

    Returns:
        Encrypted data with IV prepended (IV is first 16 bytes).
    """
    key = _get_aes_key()
    iv = os.urandom(16)  # Random 16-byte IV for CBC mode

    # Apply PKCS7 padding
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt with AES-256-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Prepend IV to ciphertext for storage
    return iv + ciphertext


def _decrypt_aes(ciphertext_with_iv: bytes) -> bytes:
    """Decrypt AES-256-CBC encrypted data with PKCS7 padding.

    Args:
        ciphertext_with_iv: Encrypted data with IV prepended (IV is first 16 bytes).

    Returns:
        Decrypted plaintext.
    """
    key = _get_aes_key()
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    # Decrypt with AES-256-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext


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
        self._local = threading.local()
        self._lock = threading.Lock()
        # Create initial connection to set up database
        conn = self._get_conn()
        self._init_db()
        self._ensure_keys()

        # Cache one active and one expired record for tests and convenience
        now = int(time.time())
        self.active = self._select_one(exp_comparison=">", now_value=now)
        self.expired = self._select_one(exp_comparison="<=", now_value=now)

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0,
                isolation_level=None  # Autocommit mode
            )
            # Use DELETE mode instead of WAL for better compatibility with external readers
            self._local.conn.execute("PRAGMA journal_mode=DELETE")
            self._local.conn.execute("PRAGMA synchronous=FULL")
        return self._local.conn

    def _init_db(self) -> None:
        """Create the required table schema if it does not exist."""
        # Use a static DDL string; no user inputs involved here
        self._get_conn().execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )
        # Create users table for user registration
        self._get_conn().execute(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
            """
        )
        # Create auth_logs table for logging authentication requests
        self._get_conn().execute(
            """
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )

    def _ensure_keys(self) -> None:
        """Ensure the DB has at least one expired and one valid key persisted."""
        cur = self._get_conn().execute("SELECT COUNT(*) FROM keys")
        (count,) = cur.fetchone()
        if count == 0:
            now = int(time.time())
            # Generate active (valid for >=1 hour) and expired (expired 1 hour ago)
            active_rec = self._generate_keypair(not_after=now + 3600)
            expired_rec = self._generate_keypair(not_after=now - 3600)
            # Encrypt and persist private key PEM and expiry using parameterized queries
            encrypted_active = _encrypt_aes(active_rec.private_pem)
            encrypted_expired = _encrypt_aes(expired_rec.private_pem)
            self._get_conn().execute(
                "INSERT INTO keys(key, exp) VALUES(?, ?)",
                (encrypted_active, active_rec.not_after),
            )
            self._get_conn().execute(
                "INSERT INTO keys(key, exp) VALUES(?, ?)",
                (encrypted_expired, expired_rec.not_after),
            )

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
        cur = self._get_conn().execute(query, (now_value,))
        row = cur.fetchone()
        if not row:
            # Fallback: regenerate a key with a suitable expiry
            regen = self._generate_keypair(
                not_after=now_value + (3600 if exp_comparison == ">" else -3600)
            )
            return regen
        encrypted_key, exp = row[0], row[1]
        # Decrypt the private key before using it
        private_pem = _decrypt_aes(encrypted_key)
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
        cur = self._get_conn().execute("SELECT key, exp FROM keys WHERE exp > ?", (now,))
        for encrypted_key, exp in cur.fetchall():
            # Decrypt the private key before using it
            private_pem = _decrypt_aes(encrypted_key)
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

    # ---- User Management ----

    def register_user(self, *, username: str, email: Optional[str]) -> str:
        """Register a new user with a generated UUIDv4 password.

        Args:
            username: The username for the new user.
            email: The optional email address for the new user.

        Returns:
            The generated UUIDv4 password (plaintext) to be returned to the user.

        Raises:
            sqlite3.IntegrityError: If username or email already exists.
        """
        # Generate a secure UUIDv4 password
        password = str(uuid.uuid4())

        # Hash the password using Argon2
        ph = PasswordHasher()
        password_hash = ph.hash(password)

        # Insert the user into the database using parameterized query
        self._get_conn().execute(
            "INSERT INTO users(username, password_hash, email) VALUES(?, ?, ?)",
            (username, password_hash, email),
        )

        return password

    def get_user_id_by_username(self, *, username: str) -> Optional[int]:
        """Get user ID by username.

        Args:
            username: The username to look up.

        Returns:
            The user ID if found, None otherwise.
        """
        cur = self._get_conn().execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row[0] if row else None

    def log_auth_request(self, *, request_ip: str, user_id: Optional[int] = None) -> None:
        """Log an authentication request to the auth_logs table.

        Args:
            request_ip: The IP address of the request.
            user_id: The optional user ID if known.
        """
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO auth_logs(request_ip, user_id) VALUES(?, ?)",
                (request_ip, user_id),
            )
