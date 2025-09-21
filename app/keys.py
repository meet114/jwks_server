
import time
import base64
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt

# ----- Helpers -----

def _b64url_uint(data: int) -> str:
    """Base64url encode an unsigned big-endian integer (no padding)."""
    # Convert int -> big-endian bytes
    nbytes = (data.bit_length() + 7) // 8
    b = data.to_bytes(nbytes, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii") if b else "AA"

def _thumbprint_jwk_rsa(n: int, e: int) -> str:
    """Create a deterministic kid: JWK SHA-256 thumbprint (RFC 7638)."""
    # Canonical JSON string with ordered keys
    obj = f'{{"e":"{_b64url_uint(e)}","kty":"RSA","n":"{_b64url_uint(n)}"}}'
    digest = hashlib.sha256(obj.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass
class RSAKeyRecord:
    private_pem: bytes
    public_pem: bytes
    kid: str
    not_after: int  # epoch seconds

    def public_jwk(self) -> Dict[str, str]:
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
    """In-memory key store with one active and one expired key for demo."""
    def __init__(self) -> None:
        now = int(time.time())
        # Active key: valid for 24 hours
        self.active = self._generate_keypair(not_after=now + 24*3600)
        # Expired key: expired 1 hour ago
        self.expired = self._generate_keypair(not_after=now - 3600)

    def _generate_keypair(self, *, not_after: int) -> RSAKeyRecord:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        numbers = priv.public_key().public_numbers()
        kid = _thumbprint_jwk_rsa(numbers.n, numbers.e)
        return RSAKeyRecord(private_pem=private_pem, public_pem=public_pem, kid=kid, not_after=not_after)

    # ---- Public API ----

    def jwks(self) -> List[Dict[str, str]]:
        """Return only unexpired public JWKs."""
        now = int(time.time())
        keys = []
        if self.active.not_after > now:
            keys.append(self.active.public_jwk())
        # Add others here if rotating; this demo exposes only active if unexpired.
        return keys

    def sign_jwt(self, *, use_expired: bool = False) -> Tuple[str, str]:
        """Return (token, kid). If use_expired, sign with expired key and expired exp."""
        now = int(time.time())
        if use_expired:
            rec = self.expired
            exp = now - 600  # already expired
        else:
            rec = self.active
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
