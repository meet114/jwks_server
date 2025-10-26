
"""FastAPI application exposing JWKS and JWT issuance endpoints.

This app serves:
- GET /jwks.json and GET /.well-known/jwks.json: JWKS built from valid keys persisted in SQLite.
- POST /auth: issues a JWT, optionally signed with an expired key when `expired=1`.

Backed by app.keys.KeyStore which persists private keys in `totally_not_my_privateKeys.db` using
parameterized SQL queries to prevent injection.
"""

from fastapi import FastAPI, Query

from app.keys import KeyStore
from app.models import JWKS, TokenResponse

app = FastAPI(title="Educational JWKS Server", version="0.1.0")
store = KeyStore()

@app.get("/jwks.json", response_model=JWKS)
def get_jwks():
    """Serve JWKS containing only unexpired keys."""
    return JWKS(keys=store.jwks())

@app.get("/.well-known/jwks.json", response_model=JWKS)
def get_jwks_well_known():
    """Serve JWKS at the well-known path, containing only unexpired keys."""
    return JWKS(keys=store.jwks())

@app.post("/auth", response_model=TokenResponse)
def post_auth(expired: bool = Query(default=False, description="Sign with expired key & exp")):
    """Return a signed JWT. If `expired=1`, use an expired key and past exp."""
    token, _kid = store.sign_jwt(use_expired=bool(expired))
    return TokenResponse(token=token)

# Root for quick sanity check
@app.get("/")
def root():
    """Return a simple list of discoverable endpoints for quick sanity checks."""
    return {"ok": True, "endpoints": ["/jwks.json", "/.well-known/jwks.json", "/auth"]}
