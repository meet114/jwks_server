
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from app.keys import KeyStore
from app.models import JWKS, TokenResponse

app = FastAPI(title="Educational JWKS Server", version="0.1.0")
store = KeyStore()

@app.get("/jwks.json", response_model=JWKS)
def get_jwks():
    """Serve JWKS containing only unexpired keys."""
    return JWKS(keys=store.jwks())

@app.post("/auth", response_model=TokenResponse)
def post_auth(expired: bool = Query(default=False, description="Sign with expired key & exp")):
    """Return a signed JWT. If `expired=1`, use an expired key and past exp."""
    token, _kid = store.sign_jwt(use_expired=bool(expired))
    return TokenResponse(token=token)

# Root for quick sanity check
@app.get("/")
def root():
    return {"ok": True, "endpoints": ["/jwks.json", "/auth"]}
