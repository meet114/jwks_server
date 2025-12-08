
"""FastAPI application exposing JWKS and JWT issuance endpoints.

This app serves:
- GET /jwks.json and GET /.well-known/jwks.json: JWKS built from valid keys persisted in SQLite.
- POST /auth: issues a JWT, optionally signed with an expired key when `expired=1`.
- POST /register: registers a new user and returns a generated password.

Backed by app.keys.KeyStore which persists private keys in `totally_not_my_privateKeys.db` using
parameterized SQL queries to prevent injection.
"""

import sqlite3
from collections import defaultdict
from time import time

from fastapi import FastAPI, HTTPException, Query, Request, status

from app.keys import KeyStore
from app.models import JWKS, RegisterRequest, RegisterResponse, TokenResponse

app = FastAPI(title="Educational JWKS Server", version="0.1.0")
store = KeyStore()

# Rate limiter: track requests per IP in a time window
rate_limit_store: dict = defaultdict(list)
RATE_LIMIT_WINDOW = 1.0  # 1 second
RATE_LIMIT_MAX_REQUESTS = 10  # 10 requests per second

@app.get("/jwks.json", response_model=JWKS)
def get_jwks():
    """Serve JWKS containing only unexpired keys."""
    return JWKS(keys=store.jwks())

@app.get("/.well-known/jwks.json", response_model=JWKS)
def get_jwks_well_known():
    """Serve JWKS at the well-known path, containing only unexpired keys."""
    return JWKS(keys=store.jwks())

@app.post("/auth", response_model=TokenResponse)
def post_auth(
    request: Request,
    expired: bool = Query(default=False, description="Sign with expired key & exp")
):
    """Return a signed JWT. If `expired=1`, use an expired key and past exp."""
    # Rate limiting: check requests from this IP
    client_ip = request.client.host if request.client else "unknown"
    now = time()

    # Clean up old entries outside the time window
    rate_limit_store[client_ip] = [
        timestamp for timestamp in rate_limit_store[client_ip]
        if now - timestamp < RATE_LIMIT_WINDOW
    ]

    # Check if rate limit exceeded BEFORE adding the current timestamp
    if len(rate_limit_store[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
        # Don't add this request to the store since it's rate limited
        # Don't log this request either (only successful requests are logged)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )

    # Sign the JWT
    token, _kid = store.sign_jwt(use_expired=bool(expired))

    # Add current request timestamp AFTER successful processing
    rate_limit_store[client_ip].append(now)

    # Log the authentication request (only successful requests)
    store.log_auth_request(request_ip=client_ip, user_id=None)

    return TokenResponse(token=token)


@app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def post_register(req: RegisterRequest):
    """Register a new user and return a generated UUIDv4 password.

    Args:
        req: The registration request with username and optional email.

    Returns:
        A response containing the generated password.

    Raises:
        HTTPException: 400 if username or email already exists.
    """
    try:
        password = store.register_user(username=req.username, email=req.email)
        return RegisterResponse(password=password)
    except sqlite3.IntegrityError as e:
        # Username or email already exists
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username or email already exists: {e}"
        )


# Root for quick sanity check
@app.get("/")
def root():
    """Return a simple list of discoverable endpoints for quick sanity checks."""
    return {"ok": True, "endpoints": ["/jwks.json", "/.well-known/jwks.json", "/auth", "/register"]}
