
# JWKS Server (Educational)

A JWKS server implementing security best practices for educational purposes:
- RSA key generation with `kid` and expiry
- **AES-256-CBC encryption** of private keys in the database
- RESTful JWKS endpoint serving **only unexpired** public keys
- `/auth` endpoint issuing JWTs signed with the active key
- `?expired=1` to issue a JWT signed by an **expired** key and with an expired `exp`
- **User registration** with UUIDv4 password generation and Argon2 hashing
- **Authentication request logging** to database
- **Rate limiting** (10 requests per second) on `/auth` endpoint

> **Note:** This is for educational purposes. Do not use in production.

## Security Features (Project 3)

### AES Encryption
Private keys are encrypted using AES-256-CBC before storage in the SQLite database. The encryption key is provided via the `NOT_MY_KEY` environment variable.

### User Registration
- `POST /register` endpoint accepts `username` and optional `email`
- Generates a secure UUIDv4 password
- Hashes password using Argon2 before storage
- Returns the plaintext password to the user (one-time only)

### Authentication Logging
All authentication requests to `/auth` are logged with:
- Request IP address
- Timestamp
- User ID (when available)

### Rate Limiting
The `/auth` endpoint enforces a rate limit of 10 requests per second per IP address. Requests exceeding this limit receive HTTP 429 (Too Many Requests).

## Endpoints

- `GET /jwks.json` → JWKS containing only unexpired keys
- `GET /.well-known/jwks.json` → Same as above (standard JWKS path)
- `POST /auth` → Returns `{"token": "<JWT>"}` (rate limited)
  - Optional query param `expired=1` → sign with an expired key and set `exp` in the past
- `POST /register` → Register a new user
  - Request body: `{"username": "user1", "email": "user@example.com"}`
  - Response: `{"password": "<UUID>"}`

Both JWTs include the `kid` header. JWKS entries contain the matching `kid`.

## Run locally

```bash
# Install dependencies
pip install -r requirements.txt

# Set encryption key (REQUIRED for Project 3)
export NOT_MY_KEY="your-secret-key-here"

# Run the server
uvicorn app.main:app --reload --port 8080
```

Or use the provided script:
```bash
./run_server.sh
```

Then test the endpoints:
```bash
# Get JWKS (public keys)
curl http://localhost:8080/jwks.json

# Get authentication token
curl -X POST http://localhost:8080/auth

# Get expired token
curl -X POST "http://localhost:8080/auth?expired=1"

# Register a new user
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com"}'
```

## Tests & Coverage

```bash
# Run tests with coverage (set encryption key)
NOT_MY_KEY="test-key" pytest --cov=app --cov-report=term-missing
```

Expected coverage: **> 90%** (Current: **97%**)

## Blackbox check

The blackbox tester will POST to `/auth` (no body). This server answers 200 with a JSON body containing `"token"`.

## Project layout

```
app/
  main.py        # FastAPI app
  keys.py        # Key store & JWK serialization
  models.py      # Pydantic models
tests/
  test_api.py    # Unit tests
```

## Screenshots (how-to)

1. Start server: `uvicorn app.main:app --port 8080`
2. In another terminal: `curl -X POST http://localhost:8080/auth`
3. Run `pytest --cov=app`.


---

MIT License
