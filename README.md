
# JWKS Server (Educational)

A minimal JWKS server demonstrating:
- RSA key generation with `kid` and expiry
- RESTful JWKS endpoint serving **only unexpired** public keys
- `/auth` endpoint issuing JWTs signed with the active key
- `?expired=1` to issue a JWT signed by an **expired** key and with an expired `exp`

> **Note:** This is for educational purposes. Do not use in production.

## Endpoints

- `GET /jwks.json` → JWKS containing only unexpired keys.
- `POST /auth` → Returns `{"token": "<JWT>"}`.
  - Optional query param `expired=1` → sign with an expired key and set `exp` in the past.

Both JWTs include the `kid` header. JWKS entries contain the matching `kid`.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

Then:
```bash
curl -X POST http://localhost:8080/auth
curl http://localhost:8080/jwks.json
```

Expired token:
```bash
curl -X POST "http://localhost:8080/auth?expired=1"
```

## Tests & Coverage

```bash
pytest --cov=app --cov-report=term-missing
```

Expected coverage: **> 90%**

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
