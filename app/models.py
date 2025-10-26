
"""Pydantic models for API responses.

- JWKS: JSON Web Key Set envelope holding a list of public JWK dicts.
- TokenResponse: Response containing a signed JWT string.
"""

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class JWKS(BaseModel):
    """JWKS envelope with a list of public JWK objects."""
    keys: List[Dict[str, Any]] = Field(default_factory=list)

class TokenResponse(BaseModel):
    """Single-field response wrapping the signed JWT."""
    token: str
