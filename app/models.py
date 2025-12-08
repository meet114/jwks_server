
"""Pydantic models for API requests and responses.

- JWKS: JSON Web Key Set envelope holding a list of public JWK dicts.
- TokenResponse: Response containing a signed JWT string.
- RegisterRequest: Request body for user registration.
- RegisterResponse: Response containing the generated password.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class JWKS(BaseModel):
    """JWKS envelope with a list of public JWK objects."""
    keys: List[Dict[str, Any]] = Field(default_factory=list)


class TokenResponse(BaseModel):
    """Single-field response wrapping the signed JWT."""
    token: str


class RegisterRequest(BaseModel):
    """Request body for user registration."""
    username: str = Field(..., description="The username for the new user")
    email: Optional[str] = Field(None, description="The optional email address")


class RegisterResponse(BaseModel):
    """Response containing the generated password."""
    password: str = Field(..., description="The generated UUIDv4 password")
