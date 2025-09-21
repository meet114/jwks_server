
from pydantic import BaseModel, Field
from typing import List, Dict, Any

class JWKS(BaseModel):
    keys: List[Dict[str, Any]] = Field(default_factory=list)

class TokenResponse(BaseModel):
    token: str
