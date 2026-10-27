"""Application-owned identities for the local security gateway.

Credentials are configured by the operator, never accepted as role declarations in
model output or request bodies. The anonymous identity has public access only.
"""

import hmac
import json
import os
from typing import FrozenSet, Literal, Optional

from fastapi import Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

Role = Literal["public_user", "authenticated_customer", "compliance_auditor", "admin"]


class Principal(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    principal_id: str = Field(min_length=1, max_length=100)
    role: Role = "public_user"
    account_ids: FrozenSet[str] = Field(default_factory=frozenset)
    allowed_destinations: FrozenSet[str] = Field(default_factory=frozenset)

    @field_validator("account_ids", "allowed_destinations")
    @classmethod
    def explicit_resources(cls, values):
        if any(not value.strip() or value != value.strip() or "*" in value for value in values):
            raise ValueError("Resources must be explicit, nonempty identifiers without wildcards")
        return values


ANONYMOUS_PRINCIPAL = Principal(principal_id="anonymous")


def resolve_principal(authorization: Optional[str] = None) -> Principal:
    """Resolve an opaque bearer credential against the trusted environment map.

    KAVACH_API_KEYS is a JSON object of token -> Principal fields. It contains
    secrets and is intentionally never returned through the public config API.
    """
    if authorization is None:
        return ANONYMOUS_PRINCIPAL
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token or any(c.isspace() for c in token):
        raise HTTPException(status_code=401, detail="A valid bearer credential is required")

    try:
        configured = json.loads(os.getenv("KAVACH_API_KEYS", "{}"))
        if not isinstance(configured, dict):
            raise ValueError("Expected an identity map")
        identities = []
        for configured_token, identity in configured.items():
            if not isinstance(configured_token, str) or not configured_token or any(c.isspace() for c in configured_token):
                raise ValueError("Invalid configured credential")
            identities.append((configured_token, Principal.model_validate(identity)))
    except (ValueError, TypeError, ValidationError):
        raise HTTPException(status_code=503, detail="Authentication configuration is unavailable") from None

    for configured_token, principal in identities:
        if hmac.compare_digest(token.encode("utf-8"), configured_token.encode("utf-8")):
            return principal
    raise HTTPException(status_code=401, detail="Invalid bearer credential")


def get_principal(authorization: Optional[str] = Header(default=None)) -> Principal:
    return resolve_principal(authorization)
