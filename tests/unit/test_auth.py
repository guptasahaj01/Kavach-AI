"""Credentials resolve to immutable application-owned identities."""

import json

from fastapi import HTTPException
import pytest
from pydantic import ValidationError

from kavach_guard.auth import Principal, resolve_principal


def test_no_credential_is_anonymous_and_public(monkeypatch):
    monkeypatch.delenv("KAVACH_API_KEYS", raising=False)
    principal = resolve_principal()
    assert principal.role == "public_user"
    assert not principal.account_ids


def test_credential_resolves_server_owned_identity(monkeypatch):
    monkeypatch.setenv("KAVACH_API_KEYS", json.dumps({
        "local-customer-token": {"principal_id": "customer-1", "role": "authenticated_customer", "account_ids": ["CUST_1001"]}
    }))
    principal = resolve_principal("Bearer local-customer-token")
    assert principal.principal_id == "customer-1"
    assert principal.account_ids == frozenset({"CUST_1001"})
    with pytest.raises(ValidationError):
        principal.role = "admin"


@pytest.mark.parametrize("header", ["Bearer invalid", "Basic credential", "Bearer ", "Bearer token with spaces"])
def test_invalid_credentials_never_become_public_fallback(monkeypatch, header):
    monkeypatch.delenv("KAVACH_API_KEYS", raising=False)
    with pytest.raises(HTTPException) as exc:
        resolve_principal(header)
    assert exc.value.status_code == 401


@pytest.mark.parametrize("config", ["not-json", "[]", '{"token": {"principal_id":"user", "role":"superadmin"}}', '{"token":{"principal_id":"user", "account_ids":["*"]}}'])
def test_malformed_privileged_auth_config_fails_closed(monkeypatch, config):
    monkeypatch.setenv("KAVACH_API_KEYS", config)
    with pytest.raises(HTTPException) as exc:
        resolve_principal("Bearer token")
    assert exc.value.status_code == 503
    assert "token" not in exc.value.detail


def test_principal_forbids_undeclared_authority_fields():
    with pytest.raises(ValidationError):
        Principal(principal_id="customer", permissions="everything")
