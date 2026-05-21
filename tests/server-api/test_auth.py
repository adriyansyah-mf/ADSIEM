# tests/server-api/test_auth.py
import pytest
from app.core.security import (
    hash_password, verify_password, hash_token,
    create_access_token, decode_token, create_refresh_token
)

def test_password_hash_and_verify():
    h = hash_password("secret123")
    assert verify_password("secret123", h)
    assert not verify_password("wrong", h)

def test_access_token_round_trip():
    token = create_access_token("user-123")
    payload = decode_token(token)
    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"

def test_refresh_token_type():
    token = create_refresh_token("user-123")
    payload = decode_token(token)
    assert payload["type"] == "refresh"

def test_token_hash_is_deterministic():
    assert hash_token("abc") == hash_token("abc")
    assert hash_token("abc") != hash_token("xyz")
