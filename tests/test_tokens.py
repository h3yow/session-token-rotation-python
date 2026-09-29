"""令牌原语：结构、伪造、过期、时钟偏差容差。"""

from __future__ import annotations

import pytest

from app import tokens
from app.errors import (
    InvalidSignatureError,
    InvalidTokenError,
    TokenExpiredError,
)


def make(token_type=tokens.ACCESS, **over):
    kw = dict(secret="s", token_type=token_type, jti="j1", family_id="f1",
              subject="alice", ttl_seconds=100, now=1000.0)
    kw.update(over)
    return tokens.issue_token(**kw)


def test_issue_and_verify_roundtrip():
    token = make()
    payload = tokens.decode_token(token, secret="s", expected_type=tokens.ACCESS)
    assert payload["jti"] == "j1"
    assert payload["fam"] == "f1"
    assert payload["sub"] == "alice"
    assert payload["exp"] - payload["iat"] == 100


def test_wrong_secret_is_signature_error():
    token = make()
    with pytest.raises(InvalidSignatureError):
        tokens.decode_token(token, secret="wrong")


def test_tampered_signature_is_signature_error():
    token = make()
    flipped = token[:-1] + ("a" if token[-1] != "a" else "b")
    with pytest.raises(InvalidSignatureError):
        tokens.decode_token(flipped, secret="s")


@pytest.mark.parametrize("junk", ["", "abc", "a.b.c", "   ", "123"])
def test_malformed_token(junk):
    with pytest.raises(InvalidTokenError):
        tokens.decode_token(junk, secret="s")


def test_empty_signature_segment_is_signature_error():
    # 两段结构但签名段为空：属于签名不匹配，而不是结构非法
    with pytest.raises(InvalidSignatureError):
        tokens.decode_token("abc.", secret="s")


def test_wrong_token_type():
    token = make(tokens.ACCESS)
    with pytest.raises(InvalidTokenError):
        tokens.decode_token(token, secret="s", expected_type=tokens.REFRESH)


def test_expiry_without_leeway():
    payload = {"jti": "j1", "exp": 1100}
    tokens.check_expiry(payload, now=1100.0, leeway=0)  # 边界不过期
    with pytest.raises(TokenExpiredError):
        tokens.check_expiry(payload, now=1100.1, leeway=0)


def test_expiry_with_clock_skew_leeway():
    payload = {"jti": "j1", "exp": 1100}
    # 服务端时钟比客户端快 29 秒，在 30 秒容差内，不得误判过期
    tokens.check_expiry(payload, now=1129.0, leeway=30)
    tokens.check_expiry(payload, now=1130.0, leeway=30)  # 边界恰好容差
    with pytest.raises(TokenExpiredError):
        tokens.check_expiry(payload, now=1130.5, leeway=30)
