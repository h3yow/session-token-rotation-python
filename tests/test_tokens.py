"""令牌层单测：签发、验签、伪造、过期与时钟偏差。"""

from __future__ import annotations

import time
import uuid

import pytest

from auth.errors import (
    TokenExpiredError,
    TokenMalformedError,
)
from auth.tokens import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    TokenClaims,
    check_expiry,
    decode_token,
    encode_token,
)

SECRET = "unit-secret"
NOW = 1_000_000


def make_claims(token_type: str = "access", *, iat: int = NOW, exp: int = NOW + 100) -> TokenClaims:
    return TokenClaims(
        token_id=uuid.uuid4().hex,
        session_id=uuid.uuid4().hex,
        family_id=uuid.uuid4().hex,
        subject="alice",
        issued_at=iat,
        expires_at=exp,
        token_type=token_type,
    )


def test_encode_decode_roundtrip() -> None:
    claims = make_claims()
    token = encode_token(claims, SECRET)
    decoded = decode_token(token, SECRET)
    assert decoded == claims


def test_forged_signature_rejected() -> None:
    token = encode_token(make_claims(), SECRET)
    forged = token[:-1] + ("0" if token[-1] != "0" else "1")
    with pytest.raises(TokenMalformedError) as exc:
        decode_token(forged, SECRET)
    assert "签名" in str(exc.value)


def test_wrong_secret_rejected() -> None:
    token = encode_token(make_claims(), SECRET)
    with pytest.raises(TokenMalformedError):
        decode_token(token, "another-secret")


@pytest.mark.parametrize("bad", ["", "abc", "a.b.c", ".", "abc.", ".def"])
def test_malformed_token_rejected(bad: str) -> None:
    with pytest.raises(TokenMalformedError):
        decode_token(bad, SECRET)


def test_unknown_token_type_rejected() -> None:
    claims = make_claims(token_type="weird")  # type: ignore[arg-type]
    token = encode_token(claims, SECRET)
    with pytest.raises(TokenMalformedError):
        decode_token(token, SECRET)


def test_expired_outside_skew_window() -> None:
    # 已过期 100s，超出默认 30s 偏差窗口
    claims = make_claims(iat=NOW - 200, exp=NOW - 100)
    with pytest.raises(TokenExpiredError):
        check_expiry(claims, now=NOW, clock_skew_seconds=DEFAULT_CLOCK_SKEW_SECONDS)


def test_expired_inside_skew_window_allowed() -> None:
    # 过期 20s，在 30s 偏差窗口内，不判过期
    claims = make_claims(iat=NOW - 920, exp=NOW - 20)
    check_expiry(claims, now=NOW, clock_skew_seconds=DEFAULT_CLOCK_SKEW_SECONDS)


def test_future_iat_beyond_skew_rejected() -> None:
    claims = make_claims(iat=NOW + 120, exp=NOW + 220)
    with pytest.raises(TokenMalformedError):
        check_expiry(claims, now=NOW, clock_skew_seconds=30)


def test_real_clock_default_now() -> None:
    now = int(time.time())
    claims = make_claims(iat=now, exp=now + 10)
    check_expiry(claims)  # 不传 now，使用真实时钟不应抛错
