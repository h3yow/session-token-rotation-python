"""服务层单测：签发、四类失败区分、轮换与注销。"""

from __future__ import annotations

import logging
import time
import uuid

import pytest

from auth.errors import (
    RefreshReplayError,
    RefreshTokenExpiredError,
    SessionNotFoundError,
    TokenExpiredError,
    TokenMalformedError,
    TokenRevokedError,
)
from auth.service import AuthService
from auth.tokens import TokenClaims, encode_token

NOW = 2_000_000


def test_login_issues_usable_pair(service: AuthService) -> None:
    access, refresh, session_id = service.login("alice", now=NOW)
    claims = service.verify_access_token(access, now=NOW)
    assert claims.subject == "alice"
    assert claims.session_id == session_id
    new_access, new_refresh = service.refresh(refresh, now=NOW)
    assert service.verify_access_token(new_access, now=NOW).subject == "alice"
    assert new_refresh != refresh


def test_access_failure_reasons_are_distinguishable(service: AuthService) -> None:
    access, _, sid = service.login("alice", now=NOW)

    # 1) 签名被伪造
    forged = access[:-1] + ("0" if access[-1] != "0" else "1")
    with pytest.raises(TokenMalformedError):
        service.verify_access_token(forged, now=NOW)

    # 2) 令牌过期（超出时钟偏差窗口）
    with pytest.raises(TokenExpiredError):
        service.verify_access_token(access, now=NOW + service._access_ttl + 100)

    # 3) 所属会话不存在：真实签名但 sid 在存储中查不到
    ghost = encode_token(
        TokenClaims(
            token_id=uuid.uuid4().hex,
            session_id="ghost-session",
            family_id="ghost-family",
            subject="mallory",
            issued_at=NOW,
            expires_at=NOW + 100,
            token_type="access",
        ),
        service._secret,
    )
    with pytest.raises(SessionNotFoundError):
        service.verify_access_token(ghost, now=NOW)

    # 4) 已被吊销（注销）
    assert service.logout(session_id=sid) is True
    with pytest.raises(TokenRevokedError):
        service.verify_access_token(access, now=NOW)


def test_refresh_type_mismatch_rejected(service: AuthService) -> None:
    access, _, _ = service.login("alice", now=NOW)
    with pytest.raises(TokenMalformedError):
        service.refresh(access, now=NOW)


def test_refresh_expiry_is_its_own_reason(service: AuthService) -> None:
    _, refresh, _ = service.login(
        "alice",
        now=NOW,
    )
    # 刷新令牌 TTL 到期且超出偏差窗口 -> refresh_expired，而非泛化拒绝
    with pytest.raises(RefreshTokenExpiredError):
        service.refresh(
            refresh, now=NOW + service._refresh_ttl + service._clock_skew + 1
        )


def test_clock_skew_tolerance_on_refresh(service: AuthService) -> None:
    _, refresh, _ = service.login("alice", now=NOW)
    # 服务端时钟比客户端快 20s（在 30s 容忍窗口内），刷新令牌“刚过期”仍可用
    new_access, new_refresh = service.refresh(
        refresh, now=NOW + service._refresh_ttl + 20
    )
    service.verify_access_token(
        new_access, now=NOW + service._refresh_ttl + 20
    )


def test_rotation_is_one_time_use(service: AuthService) -> None:
    _, r0, _ = service.login("alice", now=NOW)
    _, r1 = service.refresh(r0, now=NOW)
    _, r2 = service.refresh(r1, now=NOW + 1)

    # 链条上的旧令牌全部不能再次使用
    for stale in (r0, r1):
        with pytest.raises(RefreshReplayError):
            service.refresh(stale, now=NOW + 2)

    # 重放后：最新令牌也被连带吊销
    with pytest.raises((RefreshReplayError, TokenRevokedError)):
        service.refresh(r2, now=NOW + 3)

    family = service.store.get_family_by_session(
        _session_id_of(service, r2)
    )
    assert family is not None and family.revoked is True


def _session_id_of(service: AuthService, refresh_token: str) -> str:
    from auth.tokens import decode_token

    return decode_token(refresh_token, service._secret).session_id


def test_replay_revokes_entire_family(service: AuthService) -> None:
    access, r0, sid = service.login("alice", now=NOW)
    a1, r1 = service.refresh(r0, now=NOW)

    # 攻击者拿到旧 r0 重放
    with pytest.raises(RefreshReplayError):
        service.refresh(r0, now=NOW + 1)

    family = service.store.get_family_by_session(sid)
    assert family is not None and family.revoked
    assert family.revoke_reason == "refresh_token_replay"
    assert service.store.get_session(sid).revoked

    # 家族内一切访问令牌、刷新令牌立即不可用
    with pytest.raises(TokenRevokedError):
        service.verify_access_token(access, now=NOW + 1)
    with pytest.raises(TokenRevokedError):
        service.verify_access_token(a1, now=NOW + 1)
    with pytest.raises((RefreshReplayError, TokenRevokedError)):
        service.refresh(r1, now=NOW + 1)


def test_logout_is_immediately_effective_and_idempotent(
    service: AuthService, caplog: pytest.LogCaptureFixture
) -> None:
    access, refresh, sid = service.login("alice", now=NOW)

    assert service.logout(session_id=sid) is True
    # 注销后访问令牌立刻不可用
    with pytest.raises(TokenRevokedError):
        service.verify_access_token(access, now=NOW)
    # 刷新令牌也立刻不可用（按吊销处理）
    with pytest.raises(TokenRevokedError):
        service.refresh(refresh, now=NOW)

    # 重复注销 / 不存在会话注销 / 垃圾令牌注销：稳定不抛错
    assert service.logout(session_id=sid) is False
    assert service.logout(session_id="does-not-exist") is False
    assert service.logout(refresh_token="garbage.value") is False
    assert service.logout() is False


def test_logout_via_refresh_token(service: AuthService) -> None:
    access, refresh, sid = service.login("alice", now=NOW)
    assert service.logout(refresh_token=refresh) is True
    with pytest.raises(TokenRevokedError):
        service.verify_access_token(access, now=NOW)


def test_replay_logs_identifiers_and_judgment(
    service: AuthService, caplog: pytest.LogCaptureFixture
) -> None:
    _, r0, sid = service.login("alice", now=NOW)
    service.refresh(r0, now=NOW)
    caplog.clear()
    with pytest.raises(RefreshReplayError):
        with caplog.at_level(logging.WARNING, logger="auth"):
            service.refresh(r0, now=NOW)
    texts = [r.message for r in caplog.records]
    assert any("refresh_replay_detected" in t for t in texts)
    assert any("used 集合" in t for t in texts)
    # 日志含会话标识前缀
    assert any(sid[:8] in t for t in texts)


def test_unknown_family_signed_token_is_session_not_found(
    service: AuthService,
) -> None:
    _, _, _ = service.login("alice", now=NOW)
    refresh = encode_token(
        TokenClaims(
            token_id=uuid.uuid4().hex,
            session_id="missing",
            family_id="missing",
            subject="x",
            issued_at=NOW,
            expires_at=NOW + 100,
            token_type="refresh",
        ),
        service._secret,
    )
    with pytest.raises(SessionNotFoundError):
        service.refresh(refresh, now=NOW)
