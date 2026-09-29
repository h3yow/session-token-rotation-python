"""服务层：签发、校验、轮换、重放、吊销、过期与容差、注销幂等。"""

from __future__ import annotations

import logging

import pytest

from app.errors import (
    InvalidSignatureError,
    RefreshReplayError,
    RevokedError,
    SessionNotFoundError,
    TokenExpiredError,
)
from tests.conftest import assert_decision_logged


def test_login_issues_usable_pair(service):
    pair = service.login("alice")
    claims = service.authenticate(pair.access_token)
    assert claims["sub"] == "alice"
    family = service.store.get(pair.family_id)
    assert family.latest_refresh_jti == pair.refresh_jti
    assert family.current_access_jti == pair.access_jti


def test_refresh_rotates_and_supersedes_old_tokens(service):
    old = service.login("alice")
    new = service.refresh(old.refresh_token)

    # 正常轮换后家族仍然存活，且轮换链已推进
    family = service.store.get(old.family_id)
    assert family.revoked is False
    assert family.latest_refresh_jti == new.refresh_jti
    assert old.refresh_jti in family.used_refresh_jtis

    # 新令牌可用
    assert service.authenticate(new.access_token)["fam"] == old.family_id
    # 旧刷新令牌重放 -> 家族连带失效
    with pytest.raises(RefreshReplayError):
        service.refresh(old.refresh_token)
    # 旧访问令牌已被取代
    with pytest.raises(RevokedError):
        service.authenticate(old.access_token)
    assert service.store.get(old.family_id).revoked is True


def test_expired_access_token(service, clock, caplog):
    pair = service.login("alice")
    clock.advance(900 + 30 + 1)  # access 900 + 容差 30
    with pytest.raises(TokenExpiredError):
        service.authenticate(pair.access_token)


def test_clock_skew_within_leeway_does_not_expire(service, clock):
    pair = service.login("alice")
    clock.advance(920)  # 已超 900，但在 30 秒容差内
    assert service.authenticate(pair.access_token)["sub"] == "alice"


def test_session_not_found_distinct(service, clock):
    pair = service.login("alice")
    # 同样的密钥与时钟，但使用全新的空存储：签名有效、令牌未过期，只是查无此会话
    other = type(service)(
        secret="unit-test-secret",
        access_ttl_seconds=900,
        refresh_ttl_seconds=3600,
        clock_skew_leeway_seconds=30.0,
        clock=clock,
    )
    with pytest.raises(SessionNotFoundError):
        other.authenticate(pair.access_token)


def test_forged_signature_distinct(service):
    pair = service.login("alice")
    bad = pair.access_token[:-1] + ("z" if pair.access_token[-1] != "z" else "x")
    with pytest.raises(InvalidSignatureError):
        service.authenticate(bad)


def test_revoked_family_rejects_current_tokens(service, caplog):
    pair = service.login("alice")
    assert service.revoke(pair.family_id) is True
    with pytest.raises(RevokedError):
        service.authenticate(pair.access_token)
    with pytest.raises(RevokedError):
        service.refresh(pair.refresh_token)


def test_logout_is_immediate_and_idempotent(service):
    pair = service.login("alice")
    assert service.logout(access_token=pair.access_token) is True
    # 注销后立刻不可用
    with pytest.raises(RevokedError):
        service.authenticate(pair.access_token)
    # 重复注销稳定返回 False，不报错
    assert service.logout(family_id=pair.family_id) is False
    # 不存在的家族注销不报错
    assert service.logout(family_id="missing") is False


def test_logout_by_family_id(service):
    pair = service.login("bob")
    assert service.logout(family_id=pair.family_id) is True
    with pytest.raises(RevokedError):
        service.refresh(pair.refresh_token)


def test_refresh_expired_token(service, clock):
    pair = service.login("alice")
    clock.advance(3600 + 30 + 1)
    with pytest.raises(TokenExpiredError):
        service.refresh(pair.refresh_token)


def test_refresh_missing_session_distinct(service, clock):
    pair = service.login("alice")
    other = type(service)(
        secret="unit-test-secret",
        access_ttl_seconds=900,
        refresh_ttl_seconds=3600,
        clock_skew_leeway_seconds=30.0,
        clock=clock,
    )
    with pytest.raises(SessionNotFoundError):
        other.refresh(pair.refresh_token)


def test_replay_revokes_whole_family(service, caplog):
    caplog.set_level(logging.INFO, logger="session_auth")
    first = service.login("alice")
    second = service.refresh(first.refresh_token)

    # 攻击者重放旧刷新令牌
    with pytest.raises(RefreshReplayError):
        service.refresh(first.refresh_token)

    family = service.store.get(first.family_id)
    assert family.revoked is True

    # 整条家族失效：合法客户端手上的新令牌同样被拒
    with pytest.raises(RevokedError):
        service.refresh(second.refresh_token)
    with pytest.raises(RevokedError):
        service.authenticate(second.access_token)
    # 旧令牌再次出现，结论仍是重放
    with pytest.raises(RefreshReplayError):
        service.refresh(first.refresh_token)

    assert_decision_logged(
        caplog, event="refresh_replay", family_id=first.family_id,
        jti=first.refresh_jti, reason="replayed_refresh_token_family_compromised",
    )


def test_successful_rotation_decision_logged(service, caplog):
    caplog.set_level(logging.INFO, logger="session_auth")
    pair = service.login("alice")
    service.refresh(pair.refresh_token)
    assert_decision_logged(
        caplog, event="refresh_rotate", family_id=pair.family_id,
        jti=pair.refresh_jti, reason="single_use_enforced",
    )


def test_revoke_decision_logged(service, caplog):
    caplog.set_level(logging.INFO, logger="session_auth")
    pair = service.login("alice")
    service.revoke(pair.family_id)
    assert_decision_logged(
        caplog, event="revoke", family_id=pair.family_id, jti="-",
        reason="explicit_revoke",
    )
