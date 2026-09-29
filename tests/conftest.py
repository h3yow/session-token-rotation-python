"""共用 fixtures：可控时钟的 SessionService，以及日志判定。"""

from __future__ import annotations

import logging

import pytest

from app.service import SessionService


class MutableClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> MutableClock:
    return MutableClock()


@pytest.fixture
def service(clock: MutableClock) -> SessionService:
    return SessionService(
        secret="unit-test-secret",
        access_ttl_seconds=900,
        refresh_ttl_seconds=3600,
        clock_skew_leeway_seconds=30.0,
        clock=clock,
    )


def records_for(caplog, event_prefix: str = "") -> list[logging.LogRecord]:
    records = [r for r in caplog.records if r.name == "session_auth"]
    if event_prefix:
        records = [r for r in records if r.getMessage().startswith(f"event={event_prefix}")]
    return records


def assert_decision_logged(caplog, *, event: str, family_id: str, jti: str, reason: str) -> None:
    """断言判定日志中同时包含令牌标识、会话标识与判定依据。"""
    for record in records_for(caplog, event):
        msg = record.getMessage()
        if family_id in msg and jti in msg and f"reason={reason}" in msg:
            return
    raise AssertionError(
        f"未找到判定日志 event={event} family={family_id} jti={jti} reason={reason}; "
        f"实际日志: {[r.getMessage() for r in records_for(caplog)]}"
    )
