"""并发刷新与重放检测单测。

结论要求：

* N 个客户端并发使用同一个刷新令牌，恰好 1 个成功拿到新令牌；
* 其余全部按重放处理（RefreshReplayError），失败原因与其他拒绝可区分；
* 重放后整条会话家族失效，任何旧/新令牌都无法继续使用；
* 日志必须打印令牌标识、会话标识与判定依据。
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

import pytest

from auth.errors import (
    RefreshReplayError,
    TokenRevokedError,
)
from auth.service import AuthService


@dataclass
class RefreshOutcome:
    worker: int
    ok: bool
    reason: str = ""
    new_refresh: str = ""


def _concurrent_refresh(
    service: AuthService, refresh_token: str, n: int
) -> list[RefreshOutcome]:
    barrier = threading.Barrier(n)
    outcomes: list[RefreshOutcome] = []
    out_lock = threading.Lock()

    def worker(idx: int) -> None:
        barrier.wait()  # 尽量让所有线程同时发起，制造真实竞态
        try:
            _access, new_refresh = service.refresh(refresh_token)
            result = RefreshOutcome(
                worker=idx, ok=True, new_refresh=new_refresh
            )
        except RefreshReplayError as exc:
            result = RefreshOutcome(worker=idx, ok=False, reason=exc.reason)
        except TokenRevokedError as exc:
            # 输给“先重放触发吊销”的极端调度：本质仍是重放链路拒绝，
            # 但 reason 必须能与 refresh_replay 区分开
            result = RefreshOutcome(worker=idx, ok=False, reason=exc.reason)
        with out_lock:
            outcomes.append(result)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return outcomes


@pytest.mark.parametrize("n", [2, 4, 16])
def test_concurrent_same_refresh_token_only_one_wins(
    service: AuthService, n: int
) -> None:
    _, r0, sid = service.login("alice")
    outcomes = _concurrent_refresh(service, r0, n)

    successes = [o for o in outcomes if o.ok]
    replays = [o for o in outcomes if not o.ok and o.reason == "refresh_replay"]
    revoked = [o for o in outcomes if not o.ok and o.reason == "token_revoked"]

    # 核心结论：唯一成功
    assert len(successes) == 1, [
        (o.worker, o.ok, o.reason) for o in outcomes
    ]
    # 其余全部失败，且失败原因只能是重放或（家族已被重放吊销后的）吊销
    assert len(replays) + len(revoked) == n - 1
    assert len(replays) >= 1, "至少要有一个请求明确判定为重放"

    # 成功拿到的新令牌各不相同 —— 不可能两边拿到同一对新令牌
    assert len({o.new_refresh for o in successes}) == 1
    winner = successes[0]
    print(
        f"\n[并发刷新 n={n}] session={sid[:8]} 旧刷新令牌={r0[:16]}... "
        f"唯一成功者=worker-{winner.worker} 新令牌={winner.new_refresh[:16]}... "
        f"重放={len(replays)} 连带吊销={len(revoked)}"
    )


def test_concurrent_replay_kills_whole_family(
    service: AuthService, caplog: pytest.LogCaptureFixture
) -> None:
    access, r0, sid = service.login("alice")
    outcomes = _concurrent_refresh(service, r0, 8)
    winner = next(o for o in outcomes if o.ok)

    family = service.store.get_family_by_session(sid)
    assert family is not None
    assert family.revoked is True
    assert family.revoke_reason == "refresh_token_replay"

    # 旧访问令牌立即失效
    with pytest.raises(TokenRevokedError):
        service.verify_access_token(access)

    # 赢家拿到的新刷新令牌同样不能用：家族已因其他人的重放而整体吊销
    with pytest.raises((RefreshReplayError, TokenRevokedError)):
        service.refresh(winner.new_refresh)

    # 原始令牌再来一次，依旧是重放结论
    with pytest.raises(RefreshReplayError):
        service.refresh(r0)

    # 日志含判定依据与标识
    with caplog.at_level(logging.WARNING, logger="auth"):
        with pytest.raises(RefreshReplayError):
            service.refresh(r0)
    joined = "\n".join(r.message for r in caplog.records)
    assert "refresh_replay" in joined
    assert "used 集合" in joined
    assert sid[:8] in joined


def test_stale_token_after_legitimate_chain_is_replay(service: AuthService) -> None:
    """正常轮换链上，过期链位的令牌一律按重放处理并吊销家族。"""
    _, r0, sid = service.login("alice")
    _, r1 = service.refresh(r0)
    _, r2 = service.refresh(r1)

    # r1 已用过；再用 r1 是重放
    with pytest.raises(RefreshReplayError):
        service.refresh(r1)

    # 此时 r2 作为家族最新令牌也连带失效
    with pytest.raises((RefreshReplayError, TokenRevokedError)):
        service.refresh(r2)


def test_distinct_sessions_do_not_share_fate(service: AuthService) -> None:
    """一个家族出问题不应连累无关会话。"""
    a1, r1, s1 = service.login("alice")
    a2, r2, s2 = service.login("bob")

    _, r1b = service.refresh(r1)
    with pytest.raises(RefreshReplayError):
        service.refresh(r1)  # alice 家族被吊销

    # bob 的会话不受影响
    assert service.verify_access_token(a2).subject == "bob"
    new_a2, _ = service.refresh(r2)
    assert service.verify_access_token(new_a2).subject == "bob"
    # alice 仍然全部失效
    with pytest.raises(TokenRevokedError):
        service.verify_access_token(a1)
