"""并发刷新与重放检测。

结论要求：
1. N 个客户端并发使用同一个刷新令牌，恰好 1 个成功拿到新令牌；
2. 其余 N-1 个全部按重放处理（refresh_replay），失败原因一致且可区分；
3. 不能出现两边同时拿到新令牌；
4. 重放后整条会话家族失效，合法分支拿到的新令牌也不能继续使用。
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.errors import RefreshReplayError, RevokedError
from tests.conftest import assert_decision_logged


def _run_concurrent_refresh(service, refresh_token: str, n: int):
    barrier = threading.Barrier(n)

    def worker():
        barrier.wait()  # 尽量把 N 次刷新压到同一时刻发出
        try:
            return service.refresh(refresh_token)
        except Exception as exc:  # 收集异常以便主线程分类统计
            return exc

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(worker) for _ in range(n)]
        return [f.result(timeout=10) for f in futures]


@pytest.mark.parametrize("n", [2, 5, 16, 50])
def test_concurrent_refresh_single_winner(service, n, caplog):
    caplog.set_level(logging.INFO, logger="session_auth")
    pair = service.login("alice")
    results = _run_concurrent_refresh(service, pair.refresh_token, n)

    winners = [r for r in results if hasattr(r, "access_token")]
    replay_errors = [r for r in results if isinstance(r, Exception)]

    # 结论 1：唯一成功
    assert len(winners) == 1, f"期望恰好 1 个成功，实际 {len(winners)}"
    # 结论 2：其余全部为重放，错误类型可区分
    assert len(replay_errors) == n - 1
    assert all(isinstance(e, RefreshReplayError) for e in replay_errors)
    # 结论 3：成功结果唯一（不会两边拿到不同的新令牌）
    winner = winners[0]
    assert winner.refresh_jti != pair.refresh_jti

    family = service.store.get(pair.family_id)
    # 结论 4：重放发生 -> 家族连带失效
    assert family.revoked is True
    # 唯一成功的新令牌也不能继续刷新 / 鉴权
    with pytest.raises(RevokedError):
        service.refresh(winner.refresh_token)
    with pytest.raises(RevokedError):
        service.authenticate(winner.access_token)

    assert_decision_logged(
        caplog, event="refresh_replay", family_id=pair.family_id,
        jti=pair.refresh_jti, reason="replayed_refresh_token_family_compromised",
    )


def test_concurrent_refresh_under_contended_lock(service):
    """加重临界区竞争：在 refresh 进行期间制造其它家族上的并发操作。"""
    target = service.login("target")
    noise = [service.login(f"noise-{i}") for i in range(8)]

    def use_noise(pair):
        # 与目标刷新竞争同一把全局存储锁，但不得影响目标结论
        service.authenticate(pair.access_token)

    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = [pool.submit(service.refresh, target.refresh_token) for _ in range(8)]
        noise_futures = [pool.submit(use_noise, p) for p in noise]
        outcomes = [f.exception() or f.result() for f in futures]
        for f in noise_futures:
            f.result(timeout=5)  # 噪音操作不应抛异常

    winners = [o for o in outcomes if hasattr(o, "access_token")]
    replays = [o for o in outcomes if isinstance(o, RefreshReplayError)]
    assert len(winners) == 1
    assert len(replays) == 7
    assert service.store.get(target.family_id).revoked is True
    # 噪音家族不受牵连
    assert all(service.store.get(p.family_id).revoked is False for p in noise)


def test_sequential_replays_all_classified_identically(service):
    """同一令牌连续多次重放，结论稳定一致，家族保持吊销。"""
    pair = service.login("alice")
    service.refresh(pair.refresh_token)
    for _ in range(5):
        with pytest.raises(RefreshReplayError):
            service.refresh(pair.refresh_token)
    assert service.store.get(pair.family_id).revoked is True
