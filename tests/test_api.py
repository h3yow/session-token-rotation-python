"""HTTP 接口层测试：路由行为、reason 区分、既有接口不被破坏。"""

from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

import main
from auth.api import get_service
from auth.service import AuthService


@pytest.fixture
def client() -> TestClient:
    # 每个用例替换为全新服务实例，避免本地存储串扰
    fresh = AuthService()
    main.app.dependency_overrides[get_service] = lambda: fresh
    with TestClient(main.app) as c:
        yield c
    main.app.dependency_overrides.clear()


def _login(client: TestClient, subject: str = "alice") -> dict:
    r = client.post("/auth/login", params={"subject": subject})
    assert r.status_code == 200, r.text
    return r.json()


def test_existing_root_endpoint_unchanged(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert r.json() == {"Hello": "World"}


def test_login_and_me_flow(client: TestClient) -> None:
    tokens = _login(client)
    r = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 200
    assert r.json()["subject"] == "alice"
    assert r.json()["session_id"] == tokens["session_id"]


def test_missing_bearer_has_reason(client: TestClient) -> None:
    r = client.get("/auth/me")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "missing_bearer_token"


def test_forged_token_has_malformed_reason(client: TestClient) -> None:
    r = client.get("/auth/me", headers={"Authorization": "Bearer forged.sig"})
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "token_malformed"


def test_missing_refresh_header_is_400(client: TestClient) -> None:
    r = client.post("/auth/refresh")
    assert r.status_code == 400
    assert r.json()["detail"]["reason"] == "missing_refresh_token"


def test_refresh_then_replay_reason_over_http(client: TestClient) -> None:
    tokens = _login(client)
    r1 = client.post(
        "/auth/refresh",
        headers={"X-Refresh-Token": tokens["refresh_token"]},
    )
    assert r1.status_code == 200
    new_refresh = r1.json()["refresh_token"]

    # 旧刷新令牌重放
    r2 = client.post(
        "/auth/refresh",
        headers={"X-Refresh-Token": tokens["refresh_token"]},
    )
    assert r2.status_code == 401
    assert r2.json()["detail"]["reason"] == "refresh_replay"

    # 家族已被连带吊销
    r3 = client.post(
        "/auth/refresh", headers={"X-Refresh-Token": new_refresh}
    )
    assert r3.status_code == 401
    assert r3.json()["detail"]["reason"] in (
        "refresh_replay",
        "token_revoked",
    )


def test_logout_revokes_and_is_idempotent(client: TestClient) -> None:
    tokens = _login(client)
    r = client.post(
        "/auth/logout", headers={"X-Session-Id": tokens["session_id"]}
    )
    assert r.status_code == 200 and r.json()["status"] == "logged_out"

    # 注销后访问令牌立即失效
    r = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "token_revoked"

    # 重复注销 / 不存在会话：稳定 200
    assert (
        client.post(
            "/auth/logout",
            headers={"X-Session-Id": tokens["session_id"]},
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/auth/logout", headers={"X-Session-Id": "nope"}
        ).status_code
        == 200
    )


def test_logout_via_refresh_token_header(client: TestClient) -> None:
    tokens = _login(client)
    r = client.post(
        "/auth/logout",
        headers={"X-Refresh-Token": tokens["refresh_token"]},
    )
    assert r.status_code == 200
    r = client.post(
        "/auth/refresh",
        headers={"X-Refresh-Token": tokens["refresh_token"]},
    )
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "token_revoked"


def test_concurrent_refresh_over_http_unique_winner(client: TestClient) -> None:
    """端到端并发：多条真实 HTTP 请求同时刷新，结论唯一。"""
    tokens = _login(client)
    barrier = threading.Barrier(6)
    results: list[tuple[int, int, str]] = []
    lock = threading.Lock()

    def call(idx: int) -> None:
        barrier.wait()
        r = client.post(
            "/auth/refresh",
            headers={"X-Refresh-Token": tokens["refresh_token"]},
        )
        reason = ""
        if r.status_code == 401:
            reason = r.json()["detail"]["reason"]
        with lock:
            results.append((idx, r.status_code, reason))

    threads = [threading.Thread(target=call, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [x for x in results if x[1] == 200]
    assert len(winners) == 1, results
    losers = [x for x in results if x[1] == 401]
    assert all(x[2] in ("refresh_replay", "token_revoked") for x in losers)
    assert any(x[2] == "refresh_replay" for x in losers)
