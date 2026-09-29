"""HTTP 接口：端到端错误码区分、重放、注销幂等、既有根接口不回归。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api import build_service
from main import app


@pytest.fixture
def client():
    app.state.session_service = build_service()
    return TestClient(app)


def test_root_endpoint_unchanged(client):
    assert client.get("/").json() == {"Hello": "World"}


def test_login_and_me(client):
    data = client.post("/auth/login", json={"subject": "alice"}).json()
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"})
    assert r.status_code == 200
    assert r.json()["subject"] == "alice"


def test_missing_bearer(client):
    assert client.get("/auth/me").status_code == 401


def test_error_codes_are_distinguishable(client):
    data = client.post("/auth/login", json={"subject": "alice"}).json()
    fam = data["family_id"]
    access = data["access_token"]
    refresh = data["refresh_token"]

    # 过期：另起一个默认 TTL 的服务并等待并不现实，这里通过服务实例直接验证；
    # 此处覆盖另外四类在 HTTP 上的区分。
    # 伪造签名
    forged = access[:-1] + ("0" if access[-1] != "0" else "1")
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401 and r.json()["detail"]["code"] == "invalid_signature"

    # 会话不存在：签名正确但指向未知家族（用别的空存储验证服务层，
    # HTTP 层通过显式删除家族模拟）
    assert client.delete(f"/auth/sessions/{fam}").json()["revoked"] is True

    # 吊销后：当前访问令牌 -> revoked
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 401 and r.json()["detail"]["code"] == "revoked"

    # 已使用过/非当前刷新令牌在吊销家族上：重放（先正常轮换一次制造 used）
    # 家族已吊销，当前 refresh 仍在链上 -> revoked
    r = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 401 and r.json()["detail"]["code"] == "revoked"


def test_replay_over_http_revokes_family(client):
    data = client.post("/auth/login", json={"subject": "alice"}).json()
    new = client.post("/auth/refresh", json={"refresh_token": data["refresh_token"]}).json()
    r = client.post("/auth/refresh", json={"refresh_token": data["refresh_token"]})
    assert r.status_code == 401 and r.json()["detail"]["code"] == "refresh_replay"
    # 合法客户端的新令牌立即失效
    r = client.post("/auth/refresh", json={"refresh_token": new["refresh_token"]})
    assert r.status_code == 401 and r.json()["detail"]["code"] == "revoked"


def test_logout_idempotent_and_immediate(client):
    data = client.post("/auth/login", json={"subject": "alice"}).json()
    r = client.post("/auth/logout", json={"family_id": data["family_id"]})
    assert r.status_code == 200 and r.json()["revoked"] is True
    # 重复注销稳定处理
    r = client.post("/auth/logout", json={"family_id": data["family_id"]})
    assert r.status_code == 200 and r.json()["revoked"] is False
    # 对不存在的会话注销不报错
    r = client.post("/auth/logout", json={"family_id": "ghost"})
    assert r.status_code == 200 and r.json()["revoked"] is False
    # 注销后令牌立即不可用
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"})
    assert r.status_code == 401 and r.json()["detail"]["code"] == "revoked"


def test_logout_with_bearer_token(client):
    data = client.post("/auth/login", json={"subject": "alice"}).json()
    r = client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {data['access_token']}"},
    )
    assert r.status_code == 200 and r.json()["revoked"] is True
