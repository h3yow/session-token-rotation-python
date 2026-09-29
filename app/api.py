"""HTTP 接口：登录、校验、轮换、注销 / 吊销。

每类 AuthError 映射到可区分的响应：HTTP 状态 + 稳定的 error.code，
调用方不会再把过期、伪造、吊销、会话不存在、重放混成同一种拒绝。
"""

from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.errors import (
    AuthError,
    InvalidSignatureError,
    InvalidTokenError,
    RefreshReplayError,
    RevokedError,
    SessionNotFoundError,
    TokenExpiredError,
)
from app.service import SessionService

router = APIRouter(prefix="/auth", tags=["auth"])

# 各错误 -> HTTP 状态码。body 中仍带稳定的 code 字段用于细分。
_STATUS: dict[type[AuthError], int] = {
    InvalidSignatureError: 401,
    TokenExpiredError: 401,
    SessionNotFoundError: 401,
    RevokedError: 401,
    RefreshReplayError: 401,
    InvalidTokenError: 400,
}


def build_service() -> SessionService:
    secret = os.environ.get("SESSION_SECRET", "local-dev-secret")
    return SessionService(secret)


def _raise_http(exc: AuthError) -> None:
    raise HTTPException(status_code=_STATUS[type(exc)], detail={"code": exc.code, "message": str(exc)})


def _service(request: Request) -> SessionService:
    return request.app.state.session_service


def _bearer(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"code": "missing_bearer",
                                                      "message": "Authorization: Bearer <token>"})
    return auth[len("Bearer "):].strip()


class LoginBody(BaseModel):
    subject: str


class RefreshBody(BaseModel):
    refresh_token: str


class LogoutBody(BaseModel):
    family_id: str | None = None


def _pair_payload(pair) -> dict:
    return {
        "access_token": pair.access_token,
        "refresh_token": pair.refresh_token,
        "token_type": "Bearer",
        "access_jti": pair.access_jti,
        "refresh_jti": pair.refresh_jti,
        "family_id": pair.family_id,
        "expires_in": pair.expires_in,
    }


@router.post("/login")
def login(body: LoginBody, request: Request):
    pair = _service(request).login(body.subject)
    return _pair_payload(pair)


@router.post("/refresh")
def refresh(body: RefreshBody, request: Request):
    try:
        pair = _service(request).refresh(body.refresh_token)
    except AuthError as exc:
        _raise_http(exc)
    return _pair_payload(pair)


@router.get("/me")
def me(request: Request):
    token = _bearer(request)
    try:
        claims = _service(request).authenticate(token)
    except AuthError as exc:
        _raise_http(exc)
    return {"subject": claims["sub"], "family_id": claims["fam"], "access_jti": claims["jti"]}


@router.post("/logout")
def logout(request: Request, body: LogoutBody | None = None):
    family_id = body.family_id if body else None
    try:
        if family_id is None:
            revoked = _service(request).logout(access_token=_bearer(request))
        else:
            revoked = _service(request).logout(family_id=family_id)
    except AuthError as exc:
        _raise_http(exc)
    # 重复注销 / 不存在的会话：稳定返回 200，不报错崩掉
    return JSONResponse({"revoked": revoked, "family_id": family_id or "(resolved from token)"})


@router.delete("/sessions/{family_id}")
def revoke_session(family_id: str, request: Request):
    revoked = _service(request).revoke(family_id)
    return JSONResponse({"revoked": revoked, "family_id": family_id})
