"""HTTP 接口层：把认证服务暴露为 FastAPI 路由。

错误到 HTTP 状态码的映射：

* 伪造/格式错误            -> 401 invalid_token（reason=token_malformed）
* 访问令牌过期             -> 401 token_expired
* 刷新令牌过期             -> 401 refresh_expired
* 已吊销/已注销            -> 401 token_revoked
* 会话不存在               -> 401 session_not_found
* 刷新令牌重放             -> 401 refresh_replay（家族已连带失效）

所有拒绝都带不同的 ``detail.reason``，调用方可以明确区分失败原因。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, status

from auth.errors import AuthError
from auth.service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])

# 单进程内共享一个服务实例（本地内存存储）
_service = AuthService()


def get_service() -> AuthService:
    return _service


@router.post("/login")
def login(subject: str, service: AuthService = Depends(get_service)) -> dict:
    """登录：以 subject（如用户名）换取访问/刷新令牌。"""
    access, refresh, session_id = service.login(subject)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "session_id": session_id,
        "token_type": "Bearer",
    }


@router.post("/refresh")
def refresh(
    refresh_token: str | None = Header(default=None, alias="X-Refresh-Token"),
    service: AuthService = Depends(get_service),
) -> dict:
    """刷新：轮换刷新令牌并发放新令牌对。"""
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"reason": "missing_refresh_token"},
        )
    try:
        access, new_refresh = service.refresh(refresh_token)
    except AuthError as err:
        raise_http_for_error(err)
    return {
        "access_token": access,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
    }


@router.post("/logout")
def logout(
    refresh_token: str | None = Header(default=None, alias="X-Refresh-Token"),
    x_session_id: str | None = Header(default=None, alias="X-Session-Id"),
    service: AuthService = Depends(get_service),
) -> dict:
    """注销：通过刷新令牌或 X-Session-Id 定位会话，幂等。"""
    service.logout(refresh_token=refresh_token, session_id=x_session_id)
    return {"status": "logged_out"}


@router.get("/me")
def me(
    authorization: str | None = Header(default=None),
    service: AuthService = Depends(get_service),
) -> dict:
    """受保护资源：用 ``Authorization: Bearer <access_token>`` 访问。"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"reason": "missing_bearer_token"},
        )
    token = authorization.removeprefix("Bearer ").strip()
    try:
        claims = service.verify_access_token(token)
    except AuthError as err:
        raise_http_for_error(err)
    return {
        "subject": claims.subject,
        "session_id": claims.session_id,
        "token_id": claims.token_id,
    }


def raise_http_for_error(err: AuthError) -> None:
    """把认证异常映射为带 reason 的 HTTPException（401）。"""
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"reason": err.reason, "message": str(err)},
    )
