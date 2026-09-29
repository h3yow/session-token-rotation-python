"""会话令牌相关的错误分类。

这几类失败必须能够区分开，不能一律当成同一种拒绝：
- 过期（access / refresh 各自的过期判定）
- 签名被伪造
- 已被吊销（会话家族被吊销）
- 所属会话不存在
- 刷新令牌重放（家族连带失效）
"""

from __future__ import annotations


class AuthError(Exception):
    """认证错误基类。code 用于稳定地对外区分拒绝原因。"""

    code: str = "auth_error"

    def __init__(self, message: str = "") -> None:
        super().__init__(message or self.code)


class InvalidSignatureError(AuthError):
    """令牌签名不合法（被伪造或被篡改）。"""

    code = "invalid_signature"


class TokenExpiredError(AuthError):
    """令牌已过期（容差时间之外）。"""

    code = "token_expired"


class SessionNotFoundError(AuthError):
    """令牌所声称的会话在服务端不存在。"""

    code = "session_not_found"


class RevokedError(AuthError):
    """会话（令牌家族）已被吊销 / 已注销。"""

    code = "revoked"


class RefreshReplayError(AuthError):
    """刷新令牌被重复使用（重放），整条会话家族已连带失效。"""

    code = "refresh_replay"


class InvalidTokenError(AuthError):
    """令牌结构非法（无法解析、类型不对等）。"""

    code = "invalid_token"
