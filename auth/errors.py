"""认证错误类型定义。

每一类失败对应一个独立异常，调用方可以据此区分拒绝原因，
而不是把过期、伪造、吊销、会话不存在混为同一种拒绝。
"""

from __future__ import annotations


class AuthError(Exception):
    """所有认证相关错误的基类。"""

    reason: str = "auth_error"


class TokenMalformedError(AuthError):
    """令牌格式错误或签名被伪造。"""

    reason = "token_malformed"


class TokenExpiredError(AuthError):
    """访问/刷新令牌已过期。"""

    reason = "token_expired"


class TokenRevokedError(AuthError):
    """令牌已被吊销（会话注销或重放连带失效）。"""

    reason = "token_revoked"


class SessionNotFoundError(AuthError):
    """令牌所声称的会话不存在。"""

    reason = "session_not_found"


class RefreshReplayError(AuthError):
    """刷新令牌重放：该刷新令牌此前已成功使用过。"""

    reason = "refresh_replay"


class RefreshTokenExpiredError(AuthError):
    """刷新令牌自身已过期。"""

    reason = "refresh_expired"
