"""领域数据类型：令牌族（会话家族）与签发结果。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TokenFamily:
    """一条会话对应的刷新令牌家族。

    - family_id 即会话标识；
    - latest_refresh_jti 是当前唯一有效的刷新令牌标识；
    - used_refresh_jtis 记录已经成功使用过的刷新令牌，用于重放检测；
    - revoked 为 True 时整条家族失效（注销 / 重放连带）。
    """

    family_id: str
    subject: str
    latest_refresh_jti: str = ""
    used_refresh_jtis: set[str] = field(default_factory=set)
    current_access_jti: str = ""
    revoked: bool = False
    created_at: float = 0.0


@dataclass(frozen=True)
class TokenPair:
    """一次签发 / 轮换产出的令牌对。"""

    access_token: str
    refresh_token: str
    access_jti: str
    refresh_jti: str
    family_id: str
    expires_in: int
