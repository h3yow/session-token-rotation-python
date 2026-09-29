"""令牌的编码、解码与校验（无状态部分）。

令牌为自包含的签名载荷（HMAC-SHA256），本地存储只负责会话/家族状态。
允许小幅时钟偏差，避免服务端与客户端时间不完全一致时误判过期。

令牌格式：``base64url(payload_json).hex(hmac_sha256(payload, secret))``
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

from auth.errors import TokenExpiredError, TokenMalformedError

# 默认允许的时钟偏差（秒）：签发时刻在未来一点点、或刚过期一点点都容忍
DEFAULT_CLOCK_SKEW_SECONDS: int = 30

_ACCESS = "access"
_REFRESH = "refresh"


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """令牌中携带的声明。"""

    token_id: str
    session_id: str
    family_id: str
    subject: str
    issued_at: int
    expires_at: int
    token_type: str  # "access" 或 "refresh"


def constant_time_equals(a: str, b: str) -> bool:
    """常量时间字符串比较，防时序侧信道。"""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def sign_payload(payload_b64: str, secret: str) -> str:
    """对 base64 载荷计算 HMAC-SHA256 签名，返回十六进制摘要。"""
    digest = hmac.new(
        secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256
    )
    return digest.hexdigest()


def encode_token(claims: TokenClaims, secret: str) -> str:
    """把声明编码为 ``payload.signature`` 形式的令牌字符串。"""
    raw = json.dumps(
        {
            "jti": claims.token_id,
            "sid": claims.session_id,
            "fid": claims.family_id,
            "sub": claims.subject,
            "iat": claims.issued_at,
            "exp": claims.expires_at,
            "typ": claims.token_type,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(raw).decode("ascii")
    return f"{payload_b64}.{sign_payload(payload_b64, secret)}"


def decode_token(token: str, secret: str) -> TokenClaims:
    """解码并验签令牌。

    格式错误或签名不匹配抛 TokenMalformedError；
    是否过期由 :func:`check_expiry` 单独判定。
    """
    if not isinstance(token, str) or token.count(".") != 1:
        raise TokenMalformedError("令牌格式错误：期望 payload.signature")
    payload_b64, signature = token.split(".", 1)
    if not payload_b64 or not signature:
        raise TokenMalformedError("令牌格式错误：载荷或签名为空")

    expected = sign_payload(payload_b64, secret)
    if not constant_time_equals(signature, expected):
        raise TokenMalformedError("令牌签名校验失败：可能被伪造")

    try:
        raw = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise TokenMalformedError("令牌载荷无法解析") from exc

    required = ("jti", "sid", "fid", "sub", "iat", "exp", "typ")
    if not isinstance(data, dict) or any(k not in data for k in required):
        raise TokenMalformedError("令牌声明不完整")
    if data["typ"] not in (_ACCESS, _REFRESH):
        raise TokenMalformedError(f"未知令牌类型: {data['typ']!r}")

    try:
        return TokenClaims(
            token_id=str(data["jti"]),
            session_id=str(data["sid"]),
            family_id=str(data["fid"]),
            subject=str(data["sub"]),
            issued_at=int(data["iat"]),
            expires_at=int(data["exp"]),
            token_type=data["typ"],
        )
    except (TypeError, ValueError) as exc:
        raise TokenMalformedError("令牌声明字段类型非法") from exc


def check_expiry(
    claims: TokenClaims,
    *,
    now: int | None = None,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> None:
    """结合时钟偏差容忍判断令牌是否过期。

    判定依据：``now > exp + clock_skew`` 才算过期；
    同理 ``iat`` 远在未来（超过偏差窗口）也按异常令牌处理。
    """
    current = time.time() if now is None else now
    if claims.issued_at - clock_skew_seconds > current:
        raise TokenMalformedError("令牌签发时间远在未来，时钟偏差超出容忍窗口")
    if current > claims.expires_at + clock_skew_seconds:
        raise TokenExpiredError(
            f"令牌已于 unix={claims.expires_at} 过期（当前 unix={int(current)}，"
            f"容忍偏差 {clock_skew_seconds}s）"
        )
