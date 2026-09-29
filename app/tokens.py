"""令牌的签发与校验（HMAC-SHA256 签名，不引入额外依赖）。

令牌为自包含的紧凑字符串：

    base64url(payload_json).base64url(hmac_sha256(secret, payload))

payload 字段：
    typ   "access" | "refresh"
    jti   令牌唯一标识（打印日志 / 吊销判定用）
    fam   会话（家族）标识
    sub   主体（例如用户标识）
    iat   签发时间（Unix 秒）
    exp   过期时间（Unix 秒）
"""

from __future__ import annotations

import base64
import hashlib

import hmac
import json
import time
from typing import Any

from app.errors import (
    InvalidSignatureError,
    InvalidTokenError,
    TokenExpiredError,
)

ACCESS = "access"
REFRESH = "refresh"


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except Exception as exc:  # 非法 base64
        raise InvalidTokenError("payload is not valid base64url") from exc


def _sign(payload_b64: str, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256)
    return _b64encode(mac.digest())


def issue_token(
    *,
    secret: str,
    token_type: str,
    jti: str,
    family_id: str,
    subject: str,
    ttl_seconds: int,
    now: float | None = None,
) -> str:
    """签发一个带签名的令牌。"""
    issued = time.time() if now is None else now
    payload: dict[str, Any] = {
        "typ": token_type,
        "jti": jti,
        "fam": family_id,
        "sub": subject,
        "iat": int(issued),
        "exp": int(issued) + int(ttl_seconds),
    }
    payload_b64 = _b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature_b64 = _sign(payload_b64, secret)
    return f"{payload_b64}.{signature_b64}"


def decode_token(token: str, *, secret: str, expected_type: str | None = None) -> dict[str, Any]:
    """校验结构、签名、类型与过期时间，返回 payload。

    校验顺序（对应可区分的失败原因）：
      1. 结构 / 编码非法  -> InvalidTokenError
      2. 签名不合法       -> InvalidSignatureError
      3. 类型不符 / 字段缺失 -> InvalidTokenError
      4. 已过期           -> TokenExpiredError
    """
    if not isinstance(token, str) or token.count(".") != 1:
        raise InvalidTokenError("malformed token")
    payload_b64, signature_b64 = token.split(".", 1)
    expected_sig = _sign(payload_b64, secret)
    # 常量时间比较，避免签名比较被时序侧信道利用
    if not hmac.compare_digest(expected_sig, signature_b64):
        raise InvalidSignatureError("signature mismatch")

    try:
        payload = json.loads(_b64decode(payload_b64))
    except InvalidTokenError:
        raise
    except Exception as exc:
        raise InvalidTokenError("payload is not valid json") from exc

    if not isinstance(payload, dict):
        raise InvalidTokenError("payload must be an object")
    required = {"typ", "jti", "fam", "sub", "iat", "exp"}
    if not required.issubset(payload):
        raise InvalidTokenError("payload missing required claims")
    if expected_type is not None and payload["typ"] != expected_type:
        raise InvalidTokenError(f"expected {expected_type} token, got {payload['typ']}")

    return payload


def check_expiry(payload: dict[str, Any], *, now: float, leeway: float) -> None:
    """单独做过期判定，允许时钟偏差容差 leeway 秒。"""
    if now > float(payload["exp"]) + leeway:
        raise TokenExpiredError(
            f"token {payload['jti']} expired at {payload['exp']} (now={now:.0f}, leeway={leeway:.0f})"
        )
