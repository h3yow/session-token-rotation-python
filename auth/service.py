"""认证服务：对外的签发、校验、轮换、注销入口。

失败原因一律通过 :mod:`auth.errors` 中的具体异常表达，
并通过 logging 打印令牌标识、会话标识与判定依据，便于单测与排查。

并发刷新正确性：refresh 的“检查家族状态 + 轮换推进”整段持有存储锁，
因此同一刷新令牌被多个客户端并发使用时，至多一个客户端轮换成功；
其余请求看到的旧令牌 id 已进入 used 集合，按重放处理并吊销整条家族。
"""

from __future__ import annotations

import logging
import time
import uuid

from auth.errors import (
    RefreshReplayError,
    RefreshTokenExpiredError,
    SessionNotFoundError,
    TokenExpiredError,
    TokenMalformedError,
    TokenRevokedError,
)
from auth.store import RefreshFamily, Session, SessionStore
from auth.tokens import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    TokenClaims,
    check_expiry,
    decode_token,
    encode_token,
)

logger = logging.getLogger("auth")

DEFAULT_ACCESS_TTL_SECONDS: int = 900
DEFAULT_REFRESH_TTL_SECONDS: int = 60 * 60 * 24 * 7
DEFAULT_SECRET: str = "local-dev-secret-change-me"

_SHORT = 8


def _short(value: str) -> str:
    """日志里用的短标识，既便于人读又避免打印完整令牌。"""
    return value[:_SHORT] if value else "-"


def _log_judgment(
    level: int,
    judgment: str,
    *,
    token_id: str = "-",
    session_id: str = "-",
    family_id: str = "-",
    detail: str = "",
) -> None:
    """统一的判定日志：令牌标识 + 会话标识 + 判定依据。"""
    logger.log(
        level,
        "判定=%s token_id=%s session_id=%s family_id=%s %s",
        judgment,
        _short(token_id),
        _short(session_id),
        _short(family_id),
        detail,
    )


class AuthService:
    """会话令牌签发/校验/轮换/注销服务。"""

    def __init__(
        self,
        store: SessionStore | None = None,
        *,
        secret: str = DEFAULT_SECRET,
        access_ttl_seconds: int = DEFAULT_ACCESS_TTL_SECONDS,
        refresh_ttl_seconds: int = DEFAULT_REFRESH_TTL_SECONDS,
        clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> None:
        self.store = store if store is not None else SessionStore()
        self._secret = secret
        self._access_ttl = access_ttl_seconds
        self._refresh_ttl = refresh_ttl_seconds
        self._clock_skew = clock_skew_seconds

    # ------------------------------------------------------------------ 签发
    def _issue_pair(
        self,
        *,
        session_id: str,
        family_id: str,
        subject: str,
        now_ts: int,
    ) -> tuple[str, TokenClaims, str, TokenClaims]:
        access_id = uuid.uuid4().hex
        refresh_id = uuid.uuid4().hex
        access_claims = TokenClaims(
            token_id=access_id,
            session_id=session_id,
            family_id=family_id,
            subject=subject,
            issued_at=now_ts,
            expires_at=now_ts + self._access_ttl,
            token_type="access",
        )
        refresh_claims = TokenClaims(
            token_id=refresh_id,
            session_id=session_id,
            family_id=family_id,
            subject=subject,
            issued_at=now_ts,
            expires_at=now_ts + self._refresh_ttl,
            token_type="refresh",
        )
        return (
            encode_token(access_claims, self._secret),
            access_claims,
            encode_token(refresh_claims, self._secret),
            refresh_claims,
        )

    def login(
        self, subject: str, *, now: int | None = None
    ) -> tuple[str, str, str]:
        """登录并签发访问令牌、刷新令牌，返回 (access, refresh, session_id)。"""
        now_ts = int(time.time() if now is None else now)
        session_id = uuid.uuid4().hex
        family_id = uuid.uuid4().hex
        access, _, refresh, refresh_claims = self._issue_pair(
            session_id=session_id,
            family_id=family_id,
            subject=subject,
            now_ts=now_ts,
        )
        self.store.create(
            Session(
                session_id=session_id,
                family_id=family_id,
                subject=subject,
                created_at=now_ts,
            ),
            RefreshFamily(
                family_id=family_id,
                session_id=session_id,
                subject=subject,
                current_refresh_id=refresh_claims.token_id,
            ),
        )
        _log_judgment(
            logging.INFO,
            "login_issued",
            token_id=refresh_claims.token_id,
            session_id=session_id,
            family_id=family_id,
            detail=f"subject={subject} 已签发访问/刷新令牌对",
        )
        return access, refresh, session_id

    # -------------------------------------------------------------- 访问校验
    def verify_access_token(
        self, token: str, *, now: int | None = None
    ) -> TokenClaims:
        """校验访问令牌，返回声明；任何失败以具体异常表达。

        判定顺序：签名/格式 -> 令牌类型 -> 过期/时钟偏差 ->
        会话存在性 -> 吊销状态。
        """
        claims = decode_token(token, self._secret)
        if claims.token_type != "access":
            raise TokenMalformedError(
                f"访问令牌类型错误: {claims.token_type!r}"
            )
        try:
            check_expiry(
                claims, now=now, clock_skew_seconds=self._clock_skew
            )
        except TokenExpiredError as exc:
            _log_judgment(
                logging.WARNING,
                "access_expired",
                token_id=claims.token_id,
                session_id=claims.session_id,
                family_id=claims.family_id,
                detail=f"依据=exp={claims.expires_at} 超出偏差窗口 {self._clock_skew}s",
            )
            raise

        with self.store.lock():
            session = self.store.get_session(claims.session_id)
            if session is None:
                _log_judgment(
                    logging.WARNING,
                    "access_session_missing",
                    token_id=claims.token_id,
                    session_id=claims.session_id,
                    family_id=claims.family_id,
                    detail="依据=本地存储中不存在该会话",
                )
                raise SessionNotFoundError("会话不存在或已被清除")
            family = self.store.get_family(claims.family_id)
            if family is None or family.session_id != session.session_id:
                _log_judgment(
                    logging.WARNING,
                    "access_family_mismatch",
                    token_id=claims.token_id,
                    session_id=claims.session_id,
                    family_id=claims.family_id,
                    detail="依据=令牌家族与会话无法对应",
                )
                raise SessionNotFoundError("令牌所属刷新家族不存在")
            if session.revoked or family.revoked:
                reason = session.revoke_reason or family.revoke_reason or "revoked"
                _log_judgment(
                    logging.WARNING,
                    "access_revoked",
                    token_id=claims.token_id,
                    session_id=claims.session_id,
                    family_id=claims.family_id,
                    detail=f"依据=会话/家族已吊销 reason={reason}",
                )
                raise TokenRevokedError(f"令牌已被吊销: {reason}")

        _log_judgment(
            logging.INFO,
            "access_ok",
            token_id=claims.token_id,
            session_id=claims.session_id,
            family_id=claims.family_id,
            detail="依据=签名有效、未过期、会话存在且未吊销",
        )
        return claims

    # -------------------------------------------------------------- 刷新轮换
    def refresh(
        self, refresh_token: str, *, now: int | None = None
    ) -> tuple[str, str]:
        """用刷新令牌换取新的访问/刷新令牌对。

        * 成功：旧刷新令牌进入 used 集合，家族当前令牌推进为新令牌。
        * 重放：旧令牌已在 used 集合中，吊销整条家族并抛 RefreshReplayError。
        * 并发：整段在存储锁内完成，至多一个调用成功，不可能两边同时拿到新令牌。
        """
        claims = decode_token(refresh_token, self._secret)
        if claims.token_type != "refresh":
            raise TokenMalformedError(
                f"刷新令牌类型错误: {claims.token_type!r}"
            )
        try:
            check_expiry(
                claims, now=now, clock_skew_seconds=self._clock_skew
            )
        except TokenExpiredError as exc:
            _log_judgment(
                logging.WARNING,
                "refresh_expired",
                token_id=claims.token_id,
                session_id=claims.session_id,
                family_id=claims.family_id,
                detail=f"依据=exp={claims.expires_at} 超出偏差窗口 {self._clock_skew}s",
            )
            raise RefreshTokenExpiredError(str(exc)) from exc

        now_ts = int(time.time() if now is None else now)
        with self.store.lock():
            session = self.store.get_session(claims.session_id)
            family = self.store.get_family(claims.family_id)
            if session is None or family is None:
                _log_judgment(
                    logging.WARNING,
                    "refresh_session_missing",
                    token_id=claims.token_id,
                    session_id=claims.session_id,
                    family_id=claims.family_id,
                    detail="依据=本地存储中不存在该会话/家族",
                )
                raise SessionNotFoundError("会话不存在或已被清除")
            if family.session_id != session.session_id:
                _log_judgment(
                    logging.WARNING,
                    "refresh_family_mismatch",
                    token_id=claims.token_id,
                    session_id=claims.session_id,
                    family_id=claims.family_id,
                    detail="依据=令牌家族与会话无法对应",
                )
                raise SessionNotFoundError("令牌所属刷新家族与会话不匹配")

            # 家族已吊销：若送来的是用过的旧令牌，结论仍是“重放”；
            # 否则属于注销/吊销后的使用。
            if family.revoked:
                if claims.token_id in family.used_refresh_ids:
                    _log_judgment(
                        logging.WARNING,
                        "refresh_replay_after_revoke",
                        token_id=claims.token_id,
                        session_id=claims.session_id,
                        family_id=claims.family_id,
                        detail="依据=家族已吊销且该刷新令牌在 used 集合中",
                    )
                    raise RefreshReplayError(
                        "刷新令牌重放：会话家族已因重放被整体吊销"
                    )
                _log_judgment(
                    logging.WARNING,
                    "refresh_revoked",
                    token_id=claims.token_id,
                    session_id=claims.session_id,
                    family_id=claims.family_id,
                    detail=f"依据=家族已吊销 reason={family.revoke_reason}",
                )
                raise TokenRevokedError(
                    f"刷新令牌所属会话已被吊销: {family.revoke_reason}"
                )

            if claims.token_id == family.current_refresh_id:
                new_access, _, new_refresh, new_refresh_claims = (
                    self._issue_pair(
                        session_id=session.session_id,
                        family_id=family.family_id,
                        subject=session.subject,
                        now_ts=now_ts,
                    )
                )
                advanced = self.store.rotate_refresh(
                    family.family_id,
                    claims.token_id,
                    new_refresh_claims.token_id,
                )
                # 锁内 current 与传入 id 相等，推进必然成功；防御性断言
                if not advanced:
                    _log_judgment(
                        logging.ERROR,
                        "refresh_rotate_failed",
                        token_id=claims.token_id,
                        session_id=claims.session_id,
                        family_id=claims.family_id,
                        detail="依据=锁内轮换推进失败（不应发生）",
                    )
                    raise TokenRevokedError("刷新令牌在轮换时失效")
                _log_judgment(
                    logging.INFO,
                    "refresh_rotated",
                    token_id=claims.token_id,
                    session_id=claims.session_id,
                    family_id=family.family_id,
                    detail=(
                        f"依据=旧刷新令牌匹配 current，已轮换为新令牌 "
                        f"new_token_id={_short(new_refresh_claims.token_id)}"
                    ),
                )
                return new_access, new_refresh

            if claims.token_id in family.used_refresh_ids:
                self.store.revoke_family(
                    family.family_id, "refresh_token_replay"
                )
                _log_judgment(
                    logging.WARNING,
                    "refresh_replay_detected",
                    token_id=claims.token_id,
                    session_id=claims.session_id,
                    family_id=family.family_id,
                    detail="依据=刷新令牌命中 used 集合，已吊销整条会话家族",
                )
                raise RefreshReplayError(
                    "刷新令牌重放：同一刷新令牌只能成功使用一次，"
                    "会话家族已被整体吊销"
                )

            _log_judgment(
                logging.WARNING,
                "refresh_unknown_token",
                token_id=claims.token_id,
                session_id=claims.session_id,
                family_id=claims.family_id,
                detail="依据=刷新令牌既非当前令牌也不在 used 集合",
            )
            raise TokenRevokedError("刷新令牌不属于家族当前轮换链")

    # ------------------------------------------------------------------ 注销
    def logout(
        self,
        refresh_token: str | None = None,
        session_id: str | None = None,
    ) -> bool:
        """注销会话：吊销该会话与其刷新家族。

        幂等：重复注销、对不存在的会话注销都返回 False 且不抛异常。
        返回 True 表示本次调用实际发生了吊销。
        """
        target_session_id = session_id
        if refresh_token:
            try:
                claims = decode_token(refresh_token, self._secret)
            except TokenMalformedError:
                _log_judgment(
                    logging.INFO,
                    "logout_bad_token_ignored",
                    detail="依据=注销请求携带无法验签的令牌，按幂等忽略",
                )
                claims = None
            if claims is not None:
                target_session_id = claims.session_id
                _log_judgment(
                    logging.INFO,
                    "logout_token_decoded",
                    token_id=claims.token_id,
                    session_id=claims.session_id,
                    family_id=claims.family_id,
                    detail="依据=注销请求由刷新令牌定位会话",
                )

        if not target_session_id:
            _log_judgment(
                logging.INFO,
                "logout_no_target",
                detail="依据=未提供可定位会话的令牌或会话标识，按幂等返回",
            )
            return False

        changed = self.store.revoke_session(target_session_id, "logout")
        _log_judgment(
            logging.INFO,
            "logout_done" if changed else "logout_already_revoked",
            session_id=target_session_id,
            detail=(
                "依据=本次调用已吊销会话与家族"
                if changed
                else "依据=会话不存在或此前已吊销，幂等返回"
            ),
        )
        return changed
