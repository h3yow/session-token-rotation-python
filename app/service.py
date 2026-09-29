"""会话服务：签发、校验、轮换、重放检测、注销 / 吊销。

并发正确性的关键：刷新的「读旧令牌 -> 判定 -> 换新令牌 -> 更新家族」
全部在 LocalStore 的同一把锁内完成，因此多个客户端并发使用同一个刷新
令牌时，只有抢到临界区的第一个能成功；随后的请求看到该 jti 已进入
used_refresh_jtis，一律按重放处理并把整条家族置为 revoked。
"""

from __future__ import annotations

import logging
import time
import uuid

from app.errors import (
    InvalidSignatureError,
    RefreshReplayError,
    RevokedError,
    SessionNotFoundError,
    TokenExpiredError,
)
from app.models import TokenFamily, TokenPair
from app.storage import LocalStore
from app.tokens import ACCESS, REFRESH, check_expiry, decode_token, issue_token

logger = logging.getLogger("session_auth")


def _new_jti() -> str:
    return uuid.uuid4().hex


class SessionService:
    def __init__(
        self,
        secret: str,
        store: LocalStore | None = None,
        *,
        access_ttl_seconds: int = 900,
        refresh_ttl_seconds: int = 60 * 60 * 24 * 7,
        clock_skew_leeway_seconds: float = 30.0,
        clock=time.time,
    ) -> None:
        self._secret = secret
        self._store = store or LocalStore()
        self._access_ttl = access_ttl_seconds
        self._refresh_ttl = refresh_ttl_seconds
        self._leeway = float(clock_skew_leeway_seconds)
        self._clock = clock

    @property
    def store(self) -> LocalStore:
        return self._store

    @property
    def leeway(self) -> float:
        return self._leeway

    def _now(self) -> float:
        return self._clock()

    def _log(self, event: str, *, family_id: str, jti: str = "-", reason: str = "-", **extra) -> None:
        details = " ".join(f"{k}={v}" for k, v in extra.items())
        logger.info(
            "event=%s family_id=%s token_jti=%s reason=%s%s",
            event, family_id, jti, reason, (" " + details) if details else "",
        )

    # ------------------------------------------------------------------ #
    # 签发
    # ------------------------------------------------------------------ #
    def login(self, subject: str) -> TokenPair:
        """为主体创建一条新会话（新家族）并签发首组令牌。"""
        now = self._now()
        family_id = str(uuid.uuid4())
        access_jti = _new_jti()
        refresh_jti = _new_jti()

        family = TokenFamily(
            family_id=family_id,
            subject=subject,
            latest_refresh_jti=refresh_jti,
            used_refresh_jtis=set(),
            current_access_jti=access_jti,
            revoked=False,
            created_at=now,
        )
        self._store.put(family)

        pair = self._mint_pair(family_id, subject, access_jti, refresh_jti, now)
        self._log("login", family_id=family_id, jti=refresh_jti, subject=subject,
                  reason="new_family_issued")
        return pair

    def _mint_pair(
        self, family_id: str, subject: str, access_jti: str, refresh_jti: str, now: float
    ) -> TokenPair:
        access_token = issue_token(
            secret=self._secret, token_type=ACCESS, jti=access_jti, family_id=family_id,
            subject=subject, ttl_seconds=self._access_ttl, now=now,
        )
        refresh_token = issue_token(
            secret=self._secret, token_type=REFRESH, jti=refresh_jti, family_id=family_id,
            subject=subject, ttl_seconds=self._refresh_ttl, now=now,
        )
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            access_jti=access_jti,
            refresh_jti=refresh_jti,
            family_id=family_id,
            expires_in=self._access_ttl,
        )

    # ------------------------------------------------------------------ #
    # 访问令牌校验
    # ------------------------------------------------------------------ #
    def authenticate(self, access_token: str) -> dict:
        """校验访问令牌，返回 payload；失败按原因抛出对应错误。

        判定顺序：签名/结构 -> 过期（含时钟容差）-> 会话存在 -> 未吊销/未被轮换取代。
        """
        claims = decode_token(access_token, secret=self._secret, expected_type=ACCESS)
        check_expiry(claims, now=self._now(), leeway=self._leeway)

        family_id = claims["fam"]
        jti = claims["jti"]
        family = self._store.get(family_id)
        if family is None:
            self._log("auth_deny", family_id=family_id, jti=jti, reason="session_not_found")
            raise SessionNotFoundError(f"family {family_id} does not exist")
        if family.revoked:
            self._log("auth_deny", family_id=family_id, jti=jti, reason="family_revoked")
            raise RevokedError(f"family {family_id} revoked")
        if jti != family.current_access_jti:
            # 轮换后旧访问令牌立即失效，也按吊销语义拒绝
            self._log("auth_deny", family_id=family_id, jti=jti,
                      reason="access_token_superseded",
                      current_access_jti=family.current_access_jti)
            raise RevokedError("access token superseded by rotation")

        self._log("auth_allow", family_id=family_id, jti=jti, reason="valid")
        return claims

    # ------------------------------------------------------------------ #
    # 刷新令牌轮换
    # ------------------------------------------------------------------ #
    def refresh(self, refresh_token: str) -> TokenPair:
        """原子地轮换刷新令牌。

        返回的新刷新令牌是该家族唯一有效令牌；旧令牌立即失效。
        若传入的刷新令牌已被使用过（重放），整条家族连带失效。
        """
        # 签名/结构与过期在锁外即可判定（无共享状态）
        claims = decode_token(refresh_token, secret=self._secret, expected_type=REFRESH)
        check_expiry(claims, now=self._now(), leeway=self._leeway)

        family_id = claims["fam"]
        jti = claims["jti"]

        with self._store.lock:
            family = self._store.get(family_id)
            if family is None:
                self._log("refresh_deny", family_id=family_id, jti=jti,
                          reason="session_not_found")
                raise SessionNotFoundError(f"family {family_id} does not exist")

            is_replay = jti in family.used_refresh_jtis
            is_current = jti == family.latest_refresh_jti

            if family.revoked:
                if is_replay or not is_current:
                    # 已被连带吊销后再次出现 -> 仍然是重放结论
                    self._log("refresh_replay", family_id=family_id, jti=jti,
                              reason="replayed_token_after_family_revoked")
                    raise RefreshReplayError("refresh token replay on revoked family")
                self._log("refresh_deny", family_id=family_id, jti=jti,
                          reason="family_revoked")
                raise RevokedError(f"family {family_id} revoked")

            if is_replay or not is_current:
                # 重放：同一刷新令牌第二次（及以后）被使用，
                # 或出现了不属于当前轮换链的令牌 —— 家族整体连带失效。
                # 保留 latest/current 标识，使之后的判定仍可区分
                # 「合法分支的当前令牌（已吊销）」与「旧令牌重放」。
                family.revoked = True
                self._store.put(family)
                self._log("refresh_replay", family_id=family_id, jti=jti,
                          reason="replayed_refresh_token_family_compromised",
                          used_count=len(family.used_refresh_jtis))
                raise RefreshReplayError("refresh token replay; family revoked")

            # 唯一的正常路径：原子换发
            now = self._now()
            new_access_jti = _new_jti()
            new_refresh_jti = _new_jti()
            family.used_refresh_jtis.add(jti)
            family.latest_refresh_jti = new_refresh_jti
            family.current_access_jti = new_access_jti
            self._store.put(family)

            pair = self._mint_pair(family_id, family.subject, new_access_jti,
                                   new_refresh_jti, now)
            self._log("refresh_rotate", family_id=family_id, jti=jti,
                      reason="single_use_enforced", new_refresh_jti=new_refresh_jti,
                      new_access_jti=new_access_jti)
            return pair

    # ------------------------------------------------------------------ #
    # 注销 / 吊销
    # ------------------------------------------------------------------ #
    def revoke(self, family_id: str) -> bool:
        """吊销整条会话家族。幂等：重复吊销 / 家族不存在都返回 False 且不报错。"""
        with self._store.lock:
            family = self._store.get(family_id)
            if family is None:
                self._log("revoke_noop", family_id=family_id, reason="family_not_found")
                return False
            if family.revoked:
                self._log("revoke_noop", family_id=family_id, reason="already_revoked")
                return False
            family.revoked = True
            self._store.put(family)
            self._log("revoke", family_id=family_id, reason="explicit_revoke")
            return True

    def logout(
        self,
        access_token: str | None = None,
        family_id: str | None = None,
    ) -> bool:
        """注销会话。可用访问令牌或显式 family_id 定位；重复注销安全无异常。

        对过期访问令牌保持宽容（注销时不再以过期为由拒绝），但伪造签名
        的令牌无法信任其家族归属，仍抛 InvalidSignatureError。
        """
        if family_id is None:
            if access_token is None:
                raise ValueError("either access_token or family_id is required")
            claims = decode_token(access_token, secret=self._secret, expected_type=ACCESS)
            family_id = claims["fam"]
            self._log("logout", family_id=family_id, jti=claims["jti"],
                      reason="logout_by_access_token")
        else:
            self._log("logout", family_id=family_id, reason="logout_by_family_id")
        return self.revoke(family_id)
