"""会话状态的本地存储（线程安全的内存实现）。

用本地内存模拟会话数据库：

* Session：一次登录产生一条会话，挂在某个“刷新家族”下。
* 刷新令牌轮换时记录“当前有效刷新令牌 id”与“已使用过的刷新令牌 id 集合”。
* 一旦检测到重放，整个家族标记为 revoked，家族下所有会话连带失效。

所有变更操作通过同一把可重入锁串行化，保证并发刷新下结论唯一。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass(slots=True)
class Session:
    """一条登录会话。"""

    session_id: str
    family_id: str
    subject: str
    created_at: int
    revoked: bool = False
    revoke_reason: str = ""


@dataclass(slots=True)
class RefreshFamily:
    """刷新令牌家族：同一次登录的整条刷新链。"""

    family_id: str
    session_id: str
    subject: str
    current_refresh_id: str
    used_refresh_ids: set[str] = field(default_factory=set)
    revoked: bool = False
    revoke_reason: str = ""


class SessionStore:
    """线程安全的内存会话存储。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, Session] = {}
        self._families: dict[str, RefreshFamily] = {}

    def lock(self) -> threading.RLock:
        """返回底层锁，服务层用它保证“检查+变更”整体原子。"""
        return self._lock

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def get_family(self, family_id: str) -> RefreshFamily | None:
        with self._lock:
            return self._families.get(family_id)

    def get_family_by_session(self, session_id: str) -> RefreshFamily | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            return self._families.get(session.family_id)

    def create(self, session: Session, family: RefreshFamily) -> None:
        with self._lock:
            self._sessions[session.session_id] = session
            self._families[family.family_id] = family

    def rotate_refresh(
        self, family_id: str, old_refresh_id: str, new_refresh_id: str
    ) -> bool:
        """把家族当前刷新令牌从旧 id 推进到新 id。

        仅当家族未吊销、旧 id 仍为当前令牌时成功（返回 True）；
        旧 id 已被使用过说明发生重放，返回 False，调用方负责吊销整个家族。
        """
        with self._lock:
            family = self._families.get(family_id)
            if family is None or family.revoked:
                return False
            if family.current_refresh_id != old_refresh_id:
                return False
            family.used_refresh_ids.add(old_refresh_id)
            family.current_refresh_id = new_refresh_id
            return True

    def revoke_family(self, family_id: str, reason: str) -> bool:
        """吊销整个刷新家族，家族关联会话同时标记吊销。

        幂等：家族不存在返回 False；已吊销时保持原吊销原因并返回 False。
        """
        with self._lock:
            family = self._families.get(family_id)
            if family is None or family.revoked:
                return False
            family.revoked = True
            family.revoke_reason = reason
            session = self._sessions.get(family.session_id)
            if session is not None and not session.revoked:
                session.revoked = True
                session.revoke_reason = reason
            return True

    def revoke_session(self, session_id: str, reason: str) -> bool:
        """注销单条会话：会话与其刷新家族一起吊销。

        幂等：会话不存在返回 False；已吊销返回 False，不抛异常。
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            changed = False
            if not session.revoked:
                session.revoked = True
                session.revoke_reason = reason
                changed = True
            family = self._families.get(session.family_id)
            if family is not None and not family.revoked:
                family.revoked = True
                family.revoke_reason = reason
                changed = True
            return changed
