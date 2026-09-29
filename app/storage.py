"""本地存储：用内存结构模拟会话状态。

所有对家族状态的读写都在同一把锁内完成，保证「同一刷新令牌并发刷新
只有一个成功」这一结论。
"""

from __future__ import annotations

import threading

from app.models import TokenFamily


class LocalStore:
    def __init__(self) -> None:
        self._families: dict[str, TokenFamily] = {}
        self._lock = threading.RLock()

    @property
    def lock(self) -> threading.RLock:
        """暴露锁，使服务层可以把「读-判定-改」放进同一个临界区。"""
        return self._lock

    def get(self, family_id: str) -> TokenFamily | None:
        with self._lock:
            return self._families.get(family_id)

    def put(self, family: TokenFamily) -> None:
        with self._lock:
            self._families[family.family_id] = family

    def delete(self, family_id: str) -> None:
        with self._lock:
            self._families.pop(family_id, None)

    def all_families(self) -> dict[str, TokenFamily]:
        """测试辅助：返回家族快照。"""
        with self._lock:
            return dict(self._families)
