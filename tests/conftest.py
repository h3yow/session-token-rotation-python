"""测试公共配置：打开 auth 日志，让每条判定都打印令牌/会话标识与依据。"""

from __future__ import annotations

import logging

import pytest

from auth.service import AuthService


@pytest.fixture
def service() -> AuthService:
    """每个测试使用全新的本地存储，避免状态串扰。"""
    return AuthService()


def pytest_configure(config: pytest.Config) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s | %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    logger = logging.getLogger("auth")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False
