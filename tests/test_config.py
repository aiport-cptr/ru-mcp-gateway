"""Конфигурация должна отказываться стартовать в небезопасном виде."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from rugw.policy import admission_role
from tests.conftest import make_settings


def test_ok_dev(tmp_path):
    make_settings(tmp_path)


@pytest.mark.parametrize(
    "over",
    [
        {"public_url": "http://mcp.company.ru", "dev_mode": False},  # http в проде
        {"public_url": "http://mcp.company.ru", "dev_mode": True},  # dev_mode не на localhost
        {"public_url": "https://mcp.example.com", "dev_mode": False, "database_url": "postgresql+asyncpg://x/y"},
        {"public_url": "https://mcp.company.ru", "dev_mode": False, "database_url": "sqlite+aiosqlite:///x.db"},
        {"public_url": "https://mcp.company.ru/sub"},
        {"yandex_client_secret": "change-me"},
        {"yandex_client_secret": ""},
        {"default_role": "admin"},
        {"allowed_email_domains": "", "bootstrap_admin_emails": ""},
    ],
)
def test_unsafe_configs_rejected(tmp_path, over):
    with pytest.raises(ValidationError):
        make_settings(tmp_path, **over)


def test_admission(tmp_path):
    s = make_settings(tmp_path, allowed_emails="contractor@gmail.com")
    assert admission_role(s, "boss@company.ru") == "admin"
    assert admission_role(s, "ann@company.ru") == "readonly"
    assert admission_role(s, "ANN@Company.RU") == "readonly"
    assert admission_role(s, "contractor@gmail.com") == "readonly"
    assert admission_role(s, "other@gmail.com") is None
    assert admission_role(s, "a@evil-company.ru") is None
    assert admission_role(s, "a@sub.company.ru") is None
    assert admission_role(s, "not-an-email") is None
