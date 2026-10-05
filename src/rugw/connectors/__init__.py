"""Реестр коннекторов. Коннектор включается, только если заданы его учётные данные."""

from __future__ import annotations

import httpx

from rugw.config import Settings
from rugw.connectors import bitrix24, onec_odata, yandex_tracker
from rugw.tools import ToolSpec

BUILDERS = (yandex_tracker.build, bitrix24.build, onec_odata.build)


def build_all(settings: Settings, http: httpx.AsyncClient) -> list[ToolSpec]:
    specs: list[ToolSpec] = []
    for build in BUILDERS:
        specs.extend(build(settings, http))
    return specs
