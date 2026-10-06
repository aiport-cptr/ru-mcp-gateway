"""Реестр коннекторов. Коннектор включается, только если заданы его учётные данные."""

from __future__ import annotations

import httpx

from rugw.access import CONNECTORS
from rugw.config import Settings
from rugw.connectors import amocrm, bitrix24, kontur_focus, marketplaces, moysklad, onec_odata, yandex_tracker
from rugw.tools import ToolSpec

BUILDERS = (
    yandex_tracker.build,
    bitrix24.build,
    onec_odata.build,
    amocrm.build,
    moysklad.build,
    kontur_focus.build,
    marketplaces.build,
)


def build_all(settings: Settings, http: httpx.AsyncClient, credentials=None) -> list[ToolSpec]:
    specs: list[ToolSpec] = []
    for build in BUILDERS:
        specs.extend(build(settings, http, credentials))
    for spec in specs:
        if spec.connector is None:  # инструмент коннектора без коннектора обошёл бы права на ресурсы
            raise RuntimeError(f"Инструмент {spec.name} не указал коннектор")
        if spec.connector not in CONNECTORS:  # на неизвестный коннектор нельзя выдать права — ошибка в коде
            raise RuntimeError(f"Инструмент {spec.name}: коннектор {spec.connector} не объявлен в access.CONNECTORS")
    return specs
