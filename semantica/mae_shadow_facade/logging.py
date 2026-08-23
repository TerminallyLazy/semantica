"""Metadata-only operational events for the Mae shadow facade."""

from __future__ import annotations

import json
import logging
from typing import Protocol


class SafeEventSink(Protocol):
    def emit(self, event: str, route: str, status: int) -> None: ...


class MetadataOnlyEventSink:
    """Emits allowlisted operation metadata, never request or identity values."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("semantica.mae_shadow_facade")

    def emit(self, event: str, route: str, status: int) -> None:
        payload = {"event": event, "route": route, "status": status}
        self._logger.info(json.dumps(payload, sort_keys=True, separators=(",", ":")))


class NullEventSink:
    def emit(self, event: str, route: str, status: int) -> None:
        return None
