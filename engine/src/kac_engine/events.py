"""Live-Events für die Oberfläche (WebSocket-Verteiler)."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any


class EventHub:
    """Verteilt Events an alle WebSocket-Abonnenten und puffert sie pro Lauf."""

    def __init__(self, max_buffer: int = 5000) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._buffers: dict[str, list[dict]] = defaultdict(list)
        self._max_buffer = max_buffer

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def history(self, run_id: str) -> list[dict]:
        return list(self._buffers.get(run_id, []))

    async def publish(self, type_: str, run_id: str, **data: Any) -> dict:
        event = {"type": type_, "run_id": run_id, "ts": datetime.now(UTC).isoformat(), **data}
        buffer = self._buffers[run_id]
        if len(buffer) < self._max_buffer:
            buffer.append(event)
        for queue in list(self._subscribers):
            if queue.full():
                # Langsamer Client: ältestes Event verwerfen statt die Engine zu blockieren
                queue.get_nowait()
            queue.put_nowait(event)
        return event
