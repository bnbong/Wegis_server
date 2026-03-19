# --------------------------------------------------------------------------
# In-memory performance record store
# --------------------------------------------------------------------------
import asyncio
from collections import deque
from typing import Any


class PerformanceStore:
    def __init__(self, maxlen: int = 10000):
        self._records: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._lock = asyncio.Lock()

    async def add(self, record: dict[str, Any]) -> None:
        async with self._lock:
            self._records.append(record)

    async def list(self, scenario: str | None = None) -> list[dict[str, Any]]:
        async with self._lock:
            records = list(self._records)
        if scenario is None:
            return records
        return [r for r in records if r.get("scenario") == scenario]

    async def clear(self) -> None:
        async with self._lock:
            self._records.clear()


perf_store = PerformanceStore()
