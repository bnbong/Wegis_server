# --------------------------------------------------------------------------
# Performance instrumentation module
# --------------------------------------------------------------------------
import json
import logging
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, UTC
from time import perf_counter
from typing import Any

from src.services.perf_store import perf_store


logger = logging.getLogger("main")


@dataclass
class StageTimer:
    stages: dict[str, float] = field(default_factory=dict)
    _marks: dict[str, float] = field(default_factory=dict)

    def start(self, name: str) -> None:
        self._marks[name] = perf_counter()

    def stop(self, name: str) -> float:
        started = self._marks.pop(name, None)
        if started is None:
            self.stages[name] = 0.0
            return 0.0
        elapsed_ms = (perf_counter() - started) * 1000
        self.stages[name] = round(elapsed_ms, 3)
        return self.stages[name]


def build_perf_record(
    *,
    url: str,
    source: str,
    timer: StageTimer,
    fetch_mode: str | None = None,
    cache_hit: bool = False,
    scenario: str = "runtime",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    stages = {
        "cache_lookup": timer.stages.get("cache_lookup", 0.0),
        "html_fetch": timer.stages.get("html_fetch", 0.0),
        "preprocess": timer.stages.get("preprocess", 0.0),
        "inference": timer.stages.get("inference", 0.0),
        "db_write": timer.stages.get("db_write", 0.0),
    }
    total_ms = round(sum(stages.values()), 3)
    payload: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "scenario": scenario,
        "url": url,
        "total_ms": total_ms,
        "stages": stages,
        "source": source,
        "fetch_mode": fetch_mode,
        "cache_hit": cache_hit,
    }
    if extra:
        payload.update(extra)
    return payload


def log_perf_record(record: dict[str, Any]) -> None:
    logger.info("PERF_METRIC %s", json.dumps(record, ensure_ascii=False))
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(perf_store.add(record))
    except RuntimeError:
        pass
