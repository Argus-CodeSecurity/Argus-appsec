"""Scan metrics for observability (spec §50)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class ScanMetrics:
    scanners_run: list[str] = field(default_factory=list)
    findings_total: int = 0
    duration_ms: int = 0
    cache_hits: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scanners_run": self.scanners_run,
            "findings_total": self.findings_total,
            "duration_ms": self.duration_ms,
            "cache_hits": self.cache_hits,
            "errors": self.errors,
        }


class MetricsTimer:
    def __init__(self) -> None:
        self._start = time.perf_counter()

    def elapsed_ms(self) -> int:
        return int((time.perf_counter() - self._start) * 1000)
