"""Server agent: monitor multiple paths on a host and push results."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from argus.agent.config import AgentConfig, AgentTarget
from argus.agent.fim import check_integrity
from argus.agent.host_posture import assess_host
from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.models import ScanResult, Severity
from argus.targets import resolve
from argus.upload import PushError, build_ingest_payload, push_result
from argus.watch.scheduler import run_watch_cycle, state_dir_for


@dataclass
class AgentCycleSummary:
    targets_scanned: int = 0
    total_findings: int = 0
    exit_code: int = 0


def _scan_target(target: AgentTarget, host_label: str | None) -> tuple[ScanResult, Callable[[], None]]:
    resolved = resolve(target.path)
    if resolved.project is None:
        raise RuntimeError(f"Agent target is not a scannable path or repo: {target.path}")

    cfg = Config.load(
        path=target.config,
        project_root=resolved.project.root if resolved.project.origin == "local" else None,
    )
    cfg.trust_project_config = resolved.project.origin == "local"
    if target.scanners:
        cfg.scanners = target.scanners

    def scan() -> ScanResult:
        result = ScanEngine(cfg).scan(resolved.project)
        if host_label:
            result.target = f"{host_label}:{result.target}"
        return result

    return scan(), resolved.cleanup


def run_agent_cycle(
    config: AgentConfig,
    *,
    on_target: Callable[[str, ScanResult], None] | None = None,
) -> AgentCycleSummary:
    """Scan every configured target once."""
    summary = AgentCycleSummary()
    worst = 0

    if config.push and not (config.cloud_url and config.cloud_token):
        raise PushError("Agent push enabled but cloud URL/token is missing.")

    def _maybe_push(result: ScanResult) -> None:
        if not config.push:
            return
        payload = build_ingest_payload(result)
        push_result(payload, url=config.cloud_url, token=config.cloud_token)  # type: ignore[arg-type]

    if config.host_posture:
        store = state_dir_for("host-posture", config.state_dir)
        outcome = run_watch_cycle(
            scan_fn=lambda: assess_host(label=config.host_label),
            state_dir=store,
            fail_on_drift=config.fail_on_drift,
            push_fn=_maybe_push if config.push else None,
        )
        summary.targets_scanned += 1
        summary.total_findings += len(outcome.scan.findings)
        worst = max(worst, outcome.exit_code)

    if config.integrity_paths:
        state_file = config.state_dir / "integrity.json"
        store = state_dir_for("fim", config.state_dir)
        outcome = run_watch_cycle(
            scan_fn=lambda: check_integrity(
                config.integrity_paths, state_file, host_label=config.host_label,
            ),
            state_dir=store,
            fail_on_drift=config.fail_on_drift,
            push_fn=_maybe_push if config.push else None,
        )
        summary.targets_scanned += 1
        summary.total_findings += len(outcome.scan.findings)
        worst = max(worst, outcome.exit_code)

    for target in config.targets:
        scan_fn, cleanup = _scan_target(target, config.host_label)
        store = state_dir_for(target.path, config.state_dir)

        def push_fn(result: ScanResult) -> None:
            _maybe_push(result)

        try:
            outcome = run_watch_cycle(
                scan_fn=scan_fn,
                state_dir=store,
                fail_on_drift=config.fail_on_drift,
                push_fn=push_fn if config.push else None,
            )
            summary.targets_scanned += 1
            summary.total_findings += len(outcome.scan.findings)
            worst = max(worst, outcome.exit_code)
            if on_target:
                on_target(target.path, outcome.scan)
        finally:
            cleanup()

    summary.exit_code = worst
    return summary


def run_agent_loop(
    config: AgentConfig,
    *,
    once: bool = False,
    on_cycle: Callable[[AgentCycleSummary], None] | None = None,
) -> int:
    """Run agent cycles until interrupted or ``once`` is set."""
    worst = 0
    while True:
        summary = run_agent_cycle(config)
        if on_cycle:
            on_cycle(summary)
        worst = max(worst, summary.exit_code)
        if once:
            return worst
        try:
            time.sleep(max(1, config.interval))
        except KeyboardInterrupt:
            return worst
