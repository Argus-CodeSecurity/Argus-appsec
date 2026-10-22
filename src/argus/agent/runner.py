"""Server agent: monitor multiple paths on a host and push results.

Each step of a cycle (host posture, file integrity, every target) runs on its
own: if one fails, the error is logged, recorded on the cycle summary and, when
pushing is enabled, uploaded as an ``agent.step-failed`` finding so a broken or
sabotaged scan is visible in the dashboard. The remaining steps still run, and
the loop keeps going.

Monitored directories are treated as untrusted: their own ``.argus.yml`` and
``.argus/rules`` are never loaded. Only the agent config, and a config file
the agent config names explicitly for a target, decide what is scanned.
Otherwise anyone able to write to a monitored path could switch off the
scanners or allowlist their own changes.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from argus.agent.config import AgentConfig, AgentTarget
from argus.agent.fim import assess_integrity, save_integrity_state
from argus.agent.host_posture import assess_host
from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    ScanResult,
    Severity,
)
from argus.targets import resolve
from argus.upload import PushError, build_ingest_payload, push_result
from argus.watch.scheduler import WatchCycleResult, run_watch_cycle, state_dir_for

log = logging.getLogger("argus.agent")


@dataclass
class AgentCycleSummary:
    targets_scanned: int = 0
    total_findings: int = 0
    exit_code: int = 0
    errors: list[str] = field(default_factory=list)


def target_config(target: AgentTarget) -> Config:
    """The scan config for a target: agent-declared only, never the target's own.

    A monitored directory is untrusted: anyone who can write to it could
    otherwise drop an .argus.yml or .argus/rules there to switch scanners
    off or allowlist their own changes. Only the agent config, and a config
    file it names explicitly for the target, apply.
    """
    cfg = Config.load(path=target.config) if target.config else Config()
    # Set explicitly rather than relying on the Config default.
    cfg.trust_project_config = False
    if target.scanners:
        cfg.scanners = list(target.scanners)
    return cfg


def _scan_target(target: AgentTarget, host_label: str | None) -> tuple[Callable[[], ScanResult], Callable[[], None]]:
    resolved = resolve(target.path)
    if resolved.project is None:
        resolved.cleanup()
        raise RuntimeError(f"Agent target is not a scannable path or repo: {target.path}")

    try:
        cfg = target_config(target)
    except Exception:
        resolved.cleanup()
        raise

    def scan() -> ScanResult:
        proj = resolved.project
        if proj is None:
            raise RuntimeError(f"Agent target is not a scannable path or repo: {target.path}")
        result = ScanEngine(cfg).scan(proj)
        if host_label:
            result.target = f"{host_label}:{result.target}"
        return result

    return scan, resolved.cleanup


def step_failure_result(step: str, exc: BaseException, host_label: str | None) -> ScanResult:
    """A one-finding scan result describing a failed agent step."""
    label = host_label or "host"
    now = datetime.now(timezone.utc)
    message = f"{exc.__class__.__name__}: {exc}"[:500]
    return ScanResult(
        target=f"{label}:{step}",
        started_at=now,
        finished_at=now,
        scanners_run=["agent"],
        errors=[message],
        findings=[Finding(
            id=f"agent:step-failed:{step}",
            rule_id="agent.step-failed",
            scanner="agent",
            title=f"Argus agent could not complete: {step}",
            description=f"The agent step '{step}' failed: {message}",
            location=Location(path=step, snippet=message[:200]),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            likelihood=Likelihood.POSSIBLE,
            why_vulnerable=(
                "While this step fails, changes to what it monitors go unnoticed. "
                "Repeated failures can also mean someone is interfering with monitoring."
            ),
            remediation=Remediation(
                summary="Check the agent logs on the host and fix the failing step."
            ),
            tags=["agent", "monitoring"],
            metadata={"verification": "detected"},
        )],
    )


def run_agent_cycle(
    config: AgentConfig,
    *,
    on_target: Callable[[str, ScanResult], None] | None = None,
) -> AgentCycleSummary:
    """Scan every configured target once.

    Raises :class:`PushError` only for a configuration problem (push enabled
    without a URL/token). Failures of individual steps are recorded on the
    summary and do not stop the cycle.
    """
    summary = AgentCycleSummary()
    worst = 0

    if config.push and not (config.cloud_url and config.cloud_token):
        raise PushError("Agent push enabled but cloud URL/token is missing.")

    def _push(result: ScanResult) -> None:
        payload = build_ingest_payload(result)
        push_result(payload, url=config.cloud_url or "", token=config.cloud_token or "")

    push_fn = _push if config.push else None

    def _fail(step: str, exc: Exception) -> None:
        log.error("agent step %s failed: %s", step, exc)
        summary.errors.append(f"{step}: {exc}")
        if push_fn is None or isinstance(exc, PushError):
            return
        try:
            push_fn(step_failure_result(step, exc, config.host_label))
        except Exception as push_exc:
            log.error("could not report the failure of %s: %s", step, push_exc)

    def _run(step: str, state_key: str, scan_fn: Callable[[], ScanResult],
             commit_fn: Callable[[], None] | None = None) -> WatchCycleResult | None:
        nonlocal worst
        try:
            outcome = run_watch_cycle(
                scan_fn=scan_fn,
                state_dir=state_dir_for(state_key, config.state_dir),
                fail_on_drift=config.fail_on_drift,
                push_fn=push_fn,
                commit_fn=commit_fn,
            )
        except Exception as exc:
            _fail(step, exc)
            return None
        summary.targets_scanned += 1
        summary.total_findings += len(outcome.scan.findings)
        worst = max(worst, outcome.exit_code)
        return outcome

    if config.host_posture:
        _run("host-posture", "host-posture", lambda: assess_host(label=config.host_label))

    if config.integrity_paths:
        state_file = config.state_dir / "integrity.json"
        pending: dict[str, Any] = {}

        def fim_scan() -> ScanResult:
            result, state = assess_integrity(
                config.integrity_paths, state_file, host_label=config.host_label,
            )
            pending["state"] = state
            return result

        def fim_commit() -> None:
            # Only advance the integrity baseline once the result was pushed.
            save_integrity_state(state_file, pending["state"])

        _run("fim", "fim", fim_scan, commit_fn=fim_commit)

    for target in config.targets:
        try:
            scan_fn, cleanup = _scan_target(target, config.host_label)
        except Exception as exc:
            _fail(target.path, exc)
            continue
        try:
            outcome = _run(target.path, target.path, scan_fn)
            if outcome is not None and on_target:
                on_target(target.path, outcome.scan)
        finally:
            cleanup()

    summary.exit_code = max(worst, 2) if summary.errors else worst
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
        try:
            summary = run_agent_cycle(config)
        except PushError:
            raise  # push enabled without URL/token: a config error, not transient
        except Exception as exc:
            if once:
                raise
            log.error("agent cycle failed, will retry next interval: %s", exc)
        else:
            if on_cycle:
                on_cycle(summary)
            worst = max(worst, summary.exit_code)
        if once:
            return worst
        try:
            time.sleep(max(1, config.interval))
        except KeyboardInterrupt:
            return worst
