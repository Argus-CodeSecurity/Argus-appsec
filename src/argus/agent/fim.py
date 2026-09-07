"""File integrity monitoring for configured paths (spec §25)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    ScanResult,
    Severity,
)


def _hash_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _stat_sig(path: Path) -> dict[str, int | str] | None:
    try:
        st = path.stat()
        return {"mode": st.st_mode, "uid": st.st_uid, "size": st.st_size}
    except OSError:
        return None


def snapshot_integrity(paths: list[str], state_file: Path) -> dict[str, dict]:
    current: dict[str, dict] = {}
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            continue
        current[str(p)] = {
            "hash": _hash_file(p) if p.is_file() else None,
            "stat": _stat_sig(p),
        }
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    return current


def check_integrity(
    paths: list[str],
    state_file: Path,
    *,
    host_label: str | None = None,
) -> ScanResult:
    """Compare current file state to the last snapshot; update snapshot."""
    label = host_label or "host"
    previous: dict[str, dict] = {}
    if state_file.is_file():
        try:
            previous = json.loads(state_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            previous = {}

    current = snapshot_integrity(paths, state_file)
    findings: list[Finding] = []

    for path, now in current.items():
        before = previous.get(path)
        if before is None:
            continue
        if before.get("hash") and now.get("hash") and before["hash"] != now["hash"]:
            findings.append(Finding(
                id=f"fim:changed:{path}",
                rule_id="fim.content-changed",
                scanner="fim",
                title=f"Critical file changed: {path}",
                description="File content hash differs from the previous agent cycle.",
                location=Location(path=path, snippet=path),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                likelihood=Likelihood.POSSIBLE,
                why_vulnerable="Unexpected changes to security-sensitive files may indicate compromise.",
                remediation=Remediation(
                    summary="Review the change and restore from known-good backup if unauthorized.",
                    guidance="Investigate who changed the file and whether it was expected.",
                ),
                tags=["fim", "integrity"],
                metadata={"verification": "confirmed", "before_hash": before["hash"], "after_hash": now["hash"]},
            ))
        bstat, nstat = before.get("stat"), now.get("stat")
        if bstat and nstat and bstat != nstat and before.get("hash") == now.get("hash"):
            findings.append(Finding(
                id=f"fim:perm:{path}",
                rule_id="fim.permission-changed",
                scanner="fim",
                title=f"File permissions changed: {path}",
                description="Metadata changed without content hash change.",
                location=Location(path=path, snippet=str(nstat)),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                likelihood=Likelihood.POSSIBLE,
                why_vulnerable="Permission changes on sensitive files can weaken access controls.",
                remediation=Remediation(summary="Verify the permission change was authorized."),
                tags=["fim", "integrity"],
                metadata={"verification": "confirmed"},
            ))

    for path in previous:
        if path not in current:
            findings.append(Finding(
                id=f"fim:removed:{path}",
                rule_id="fim.file-removed",
                scanner="fim",
                title=f"Monitored file removed: {path}",
                description="A file on the integrity watch list no longer exists.",
                location=Location(path=path, snippet=path),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                likelihood=Likelihood.POSSIBLE,
                why_vulnerable="Removal of security-sensitive files may indicate tampering.",
                remediation=Remediation(summary="Restore the file from backup if removal was not planned."),
                tags=["fim", "integrity"],
                metadata={"verification": "confirmed"},
            ))

    return ScanResult(
        target=f"fim:{label}",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        findings=findings,
        scanners_run=["fim"],
    )
