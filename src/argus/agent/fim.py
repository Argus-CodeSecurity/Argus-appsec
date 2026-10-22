"""File integrity monitoring for configured paths (spec §25).

Each configured path is recorded every cycle, including paths that do not
exist yet, so a file that appears later is reported. Regular files are
hashed; directories are hashed entry by entry (bounded, symlinks are recorded
but not followed). A path that cannot be read is reported rather than being
silently dropped from monitoring.

:func:`assess_integrity` computes findings and the new state without writing
it; :func:`save_integrity_state` persists it. The agent saves only after the
cycle's results were pushed, so a failed upload does not swallow a change.
:func:`check_integrity` does both, for one-shot use.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    ScanResult,
    Severity,
)

#: Most entries hashed below one monitored directory.
MAX_DIR_ENTRIES = 5000
#: Most changed directory entries listed in a finding.
_MAX_LISTED = 20


def _hash_file(path: Path) -> tuple[str | None, str | None]:
    """Return (sha256, error)."""
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest(), None
    except OSError as exc:
        return None, exc.strerror or exc.__class__.__name__


def _stat_sig(path: Path) -> dict[str, int] | None:
    try:
        st = path.stat()
        return {"mode": st.st_mode, "uid": st.st_uid, "size": st.st_size}
    except OSError:
        return None


def _hash_dir(path: Path) -> dict[str, Any]:
    """Hash a directory tree entry by entry, without following symlinks."""
    entries: dict[str, str] = {}
    truncated = False
    stack: list[tuple[str, str]] = [(str(path), "")]
    while stack and not truncated:
        current, rel = stack.pop()
        try:
            with os.scandir(current) as it:
                items = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            entries[rel or "."] = f"error:{exc.strerror or exc.__class__.__name__}"
            continue
        for item in items:
            if len(entries) >= MAX_DIR_ENTRIES:
                truncated = True
                break
            name = f"{rel}/{item.name}" if rel else item.name
            try:
                if item.is_symlink():
                    entries[name] = f"link:{os.readlink(item.path)}"
                elif item.is_dir(follow_symlinks=False):
                    entries[name] = "dir"
                    stack.append((item.path, name))
                elif item.is_file(follow_symlinks=False):
                    digest, err = _hash_file(Path(item.path))
                    entries[name] = digest or f"error:{err}"
                else:
                    entries[name] = "special"
            except OSError as exc:
                entries[name] = f"error:{exc.strerror or exc.__class__.__name__}"
    combined = hashlib.sha256()
    for name in sorted(entries):
        combined.update(f"{name}\0{entries[name]}\n".encode("utf-8", "surrogateescape"))
    return {"hash": combined.hexdigest(), "entries": entries, "truncated": truncated}


def _record(path: Path) -> dict[str, Any]:
    if not path.exists() and not path.is_symlink():
        return {"absent": True}
    rec: dict[str, Any] = {"stat": _stat_sig(path)}
    if path.is_dir():
        rec.update(type="dir", **_hash_dir(path))
        errors = sorted(k for k, v in rec["entries"].items() if v.startswith("error:"))
        if errors:
            rec["error"] = f"{len(errors)} entries unreadable (e.g. {errors[0]})"
    else:
        digest, err = _hash_file(path)
        rec.update(type="file", hash=digest)
        if err:
            rec["error"] = err
    return rec


def snapshot_paths(paths: list[str]) -> dict[str, dict]:
    """The current integrity record for every configured path (absent ones too)."""
    return {str(Path(raw)): _record(Path(raw)) for raw in paths}


def save_integrity_state(state_file: Path, state: dict[str, dict]) -> None:
    from argus.watch.scheduler import write_private_file

    write_private_file(state_file, json.dumps(state, indent=2) + "\n")


def snapshot_integrity(paths: list[str], state_file: Path) -> dict[str, dict]:
    current = snapshot_paths(paths)
    save_integrity_state(state_file, current)
    return current


def _load_state(state_file: Path) -> dict[str, dict] | None:
    if not state_file.is_file():
        return None
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _fim_finding(kind: str, rule: str, path: str, title: str, description: str,
                 severity: Severity, why: str, fix: str, *, snippet: str | None = None,
                 metadata: dict[str, Any] | None = None) -> Finding:
    return Finding(
        id=f"fim:{kind}:{path}",
        rule_id=rule,
        scanner="fim",
        title=title,
        description=description,
        location=Location(path=path, snippet=snippet or path),
        severity=severity,
        confidence=Confidence.HIGH,
        likelihood=Likelihood.POSSIBLE,
        why_vulnerable=why,
        remediation=Remediation(summary=fix),
        tags=["fim", "integrity"],
        metadata={"verification": "confirmed", **(metadata or {})},
    )


def _dir_changes(before: dict, now: dict) -> dict[str, list[str]]:
    old = before.get("entries") or {}
    new = now.get("entries") or {}
    return {
        "added": sorted(set(new) - set(old))[:_MAX_LISTED],
        "removed": sorted(set(old) - set(new))[:_MAX_LISTED],
        "modified": sorted(k for k in set(old) & set(new) if old[k] != new[k])[:_MAX_LISTED],
    }


def _compare(previous: dict[str, dict] | None, current: dict[str, dict]) -> list[Finding]:
    findings: list[Finding] = []
    for path, now in current.items():
        if now.get("error"):
            findings.append(_fim_finding(
                "unreadable", "fim.unreadable", path,
                f"Monitored path could not be read: {path}",
                f"Argus could not read {path} ({now['error']}), so changes to it "
                "cannot be detected.",
                Severity.MEDIUM,
                "An unreadable monitored file is an unmonitored file; a permission "
                "change can also be a sign of tampering.",
                "Give the agent read access to the path, or remove it from integrity_paths.",
                snippet=str(now["error"]),
            ))
        if previous is None:
            continue  # first cycle: establish the baseline
        before = previous.get(path)
        if before is None:
            continue  # path newly added to the config
        before_absent, now_absent = bool(before.get("absent")), bool(now.get("absent"))
        if before_absent and not now_absent:
            findings.append(_fim_finding(
                "created", "fim.file-created", path,
                f"Monitored path appeared: {path}",
                "A path on the integrity watch list did not exist in the previous "
                "agent cycle and now does.",
                Severity.HIGH,
                "New files at security-sensitive locations (cron entries, "
                "authorized_keys, sudoers.d) are a common persistence technique.",
                "Confirm the file was created intentionally; remove it if not.",
            ))
            continue
        if now_absent and not before_absent:
            findings.append(_fim_finding(
                "removed", "fim.file-removed", path,
                f"Monitored file removed: {path}",
                "A file on the integrity watch list no longer exists.",
                Severity.HIGH,
                "Removal of security-sensitive files may indicate tampering.",
                "Restore the file from backup if removal was not planned.",
            ))
            continue
        if now_absent:
            continue
        b_hash, n_hash = before.get("hash"), now.get("hash")
        if b_hash and n_hash and b_hash != n_hash:
            meta: dict[str, Any] = {"before_hash": b_hash, "after_hash": n_hash}
            desc = "File content hash differs from the previous agent cycle."
            if now.get("type") == "dir":
                meta.update(_dir_changes(before, now))
                desc = ("Directory contents differ from the previous agent cycle "
                        f"(added: {len(meta['added'])}, removed: {len(meta['removed'])}, "
                        f"modified: {len(meta['modified'])}; lists capped at {_MAX_LISTED}).")
            findings.append(_fim_finding(
                "changed", "fim.content-changed", path,
                f"Critical file changed: {path}", desc, Severity.HIGH,
                "Unexpected changes to security-sensitive files may indicate compromise.",
                "Review the change and restore from known-good backup if unauthorized.",
                metadata=meta,
            ))
        bstat, nstat = before.get("stat") or {}, now.get("stat") or {}
        perm_keys = ("mode", "uid")
        if (bstat and nstat and b_hash == n_hash
                and any(bstat.get(k) != nstat.get(k) for k in perm_keys)):
            findings.append(_fim_finding(
                "perm", "fim.permission-changed", path,
                f"File permissions changed: {path}",
                "Metadata changed without content hash change.",
                Severity.MEDIUM,
                "Permission changes on sensitive files can weaken access controls.",
                "Verify the permission change was authorized.",
                snippet=str({k: nstat.get(k) for k in perm_keys}),
            ))
    return findings


def assess_integrity(
    paths: list[str],
    state_file: Path,
    *,
    host_label: str | None = None,
) -> tuple[ScanResult, dict[str, dict]]:
    """Compare current state to the stored baseline without updating it."""
    label = host_label or "host"
    previous = _load_state(state_file)
    current = snapshot_paths(paths)
    now = datetime.now(timezone.utc)
    result = ScanResult(
        target=f"fim:{label}",
        started_at=now,
        finished_at=datetime.now(timezone.utc),
        findings=_compare(previous, current),
        scanners_run=["fim"],
    )
    return result, current


def check_integrity(
    paths: list[str],
    state_file: Path,
    *,
    host_label: str | None = None,
) -> ScanResult:
    """Compare current file state to the last snapshot; update snapshot."""
    result, current = assess_integrity(paths, state_file, host_label=host_label)
    save_integrity_state(state_file, current)
    return result
