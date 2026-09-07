"""False-positive and risk exception management (spec §47)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import yaml

from argus.core.models import Finding


@dataclass
class FindingException:
    fingerprint: str
    status: str  # accept | false_positive | suppress
    reason: str
    owner: str
    expires_at: str | None = None


def load_exceptions(path: Path) -> list[FindingException]:
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw = data.get("exceptions") or []
    out: list[FindingException] = []
    for e in raw:
        if isinstance(e, dict) and e.get("fingerprint"):
            out.append(FindingException(
                fingerprint=str(e["fingerprint"]),
                status=str(e.get("status", "accept")),
                reason=str(e.get("reason", "")),
                owner=str(e.get("owner", "")),
                expires_at=e.get("expires_at"),
            ))
    return out


def apply_exceptions(findings: list[Finding], exceptions: list[FindingException]) -> tuple[list[Finding], int]:
    if not exceptions:
        return findings, 0
    now = datetime.utcnow().date().isoformat()
    active: dict[str, FindingException] = {}
    for ex in exceptions:
        if ex.expires_at and ex.expires_at < now:
            continue
        active[ex.fingerprint] = ex

    kept: list[Finding] = []
    suppressed = 0
    for f in findings:
        fp = f.fingerprint()
        matched = active.get(fp)
        if matched is not None:
            suppressed += 1
            f.metadata["exception"] = {
                "status": matched.status,
                "reason": matched.reason,
                "owner": matched.owner,
            }
            if matched.status == "suppress":
                continue
            f.metadata["verification"] = "accepted" if matched.status == "accept" else "false_positive"
        kept.append(f)
    return kept, suppressed


def default_exceptions_path(project_root: Path) -> Path:
    return project_root / ".argus" / "exceptions.yml"


def write_exception_template(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        return
    template = {
        "exceptions": [
            {
                "fingerprint": "rule_id|path|hash",
                "status": "accept",
                "reason": "Compensating control documented",
                "owner": "security@example.com",
                "expires_at": "2027-01-01",
            }
        ]
    }
    path.write_text(yaml.safe_dump(template, sort_keys=False), encoding="utf-8")
