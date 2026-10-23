"""False-positive and risk exception management (spec §47)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from nephilex.core.config import ConfigError
from nephilex.core.models import Finding

VALID_STATUSES = ("accept", "false_positive", "suppress")


@dataclass
class FindingException:
    fingerprint: str
    status: str  # accept | false_positive | suppress
    reason: str
    owner: str
    # A date, or an ISO ``YYYY-MM-DD`` string. Unquoted dates in YAML load as
    # ``datetime.date``; quoted ones as strings. Both are accepted.
    expires_at: date | str | None = None


def _as_date(value: Any) -> date | None:
    """Parse an expiry value, or return None if it is not a valid date."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value).strip())
    except ValueError:
        return None


def load_exceptions(path: Path) -> list[FindingException]:
    """Load ``.nephilex/exceptions.yml``.

    A malformed file is a :class:`ConfigError` rather than a crash (or a
    silent partial load), so the user sees exactly which entry is wrong.
    """
    if not path.is_file():
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"{path}: cannot read exceptions file: {exc}") from exc
    if data is None:
        return []
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a mapping with an 'exceptions:' list")
    raw = data.get("exceptions") or []
    if not isinstance(raw, list):
        raise ConfigError(f"{path}: 'exceptions' must be a list")
    out: list[FindingException] = []
    for i, e in enumerate(raw, start=1):
        where = f"{path}: exception #{i}"
        if not isinstance(e, dict):
            raise ConfigError(f"{where}: expected a mapping, got {type(e).__name__}")
        fingerprint = e.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint.strip():
            raise ConfigError(f"{where}: 'fingerprint' is required")
        status = str(e.get("status", "accept"))
        if status not in VALID_STATUSES:
            raise ConfigError(
                f"{where}: unknown status {status!r} (choose from: {', '.join(VALID_STATUSES)})"
            )
        expires = e.get("expires_at")
        if expires is not None and _as_date(expires) is None:
            raise ConfigError(f"{where}: expires_at {expires!r} is not a YYYY-MM-DD date")
        out.append(
            FindingException(
                fingerprint=fingerprint.strip(),
                status=status,
                reason=str(e.get("reason", "")),
                owner=str(e.get("owner", "")),
                expires_at=_as_date(expires) if expires is not None else None,
            )
        )
    return out


def apply_exceptions(
    findings: list[Finding], exceptions: list[FindingException]
) -> tuple[list[Finding], int]:
    if not exceptions:
        return findings, 0
    today = datetime.now(timezone.utc).date()
    active: dict[str, FindingException] = {}
    for ex in exceptions:
        if ex.expires_at is not None:
            expires = _as_date(ex.expires_at)
            # An unparseable expiry never suppresses (fail closed), and an
            # expired one lets the finding resurface.
            if expires is None or expires < today:
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
            f.metadata["verification"] = (
                "accepted" if matched.status == "accept" else "false_positive"
            )
        kept.append(f)
    return kept, suppressed


def default_exceptions_path(project_root: Path) -> Path:
    return project_root / ".nephilex" / "exceptions.yml"


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
