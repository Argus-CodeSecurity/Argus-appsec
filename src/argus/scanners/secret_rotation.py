"""Track discovered *live* secrets across scans to catch the most dangerous state:
"found, but never rotated".

A one-off scan tells you a credential is live today. What matters operationally is
whether it is *still* live weeks later, i.e. nobody rotated it. This keeps a small
local state file (only redacted fingerprints and dates, never the secret itself)
so a later scan can say "this key has been live for 30 days and is still not
rotated" and escalate accordingly. A credential that stops appearing live is
treated as resolved and dropped from the state.

This pairs with ``--verify-secrets`` (which sets the ``verification`` verdict). It
is a lightweight local version of the hosted rotation tracker.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from argus.core.models import Finding
from argus.scanners import secret_verify


@dataclass
class RotationTracker:
    path: Path
    state: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> RotationTracker:
        p = Path(path)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        return cls(p, data if isinstance(data, dict) else {})

    def record_live(self, fingerprint: str, today: date) -> int:
        """Record a live secret; return how many days it has been known live."""
        entry = self.state.get(fingerprint)
        if entry is None:
            self.state[fingerprint] = {
                "first_seen": today.isoformat(),
                "last_seen": today.isoformat(),
            }
            return 0
        entry["last_seen"] = today.isoformat()
        try:
            first = date.fromisoformat(entry.get("first_seen", ""))
        except ValueError:
            first = today
            entry["first_seen"] = today.isoformat()
        return max(0, (today - first).days)

    def prune_resolved(self, live_fingerprints: set[str]) -> list[str]:
        """Drop fingerprints no longer live (rotated/removed); return them."""
        resolved = [fp for fp in self.state if fp not in live_fingerprints]
        for fp in resolved:
            del self.state[fp]
        return resolved

    def save(self) -> None:
        with contextlib.suppress(OSError):
            self.path.write_text(json.dumps(self.state, indent=2, sort_keys=True), encoding="utf-8")


def track_rotations(
    findings: list[Finding], state_path: str | Path, *, today: date | None = None
) -> None:
    """Update rotation state from live-secret findings and annotate stale ones."""
    today = today or date.today()
    tracker = RotationTracker.load(state_path)
    live: dict[str, Finding] = {
        f.fingerprint(): f for f in findings if f.metadata.get("verification") == secret_verify.LIVE
    }
    for fp, f in live.items():
        days = tracker.record_live(fp, today)
        if days > 0:
            f.metadata["days_live"] = days
            f.title = f"{f.title} (STILL LIVE after {days} day(s), never rotated)"
            f.description = (
                f"This live credential was first seen {days} day(s) ago and has "
                f"still not been rotated. Rotate it now.\n\n{f.description}"
            )
    tracker.prune_resolved(set(live))
    tracker.save()
