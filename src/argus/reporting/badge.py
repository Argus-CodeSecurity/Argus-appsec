"""shields.io endpoint reporter: a security badge for a README.

Emits the small JSON that shields.io's ``endpoint`` badge reads, so a project can
publish "Argus: no findings" (or "2 high") on every commit. A scanner that
visibly scans itself is its own best advertisement. Wire it into CI with
``argus scan . -f badge -o badge.json`` and publish the file where shields.io can
fetch it (e.g. gh-pages), then reference it with
``https://img.shields.io/endpoint?url=<raw-url-to-badge.json>``.
"""

from __future__ import annotations

import json

from argus.core.models import ScanResult
from argus.core.plugin import Reporter, reporter


@reporter
class BadgeReporter(Reporter):
    name = "badge"
    extension = "json"
    description = "shields.io endpoint JSON for a README security badge."

    def render(self, result: ScanResult) -> str:
        counts = {str(k).lower(): int(v) for k, v in result.counts_by_severity().items()}
        crit = counts.get("critical", 0)
        high = counts.get("high", 0)
        med = counts.get("medium", 0)
        low = counts.get("low", 0) + counts.get("info", 0)

        if crit + high + med + low == 0:
            message, color = "no findings", "brightgreen"
        elif crit:
            message, color = f"{crit} critical", "red"
        elif high:
            message, color = f"{high} high", "orange"
        elif med:
            message, color = f"{med} medium", "yellow"
        else:
            message, color = f"{low} low", "yellowgreen"

        return json.dumps(
            {
                "schemaVersion": 1,
                "label": "security",
                "message": message,
                "color": color,
            },
            indent=2,
        )
