"""Reading, filtering and exporting audit records for review."""

from __future__ import annotations

import csv
import fnmatch
import io
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from nephilex.audit.log import FIELDS, iter_records, verify_log

# Spreadsheet programs evaluate a cell that starts with one of these as a
# formula. Reasons and paths can come from a suppression comment written by
# anyone with commit access, so they are neutralised for CSV.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


@dataclass
class RecordFilter:
    actions: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()
    rule: str | None = None
    path: str | None = None  # glob
    actor: str | None = None  # substring, case-insensitive
    fingerprint: str | None = None
    since: date | None = None
    until: date | None = None

    def matches(self, rec: dict[str, Any]) -> bool:
        if self.actions and rec.get("action") not in self.actions:
            return False
        if self.kinds and rec.get("kind") not in self.kinds:
            return False
        if self.rule and not _rule_matches(str(rec.get("rule") or ""), self.rule):
            return False
        if self.path and not fnmatch.fnmatchcase(str(rec.get("path") or ""), self.path):
            return False
        if self.actor and self.actor.lower() not in str(rec.get("actor") or "").lower():
            return False
        if self.fingerprint and rec.get("fingerprint") != self.fingerprint:
            return False
        day = _record_date(rec)
        if self.since and (day is None or day < self.since):
            return False
        return not (self.until and (day is None or day > self.until))


def _rule_matches(rule_id: str, wanted: str) -> bool:
    return rule_id == wanted or rule_id.endswith("." + wanted)


def _record_date(rec: dict[str, Any]) -> date | None:
    try:
        return date.fromisoformat(str(rec.get("ts", ""))[:10])
    except ValueError:
        return None


def load_records(
    path: str | Path, flt: RecordFilter | None = None
) -> tuple[list[dict[str, Any]], list[int]]:
    """Parsed records matching ``flt``, plus the line numbers that did not parse."""
    records: list[dict[str, Any]] = []
    unparsed: list[int] = []
    for lineno, rec, _raw in iter_records(path):
        if rec is None:
            unparsed.append(lineno)
            continue
        if flt is None or flt.matches(rec):
            records.append(rec)
    return records, unparsed


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    text = json.dumps(value, sort_keys=True) if isinstance(value, dict | list) else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        text = "'" + text
    return text


def to_csv(records: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    columns = [f for f in FIELDS if f != "v"]
    writer.writerow(columns)
    for rec in records:
        writer.writerow([_csv_cell(rec.get(col)) for col in columns])
    return buf.getvalue()


def to_json(path: str | Path, records: list[dict[str, Any]]) -> str:
    """A JSON document with the chain's verification status and the records."""
    result = verify_log(path)
    doc = {
        "log": str(path),
        "verified": result.ok,
        "records_total": result.records if result.ok else None,
        "head": result.head if result.ok else None,
        "broken_at_line": result.line,
        "problem": result.reason,
        "records": records,
    }
    return json.dumps(doc, indent=2, sort_keys=False) + "\n"
