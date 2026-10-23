"""`.nephilex/exceptions.yml` parsing: YAML dates, bad shapes, expiry."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from nephilex.core.config import ConfigError
from nephilex.core.models import Finding, Location, Severity
from nephilex.exceptions import FindingException, apply_exceptions, load_exceptions


def _finding() -> Finding:
    return Finding(
        id="secrets:x:1",
        rule_id="secrets.x",
        scanner="secrets",
        title="t",
        description="d",
        severity=Severity.HIGH,
        location=Location(path="a.py", start_line=1, snippet="k = 'v'"),
    )


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "exceptions.yml"
    p.write_text(text, encoding="utf-8")
    return p


def test_unquoted_yaml_date_does_not_crash(tmp_path: Path) -> None:
    f = _finding()
    future = (datetime.now(timezone.utc).date() + timedelta(days=30)).isoformat()
    past = "2001-01-01"
    p = _write(
        tmp_path,
        f"exceptions:\n"
        f"  - fingerprint: '{f.fingerprint()}'\n    status: suppress\n"
        f"    expires_at: {future}\n",
    )
    excs = load_exceptions(p)
    assert isinstance(excs[0].expires_at, date)
    kept, n = apply_exceptions([f], excs)
    assert (kept, n) == ([], 1)

    p = _write(
        tmp_path,
        f"exceptions:\n"
        f"  - fingerprint: '{f.fingerprint()}'\n    status: suppress\n"
        f"    expires_at: {past}\n",
    )
    kept, n = apply_exceptions([_finding()], load_exceptions(p))
    assert len(kept) == 1 and n == 0


def test_quoted_string_date_still_works() -> None:
    f = _finding()
    ex = FindingException(f.fingerprint(), "suppress", "r", "o", expires_at="2001-01-01")
    kept, n = apply_exceptions([f], [ex])
    assert len(kept) == 1 and n == 0


def test_unparseable_expiry_never_suppresses() -> None:
    f = _finding()
    ex = FindingException(f.fingerprint(), "suppress", "r", "o", expires_at="someday")
    kept, _ = apply_exceptions([f], [ex])
    assert kept == [f]


@pytest.mark.parametrize(
    "text",
    [
        "- just\n- a list\n",
        "exceptions: nope\n",
        "exceptions:\n  - 42\n",
        "exceptions:\n  - status: suppress\n",
        "exceptions:\n  - fingerprint: abc\n    status: ignore-forever\n",
        "exceptions:\n  - fingerprint: abc\n    expires_at: tomorrow\n",
        "exceptions: [\n",
    ],
)
def test_malformed_file_is_config_error(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_exceptions(_write(tmp_path, text))


def test_empty_file_is_fine(tmp_path: Path) -> None:
    assert load_exceptions(_write(tmp_path, "")) == []
