"""argus-ignore works in the comment syntax of each file type, and only there."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.project import Project

KEY = "AKIAIOSFODNN7EXAMPLE"
REASON = 'argus-ignore reason="test fixture key"'


def _secret_lines(root: Path, name: str, line: str) -> list[int]:
    root.mkdir(exist_ok=True)
    (root / name).write_text(line + "\n", encoding="utf-8")
    cfg = Config(scanners=["secrets"], cache=False, trust_project_config=True)
    cfg.ai.enabled = False
    result = ScanEngine(cfg).scan(Project.from_path(root))
    return [f.location.start_line or 0 for f in result.findings if f.location.path == name]


# (file, code with the secret, the comment that suppresses it)
CASES = [
    ("q.sql", f"SELECT '{KEY}';", f"-- {REASON}"),
    ("init.lua", f'local k = "{KEY}"', f"-- {REASON}"),
    ("Main.hs", f'key = "{KEY}"', f"-- {REASON}"),
    ("page.html", f"<p>{KEY}</p>", f"<!-- {REASON} -->"),
    ("page.HTM", f"<p>{KEY}</p>", f"<!-- {REASON} -->"),
    ("conf.xml", f"<key>{KEY}</key>", f"<!-- {REASON} -->"),
    ("README.md", f"`{KEY}`", f"<!-- {REASON} -->"),
    ("app.ini", f"key = {KEY}", f"; {REASON}"),
    ("init.lisp", f'(setq key "{KEY}")', f"; {REASON}"),
    ("app.py", f'KEY = "{KEY}"', f"# {REASON}"),
    ("app.js", f'const k = "{KEY}";', f"// {REASON}"),
    ("q.sql", f"SELECT '{KEY}';", f"# {REASON}"),  # `#` and `//` work everywhere
]


@pytest.mark.parametrize(("name", "code", "comment"), CASES)
def test_comment_style_of_the_file_type_suppresses(
    tmp_path: Path, name: str, code: str, comment: str
) -> None:
    assert _secret_lines(tmp_path / "plain", name, code) == [1]
    assert _secret_lines(tmp_path / "ignored", name, f"{code} {comment}") == []


@pytest.mark.parametrize(
    ("name", "line"),
    [
        # `--`, `;` and `<!--` are not comments in these files.
        ("app.py", f'KEY = "{KEY}"  -- {REASON}'),
        ("app.js", f'const k = "{KEY}"; ; {REASON}'),
        ("app.ts", f'const k = "{KEY}" <!-- {REASON} -->'),
        ("notes.txt", f"{KEY} ; {REASON}"),
    ],
)
def test_other_comment_styles_do_not_suppress(tmp_path: Path, name: str, line: str) -> None:
    assert _secret_lines(tmp_path, name, line) == [1]


def test_reason_is_still_required_in_every_style(tmp_path: Path) -> None:
    assert _secret_lines(tmp_path, "q.sql", f"SELECT '{KEY}'; -- argus-ignore") == [1]
