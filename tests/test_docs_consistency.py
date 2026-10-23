"""The README and the docs homepage describe what the code actually ships.

Both state the number of report formats, and the docs homepage lists them.
These counts drifted once (eight in one place, nine in the other); the
reporter registry is the source of truth.
"""

from __future__ import annotations

import re
from pathlib import Path

from nephilex.core.plugin import registry

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / "README.md", ROOT / "docs" / "index.md"]
NUMBER_WORDS = {
    5: "five",
    6: "six",
    7: "seven",
    8: "eight",
    9: "nine",
    10: "ten",
    11: "eleven",
    12: "twelve",
}


def _reporters() -> list[str]:
    return sorted(registry.reporters())


def test_docs_state_the_real_number_of_report_formats() -> None:
    count = len(_reporters())
    word = NUMBER_WORDS[count]
    for doc in DOCS:
        claims = re.findall(r"\b(\w+)\s+report\s+formats\b", doc.read_text(encoding="utf-8"))
        stated = [c for c in claims if c in NUMBER_WORDS.values()]
        assert stated, f"{doc.name} no longer states how many report formats there are"
        assert set(stated) == {word}, f"{doc.name} says {stated}, the registry has {count}"


def test_docs_homepage_lists_every_report_format() -> None:
    text = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    line = next(ln for ln in text.splitlines() if ln.startswith("nephilex reporters"))
    listed = set(re.findall(r"[a-z]+", line.split("(", 1)[1]))
    assert listed == set(_reporters())
