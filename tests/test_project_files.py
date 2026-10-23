"""Project file walking only yields regular files and reads them with a size bound."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import nephilex.core.project as project_mod
from nephilex.core.project import FileRef, Project


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs need POSIX")
def test_fifo_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    os.mkfifo(tmp_path / "pipe.py")  # type: ignore[attr-defined]
    names = [f.rel_path for f in Project.from_path(tmp_path).files()]
    assert names == ["app.py"]


def test_read_is_bounded_even_if_file_grew(tmp_path: Path, monkeypatch) -> None:
    p = tmp_path / "grown.py"
    p.write_text("x" * 100, encoding="utf-8")
    monkeypatch.setattr(project_mod, "MAX_TEXT_BYTES", 50)
    # Size recorded at walk time was small; the file is now over the limit.
    ref = FileRef(path=p, rel_path="grown.py", size=10)
    assert ref.text() == ""


def test_text_matches_read_text_newlines(tmp_path: Path) -> None:
    p = tmp_path / "crlf.py"
    p.write_bytes(b"a = 1\r\nb = 2\rc = 3\n")
    ref = FileRef(path=p, rel_path="crlf.py", size=p.stat().st_size)
    assert ref.text() == p.read_text(encoding="utf-8")
    assert ref.lines() == ["a = 1", "b = 2", "c = 3"]


def test_binary_detected(tmp_path: Path) -> None:
    p = tmp_path / "blob.py"
    p.write_bytes(b"abc\x00def")
    ref = FileRef(path=p, rel_path="blob.py", size=p.stat().st_size)
    assert ref.is_probably_binary()
    assert ref.text() == ""
