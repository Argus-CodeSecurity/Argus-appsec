"""Database models and engine for the dashboard (SQLite via SQLModel).

Three tables model the history the dashboard shows:

* ``Project``: a scanned codebase (grouped by name).
* ``Scan``: one run against a project, at a point in time, with its rolled-up
  numbers (risk score, severity counts) for fast list/trend rendering.
* ``Finding``: the individual findings of a scan, for the detail view.

The database file defaults to ``~/.nephilex/dashboard.db``; override with the
``NEPHILEX_DASHBOARD_DB`` environment variable (``:memory:`` is honored for tests).
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, Column
from sqlalchemy.pool import StaticPool
from sqlmodel import Field, Session, SQLModel, create_engine


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Project(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    slug: str = Field(index=True, unique=True)
    name: str
    created_at: datetime = Field(default_factory=_now)


class Scan(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id", index=True)
    created_at: datetime = Field(default_factory=_now, index=True)
    nephilex_version: str = ""
    target: str = ""
    risk_score: float = 0.0
    highest_severity: int = 0
    total_findings: int = 0
    # {"Critical": n, "High": n, ...} and the project summary (languages, etc.)
    severity_counts: dict[str, int] = Field(default_factory=dict, sa_column=Column(JSON))
    project_summary: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class Finding(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    rule_id: str = ""
    scanner: str = ""
    title: str = ""
    severity: int = 2
    confidence: int = 1
    likelihood: int = 2
    risk_score: float = 0.0
    path: str = ""
    line: int | None = None
    snippet: str = ""
    cwe: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    owasp: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    why_vulnerable: str = ""
    attacker_perspective: str = ""
    business_impact: str = ""
    remediation: str = ""
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))


def _db_path() -> str:
    raw = os.environ.get("NEPHILEX_DASHBOARD_DB")
    if raw:
        return raw
    directory = Path.home() / ".nephilex"
    directory.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        # Scan history describes vulnerabilities in your code: owner-only.
        with contextlib.suppress(OSError):
            os.chmod(directory, 0o700)
    return str(directory / "dashboard.db")


def _restrict_db_file(path: str) -> None:
    """Create the SQLite file 0600 (POSIX) before SQLite does with the umask.

    SQLite gives its journal/WAL files the same mode as the database file.
    """
    if os.name == "nt" or path == ":memory:":
        return
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)


_engine = None


def _make_engine(url: str):
    kwargs: dict = {"echo": False, "connect_args": {"check_same_thread": False}}
    # In-memory SQLite gives each connection its own empty database; a StaticPool
    # shares one connection across threads so tables persist (needed for the app's
    # threaded request handling and for tests).
    if url in ("sqlite://", "sqlite:///:memory:"):
        kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)
    SQLModel.metadata.create_all(engine)
    return engine


def get_engine():
    global _engine
    if _engine is None:
        path = _db_path()
        _restrict_db_file(path)
        url = "sqlite://" if path == ":memory:" else f"sqlite:///{path}"
        _engine = _make_engine(url)
    return _engine


def reset_engine_for_tests(url: str = "sqlite://") -> None:
    """Point the engine at a fresh (in-memory) database. Test-only."""
    global _engine
    _engine = _make_engine(url)


def get_session() -> Iterator[Session]:
    with Session(get_engine()) as session:
        yield session
