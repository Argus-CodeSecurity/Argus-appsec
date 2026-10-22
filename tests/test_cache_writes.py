"""Cache writes are atomic per writer; the ci profile does not use the cache."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from argus.core.cache import ScanCache
from argus.core.project import Project
from argus.profiles import PROFILES


def test_concurrent_saves_leave_a_valid_cache(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path / "cache"))
    root = tmp_path / "proj"
    root.mkdir()

    def writer(i: int) -> None:
        for n in range(20):
            c = ScanCache(root, "test")
            c.store(f"scanner{i}@x", f"file{n}@h", [])
            c.save()

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    cache_dir = tmp_path / "cache" / "scan"
    files = sorted(p.name for p in cache_dir.iterdir())
    assert len(files) == 1 and files[0].endswith(".json"), files  # no stray .tmp
    blob = json.loads((cache_dir / files[0]).read_text(encoding="utf-8"))
    assert blob["argus"] == "test"


def test_ci_profile_disables_cache(tmp_path: Path) -> None:
    from argus.cli._common import build_config

    assert PROFILES["ci"].cache is False
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    common = dict(config=None, project=Project.from_path(tmp_path), scanners=None,
                  exclude=None, ai_provider=None, ai_model=None, no_ai=True,
                  attack_sim=False, patches=False, min_severity=None, fail_on=None)
    assert build_config(profile="ci", **common).cache is False
    assert build_config(profile="fast", **common).cache is True
