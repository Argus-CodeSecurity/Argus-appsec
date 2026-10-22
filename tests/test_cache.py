"""Tests for the per-file scan cache and parallel scanner execution."""

from __future__ import annotations

from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.models import Severity
from argus.core.project import Project


def _fingerprint(result):
    return [
        (f.id, f.rule_id, f.location.path, f.location.start_line, f.severity)
        for f in result.findings
    ]


def test_warm_scan_identical_to_cold(vulnerable_project):
    cfg = Config()
    cold = ScanEngine(cfg).scan(vulnerable_project)

    # Fresh Project object, same directory: everything should come from cache
    # and be indistinguishable from the cold scan, same findings, ids, order.
    warm_project = Project.from_path(vulnerable_project.root)
    warm = ScanEngine(cfg).scan(warm_project)

    assert _fingerprint(warm) == _fingerprint(cold)


def test_cache_skips_unchanged_files_and_rescans_changed(vulnerable_project, monkeypatch):
    cfg = Config()
    ScanEngine(cfg).scan(vulnerable_project)  # populate the cache

    # Count which files the secrets scanner actually re-reads on a warm scan.
    from argus.scanners.secrets import SecretsScanner

    scanned: list[str] = []
    original = SecretsScanner.scan

    def counting_scan(self, ctx):
        scanned.extend(f.rel_path for f in ctx.project.files())
        return original(self, ctx)

    monkeypatch.setattr(SecretsScanner, "scan", counting_scan)

    # Unchanged project: the secrets scanner should not see a single file.
    warm_project = Project.from_path(vulnerable_project.root)
    ScanEngine(cfg).scan(warm_project)
    assert scanned == []

    # Touch one file: only that file is re-scanned.
    changed = vulnerable_project.root / "app.py"
    changed.write_text(changed.read_text(encoding="utf-8") + "\n# edited\n", encoding="utf-8")
    third = Project.from_path(vulnerable_project.root)
    ScanEngine(cfg).scan(third)
    assert scanned == ["app.py"]


def test_no_cache_flag_disables_caching(vulnerable_project, monkeypatch):
    ScanEngine(Config()).scan(vulnerable_project)  # populate

    from argus.scanners.secrets import SecretsScanner

    scanned: list[str] = []
    original = SecretsScanner.scan

    def counting_scan(self, ctx):
        scanned.extend(f.rel_path for f in ctx.project.files())
        return original(self, ctx)

    monkeypatch.setattr(SecretsScanner, "scan", counting_scan)

    result = ScanEngine(Config(cache=False)).scan(Project.from_path(vulnerable_project.root))
    assert scanned, "cache=False must re-scan every file"
    assert result.findings


def test_parallel_and_sequential_results_match(vulnerable_project):
    parallel = ScanEngine(Config(parallel=True, cache=False)).scan(vulnerable_project)
    sequential = ScanEngine(Config(parallel=False, cache=False)).scan(
        Project.from_path(vulnerable_project.root)
    )
    assert _fingerprint(parallel) == _fingerprint(sequential)
    assert parallel.highest_severity() >= Severity.HIGH


def test_cache_on_and_off_produce_identical_ids(vulnerable_project):
    # The determinism guarantee: finding ids (including the :N counter) must be
    # identical whether or not the cache is used, so reports diff cleanly.
    cached = ScanEngine(Config(cache=True)).scan(vulnerable_project)
    uncached = ScanEngine(Config(cache=False)).scan(Project.from_path(vulnerable_project.root))
    assert [f.id for f in cached.findings] == [f.id for f in uncached.findings]
    assert _fingerprint(cached) == _fingerprint(uncached)


def test_remote_projects_are_never_cached(vulnerable_project, monkeypatch):
    vulnerable_project.origin = "github"
    engine = ScanEngine(Config())
    assert engine._open_cache(vulnerable_project) is None
