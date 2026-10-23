"""The DAST scanner only probes a URL the operator chose.

A ``scanner_options.dast.url`` in the scanned repository's own ``.nephilex.yml``
comes from whoever wrote the repo (in CI, possibly a fork's pull request), so
it must never make the runner send requests.
"""

from __future__ import annotations

from nephilex.core.config import Config
from nephilex.core.plugin import ScannerContext
from nephilex.core.project import Project
from nephilex.scanners import dast


def _ctx(root, cfg: Config) -> ScannerContext:
    return ScannerContext(project=Project.from_path(root), config=cfg)


def _record_requests(monkeypatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(dast, "probe", lambda url: calls.append(url) or [])
    monkeypatch.setattr(dast, "_safe_get", lambda url, timeout=8.0: calls.append(url) or None)
    return calls


def test_dast_ignores_url_from_scanned_repo_config(tmp_path, monkeypatch):
    monkeypatch.delenv(dast.ENV_URL, raising=False)
    (tmp_path / ".nephilex.yml").write_text(
        "scanner_options:\n  dast:\n    url: http://169.254.169.254/latest/meta-data/?a=1\n",
        encoding="utf-8",
    )
    cfg = Config.load(project_root=tmp_path)  # what a local scan loads
    calls = _record_requests(monkeypatch)
    assert list(dast.DastScanner().scan(_ctx(tmp_path, cfg))) == []
    assert calls == []


def test_dast_uses_operator_live_target(tmp_path, monkeypatch):
    monkeypatch.delenv(dast.ENV_URL, raising=False)
    (tmp_path / ".nephilex.yml").write_text(
        "scanner_options:\n  dast:\n    url: http://169.254.169.254/\n",
        encoding="utf-8",
    )
    cfg = Config.load(project_root=tmp_path)
    # What `nephilex scan --live-target` does after loading the config.
    cfg.dast_url = "https://app.example.com/"
    calls = _record_requests(monkeypatch)
    list(dast.DastScanner().scan(_ctx(tmp_path, cfg)))
    assert calls and set(calls) == {"https://app.example.com/"}


def test_live_target_equal_to_repo_url_is_still_honoured(tmp_path, monkeypatch):
    # The operator chose this URL explicitly; that the repository happens to
    # declare the same one must not silently disable the scan.
    monkeypatch.delenv(dast.ENV_URL, raising=False)
    (tmp_path / ".nephilex.yml").write_text(
        "scanner_options:\n  dast:\n    url: https://app.example.com/\n",
        encoding="utf-8",
    )
    cfg = Config.load(project_root=tmp_path)
    cfg.dast_url = "https://app.example.com/"
    calls = _record_requests(monkeypatch)
    list(dast.DastScanner().scan(_ctx(tmp_path, cfg)))
    assert calls and set(calls) == {"https://app.example.com/"}


def test_config_files_cannot_set_the_live_target(tmp_path):
    (tmp_path / ".nephilex.yml").write_text(
        "dast_url: http://169.254.169.254/\n",
        encoding="utf-8",
    )
    assert Config.load(project_root=tmp_path).dast_url is None


def test_dast_env_target(tmp_path, monkeypatch):
    monkeypatch.setenv(dast.ENV_URL, "https://env.example.com/")
    calls = _record_requests(monkeypatch)
    list(dast.DastScanner().scan(_ctx(tmp_path, Config())))
    assert calls and set(calls) == {"https://env.example.com/"}


def test_dast_requests_do_not_follow_redirects_blindly(monkeypatch):
    """_safe_get goes through the guarded session (no follow_redirects=True)."""
    seen = {}

    def fake_guarded_get(url, **kwargs):
        seen.update(kwargs, url=url)
        return None

    monkeypatch.setattr(dast, "guarded_get", fake_guarded_get)
    assert dast._safe_get("https://app.example.com/?q=1") is None
    assert seen["url"] == "https://app.example.com/?q=1"
    assert seen["max_bytes"] <= 1_000_000
