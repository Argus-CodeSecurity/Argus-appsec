"""Tests for target resolution and clone-URL safety."""

from __future__ import annotations

import pytest

from argus.targets import _is_safe_clone_url, resolve


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/octo/repo.git",
        "http://example.com/x/y.git",
        "git@github.com:octo/repo.git",
        "ssh://git@host.example/owner/repo.git",
        "git://example.com/repo.git",
    ],
)
def test_safe_clone_urls_allowed(url):
    assert _is_safe_clone_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "ext::sh -c 'touch /tmp/pwned'",  # git ext:: transport -> command execution
        "file:///etc/passwd",  # local file transport
        "-oProxyCommand=evil",  # option injection
        "fd::17/repo",
    ],
)
def test_dangerous_clone_urls_rejected(url):
    assert not _is_safe_clone_url(url)


def test_resolve_local_path(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    resolved = resolve(str(tmp_path))
    assert resolved.project is not None
    assert resolved.web is None
    resolved.cleanup()


def test_resolve_web_target():
    resolved = resolve("https://example.com")
    assert resolved.web is not None
    assert resolved.project is None
