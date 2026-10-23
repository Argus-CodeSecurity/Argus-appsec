"""Read-only GitHub access for the held-out benchmark.

Two kinds of request are made, both GET only:

* REST API calls (``/advisories``, ``/repos/{owner}/{repo}/commits/{sha}``) to
  select cases. Responses are cached as JSON under the API cache directory so a
  re-run of ``select`` does not hit the API again.
* Raw file downloads from ``raw.githubusercontent.com`` at an exact commit, to
  fetch the vulnerable and patched versions of each file. No clone is made.

Authentication is optional. ``GITHUB_TOKEN`` (or ``GH_TOKEN``) is sent as a
bearer token when set. ``--api-command`` replaces the built-in client with an
external command that takes the API path as its only argument and prints the
JSON response, for environments where the token lives in a credential helper.
Nothing downloaded here is ever executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
_USER_AGENT = "nephilex-heldout-benchmark"


class GitHubError(RuntimeError):
    """A request failed after retries."""


class Client:
    """Cached, read-only GitHub client."""

    def __init__(self, cache_dir: Path, api_command: str | None = None, offline: bool = False):
        self.cache_dir = cache_dir
        self.api_command = shlex.split(api_command, posix=os.name != "nt") if api_command else None
        self.offline = offline
        self.token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.requests = 0

    def _cache_path(self, path: str) -> Path:
        digest = hashlib.sha256(path.encode("utf-8")).hexdigest()[:32]
        return self.cache_dir / f"{digest}.json"

    def api(self, path: str) -> Any:
        """GET ``path`` from the REST API (cached)."""
        cached = self._cache_path(path)
        if cached.is_file():
            return json.loads(cached.read_text(encoding="utf-8"))["body"]
        if self.offline:
            raise GitHubError(f"offline and not cached: {path}")
        body = self._api_command(path) if self.api_command else self._api_urllib(path)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        cached.write_text(json.dumps({"path": path, "body": body}), encoding="utf-8")
        return body

    def _api_command(self, path: str) -> Any:
        assert self.api_command is not None
        env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
        for attempt in range(3):
            proc = subprocess.run(
                [*self.api_command, path], capture_output=True, text=True, env=env
            )
            self.requests += 1
            if proc.returncode == 0:
                return json.loads(proc.stdout)
            if "404" in proc.stderr or "422" in proc.stderr:
                raise GitHubError(f"GET {path}: {proc.stderr.strip()[-300:]}")
            time.sleep(2 * (attempt + 1))
        raise GitHubError(f"GET {path} failed: {proc.stderr.strip()[-300:]}")

    def _api_urllib(self, path: str) -> Any:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": _USER_AGENT}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return json.loads(_get(API + path, headers))

    def raw(self, repo: str, sha: str, path: str) -> bytes:
        """File content of ``path`` at commit ``sha`` in ``owner/repo``."""
        quoted = urllib.parse.quote(path)
        headers = {"User-Agent": _USER_AGENT}
        return _get(f"{RAW}/{repo}/{sha}/{quoted}", headers)


def _get(url: str, headers: dict[str, str]) -> bytes:
    last: Exception | None = None
    for attempt in range(3):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data: bytes = resp.read()
                return data
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410, 422, 451):
                raise GitHubError(f"GET {url}: HTTP {exc.code}") from exc
            last = exc
        except (urllib.error.URLError, TimeoutError) as exc:
            last = exc
        time.sleep(2 * (attempt + 1))
    raise GitHubError(f"GET {url} failed: {last}")
