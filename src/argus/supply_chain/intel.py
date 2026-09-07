"""Malicious-package intelligence: bundled seed + optional online refresh."""

from __future__ import annotations

import json
import logging
import time
from functools import lru_cache
from importlib import resources
from pathlib import Path

import httpx

log = logging.getLogger("argus.supply_chain.intel")

# Curated feeds (bundled seed + optional remote refresh). Tried in order.
_DEFAULT_FEEDS = (
    "https://raw.githubusercontent.com/Argus-CodeSecurity/argus-intel/main/malicious-packages.json",
    "https://raw.githubusercontent.com/ossf/malicious-packages/main/osv/malicious/npm.json",
)
_CACHE_TTL = 24 * 3600


def _bundled() -> set[tuple[str, str]]:
    with resources.files("argus.scanners.data").joinpath("supply_chain.json").open(
        encoding="utf-8"
    ) as fh:
        data = json.load(fh)
    return {
        (str(e["ecosystem"]), str(e["name"]).lower())
        for e in data.get("packages", [])
        if e.get("ecosystem") and e.get("name")
    }


def _cache_path() -> Path:
    base = Path.home() / ".argus" / "cache"
    base.mkdir(parents=True, exist_ok=True)
    return base / "malicious-packages.json"


def _read_cache() -> set[tuple[str, str]] | None:
    path = _cache_path()
    if not path.is_file():
        return None
    try:
        if time.time() - path.stat().st_mtime > _CACHE_TTL:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return {
            (str(e["ecosystem"]), str(e["name"]).lower())
            for e in data.get("packages", [])
            if e.get("ecosystem") and e.get("name")
        }
    except (OSError, ValueError, TypeError):
        return None


def _write_cache(packages: set[tuple[str, str]]) -> None:
    payload = {
        "packages": [{"ecosystem": eco, "name": name} for eco, name in sorted(packages)],
    }
    try:
        _cache_path().write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        pass


def _parse_feed_payload(data: object) -> set[tuple[str, str]]:
    if isinstance(data, dict):
        items = data.get("packages") or data.get("items") or []
    elif isinstance(data, list):
        items = data
    else:
        return set()
    out: set[tuple[str, str]] = set()
    for e in items:
        if not isinstance(e, dict):
            continue
        if e.get("affected"):
            for aff in e.get("affected") or []:
                if not isinstance(aff, dict):
                    continue
                pkg = aff.get("package") or {}
                eco, name = pkg.get("ecosystem"), pkg.get("name")
                if eco and name:
                    out.add((str(eco), str(name).lower()))
            continue
        eco = e.get("ecosystem")
        name = e.get("name")
        if eco and name:
            out.add((str(eco), str(name).lower()))
    return out


def _fetch_remote(urls: tuple[str, ...] | str, timeout: float) -> set[tuple[str, str]] | None:
    if isinstance(urls, str):
        urls = (urls,)
    merged: set[tuple[str, str]] = set()
    for url in urls:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(url)
                resp.raise_for_status()
                merged |= _parse_feed_payload(resp.json())
        except Exception as exc:
            log.debug("malicious-package feed fetch failed for %s: %s", url, exc)
    return merged if merged else None


@lru_cache(maxsize=8)
def load_malicious_packages(*, online: bool = True, feed_url: str | None = None,
                            timeout: float = 10.0) -> frozenset[tuple[str, str]]:
    """Return merged malicious-package set (bundled + cache + optional remote)."""
    merged = set(_bundled())
    cached = _read_cache()
    if cached:
        merged |= cached
    if online:
        urls = (feed_url,) if feed_url else _DEFAULT_FEEDS
        remote = _fetch_remote(urls, timeout)
        if remote:
            merged |= remote
            _write_cache(merged)
    return frozenset(merged)


def merge_intel(bundled_only: bool = False, **kwargs) -> frozenset[tuple[str, str]]:
    """Alias for :func:`load_malicious_packages` with explicit offline mode."""
    return load_malicious_packages(online=not bundled_only, **kwargs)


def is_malicious(ecosystem: str, name: str, *, online: bool = True) -> bool:
    key = (ecosystem, name.lower())
    return key in load_malicious_packages(online=online)


# Popular package names used for typosquat / homoglyph detection (spec §7).
_POPULAR_PACKAGES = frozenset({
    "lodash", "react", "express", "axios", "request", "webpack", "typescript",
    "eslint", "prettier", "moment", "async", "debug", "chalk", "commander",
    "dotenv", "uuid", "jsonwebtoken", "bcrypt", "mongoose", "sequelize",
    "django", "flask", "requests", "numpy", "pandas", "pytest", "setuptools",
})


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def typosquat_risk(name: str, *, popular: frozenset[str] | None = None) -> tuple[bool, str]:
    """Return (is_suspicious, matched_popular_name) for package typosquatting."""
    n = name.lower().strip()
    pool = popular or _POPULAR_PACKAGES
    if n in pool:
        return False, ""
    for pkg in pool:
        if abs(len(n) - len(pkg)) > 2:
            continue
        dist = _levenshtein(n, pkg)
        if 0 < dist <= 2:
            return True, pkg
        if n.replace("-", "").replace("_", "") == pkg.replace("-", ""):
            return True, pkg
    return False, ""


def maintainer_anomaly(*, account_age_days: int | None, publish_count: int | None) -> bool:
    """Heuristic: brand-new maintainer with few publishes may indicate takeover."""
    if account_age_days is None or publish_count is None:
        return False
    return account_age_days < 30 and publish_count <= 2
