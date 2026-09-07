"""Opt-in isolated metadata fetch for supply-chain behavioral checks.

Full package installation never runs on the host. When Docker is available and
``sandbox: docker`` is configured, npm registry queries run inside a throwaway
``node:slim`` container with no network except registry access (no install).

Without Docker, falls back to host-side ``npm view``-equivalent (httpx registry API)
which is already used by :mod:`argus.supply_chain.behavior`.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass

log = logging.getLogger("argus.supply_chain.sandbox")

_NPM_NAME = re.compile(r"^[a-zA-Z0-9._@/-]+$")
_NPM_VERSION = re.compile(r"^[a-zA-Z0-9._@^~>=<+-]+$")


@dataclass
class SandboxResult:
    ok: bool
    mode: str
    package: str
    version: str
    manifest: dict | None = None
    error: str = ""


def _validate_npm(package: str, version: str) -> None:
    if not package or not _NPM_NAME.match(package):
        raise ValueError(f"invalid npm package name: {package!r}")
    if not version or not _NPM_VERSION.match(version):
        raise ValueError(f"invalid npm version spec: {version!r}")


def docker_available() -> bool:
    return shutil.which("docker") is not None


def fetch_npm_manifest(
    package: str,
    version: str,
    *,
    mode: str = "auto",
    timeout: float = 30.0,
) -> SandboxResult:
    """Fetch npm package manifest for one version using the requested isolation mode.

    Modes:
    * ``auto`` — Docker if available, else host registry API
    * ``docker`` — require Docker (fail if unavailable)
    * ``host`` — registry API on host (no container)
    """
    try:
        _validate_npm(package, version)
    except ValueError as exc:
        return SandboxResult(
            ok=False, mode=mode, package=package, version=version, error=str(exc),
        )
    mode = mode.lower()
    if mode in ("auto", "docker") and docker_available():
        return _docker_npm_view(package, version, timeout=timeout)
    if mode == "docker":
        return SandboxResult(
            ok=False, mode="docker", package=package, version=version,
            error="Docker is not available on PATH.",
        )
    from argus.supply_chain.behavior import npm_fingerprint
    fp = npm_fingerprint(package, version, timeout=timeout)
    if fp is None:
        return SandboxResult(
            ok=False, mode="host", package=package, version=version,
            error="Registry lookup failed.",
        )
    manifest = {
        "scripts": {h: "present" for h in fp.install_scripts},
        "bin": fp.bins,
        "dependency_count": fp.dependency_count,
        "suspicious_script": fp.suspicious_script,
    }
    return SandboxResult(ok=True, mode="host", package=package, version=version, manifest=manifest)


_DOCKER_NPM_SCRIPT = (
    "const {execFileSync}=require('child_process');"
    "const p=process.env.ARGUS_PKG;"
    "const v=process.env.ARGUS_VER;"
    "process.stdout.write("
    "execFileSync('npm',['view',`${p}@${v}`,'--json'],"
    "{encoding:'utf8',maxBuffer:10*1024*1024}));"
)


def _docker_npm_view(package: str, version: str, *, timeout: float) -> SandboxResult:
    """Run ``npm view pkg@ver --json`` inside an isolated container (no install)."""
    cmd = [
        "docker", "run", "--rm",
        "--network", "bridge",
        "--read-only",
        "--cap-drop=ALL",
        "--pids-limit=64",
        "--memory=256m",
        "--user", "node",
        "-e", f"ARGUS_PKG={package}",
        "-e", f"ARGUS_VER={version}",
        "node:22-slim",
        "node", "-e", _DOCKER_NPM_SCRIPT,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return SandboxResult(
            ok=False, mode="docker", package=package, version=version, error=str(exc),
        )
    if proc.returncode != 0:
        return SandboxResult(
            ok=False, mode="docker", package=package, version=version,
            error=(proc.stderr or proc.stdout or "docker npm view failed").strip()[:500],
        )
    try:
        manifest = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return SandboxResult(
            ok=False, mode="docker", package=package, version=version,
            error="Invalid JSON from npm view.",
        )
    return SandboxResult(
        ok=True, mode="docker", package=package, version=version, manifest=manifest,
    )
