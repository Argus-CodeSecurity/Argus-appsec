"""Opt-in container isolation for supply-chain behavioral metadata fetches.

Packages are never installed and their scripts never run, in any mode. What
the sandbox changes is where the registry query runs:

* ``host``: the npm registry JSON API is queried from the Argus process with
  httpx (:func:`argus.supply_chain.behavior.npm_fingerprint`).
* ``docker``: ``npm view <pkg>@<version> --json`` runs in a throwaway container
  from a digest-pinned ``node`` image, as the unprivileged ``node`` user, with a
  read-only root filesystem, all capabilities dropped and pid/memory limits.
  The container uses Docker's default bridge network, so it has ordinary
  outbound network access (it needs it to reach the registry); the isolation
  is from the host filesystem and privileges, not from the network.
* ``auto``: ``docker`` when the Docker CLI is available, else ``host``.

The mode comes from the ``sandbox`` option of the ``dependency-diff`` scanner,
which the ``argus supply-chain --sandbox`` flag sets.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass

from argus.supply_chain.behavior import (
    BehaviorFingerprint,
    fingerprint_from_manifest,
    npm_fingerprint,
)

log = logging.getLogger("argus.supply_chain.sandbox")

# Names and versions come from lockfiles in the scanned repository. Both must
# start with a character that cannot begin a command-line option.
_NPM_NAME = re.compile(r"^(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$")
_NPM_VERSION = re.compile(r"^[A-Za-z0-9^~<>=][A-Za-z0-9._^~<>=+-]*$")

# node:22-slim, pinned by digest (multi-arch index) so a retagged image cannot
# change what runs. Update the digest deliberately when moving to a newer image.
_NODE_IMAGE = "node:22-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d"

MODES = ("auto", "host", "docker")


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

    See the module docstring for what each mode does. ``docker`` fails when the
    Docker CLI is not available rather than silently falling back to the host.
    """
    try:
        _validate_npm(package, version)
    except ValueError as exc:
        return SandboxResult(
            ok=False,
            mode=mode,
            package=package,
            version=version,
            error=str(exc),
        )
    mode = mode.lower()
    if mode not in MODES:
        return SandboxResult(
            ok=False,
            mode=mode,
            package=package,
            version=version,
            error=f"unknown sandbox mode {mode!r} (expected one of {', '.join(MODES)})",
        )
    if mode in ("auto", "docker") and docker_available():
        return _docker_npm_view(package, version, timeout=timeout)
    if mode == "docker":
        return SandboxResult(
            ok=False,
            mode="docker",
            package=package,
            version=version,
            error="Docker is not available on PATH.",
        )
    fp = npm_fingerprint(package, version, timeout=timeout)
    if fp is None:
        return SandboxResult(
            ok=False,
            mode="host",
            package=package,
            version=version,
            error="Registry lookup failed.",
        )
    manifest = {
        "scripts": {h: "present" for h in fp.install_scripts},
        "bin": fp.bins,
        "dependency_count": fp.dependency_count,
        "suspicious_script": fp.suspicious_script,
    }
    return SandboxResult(ok=True, mode="host", package=package, version=version, manifest=manifest)


def fetch_fingerprint(
    package: str, version: str, *, mode: str = "host", timeout: float = 30.0
) -> BehaviorFingerprint | None:
    """Behavioral fingerprint of one npm package version in the given mode.

    Returns None when the name or version is rejected, the lookup fails, or
    ``docker`` was requested without Docker (logged as a warning).
    """
    try:
        _validate_npm(package, version)
    except ValueError as exc:
        log.debug("skipping behavioral fetch: %s", exc)
        return None
    mode = (mode or "host").lower()
    if mode == "host" or (mode == "auto" and not docker_available()):
        return npm_fingerprint(package, version, timeout=timeout)
    result = fetch_npm_manifest(package, version, mode=mode, timeout=timeout)
    if not result.ok or result.manifest is None:
        log.warning(
            "sandboxed npm metadata fetch for %s@%s failed: %s", package, version, result.error
        )
        return None
    return fingerprint_from_manifest(package, version, result.manifest)


_DOCKER_NPM_SCRIPT = (
    "const {execFileSync}=require('child_process');"
    "const p=process.env.ARGUS_PKG;"
    "const v=process.env.ARGUS_VER;"
    # `--` ends npm's option parsing, so the spec is only ever a package spec.
    "process.stdout.write("
    "execFileSync('npm',['view','--json','--',`${p}@${v}`],"
    "{encoding:'utf8',maxBuffer:10*1024*1024}));"
)


def _docker_npm_view(package: str, version: str, *, timeout: float) -> SandboxResult:
    """Run ``npm view pkg@ver --json`` inside an isolated container (no install)."""
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "bridge",
        "--read-only",
        # npm needs a writable cache directory even for `view`.
        "--tmpfs",
        "/tmp:rw,size=64m",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit=64",
        "--memory=256m",
        "--user",
        "node",
        "-e",
        "npm_config_cache=/tmp/.npm",
        "-e",
        "npm_config_update_notifier=false",
        "-e",
        f"ARGUS_PKG={package}",
        "-e",
        f"ARGUS_VER={version}",
        _NODE_IMAGE,
        "node",
        "-e",
        _DOCKER_NPM_SCRIPT,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return SandboxResult(
            ok=False,
            mode="docker",
            package=package,
            version=version,
            error=str(exc),
        )
    if proc.returncode != 0:
        return SandboxResult(
            ok=False,
            mode="docker",
            package=package,
            version=version,
            error=(proc.stderr or proc.stdout or "docker npm view failed").strip()[:500],
        )
    try:
        manifest = json.loads(proc.stdout)
    except (json.JSONDecodeError, RecursionError):
        return SandboxResult(
            ok=False,
            mode="docker",
            package=package,
            version=version,
            error="Invalid JSON from npm view.",
        )
    # A version range can match several versions: npm then returns a list.
    if isinstance(manifest, list):
        manifest = next((m for m in reversed(manifest) if isinstance(m, dict)), None)
    if not isinstance(manifest, dict):
        return SandboxResult(
            ok=False,
            mode="docker",
            package=package,
            version=version,
            error="Unexpected npm view output.",
        )
    return SandboxResult(
        ok=True,
        mode="docker",
        package=package,
        version=version,
        manifest=manifest,
    )
