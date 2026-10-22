"""Container image layer analysis via local Docker CLI (spec §19)."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Iterable

from argus.core.models import Confidence, Finding, Likelihood, Location, Remediation, Severity
from argus.core.plugin import Scanner, ScannerContext, scanner

# Image references read from Dockerfiles in the scanned repository (or given in
# options). Must start with an alphanumeric character, so a value can never be
# read by the docker CLI as an option.
_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
_MAX_IMAGES = 10


def _from_refs(text: str) -> list[str]:
    """Base image references named by the FROM lines of a Dockerfile.

    Skips flags such as ``--platform=...``, ``scratch``, earlier build stages
    (``FROM builder``) and references built from ARG values (``$BASE``), which
    are not images that can be inspected as written.
    """
    refs: list[str] = []
    stages: set[str] = set()
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) < 2 or parts[0].upper() != "FROM":
            continue
        args = [p for p in parts[1:] if not p.startswith("--")]
        if not args:
            continue
        ref = args[0].strip("\"'")
        if len(args) >= 3 and args[1].upper() == "AS":
            stages.add(args[2].lower())
        if ref.lower() == "scratch" or ref.lower() in stages or "$" in ref:
            continue
        refs.append(ref)
    return refs


def _is_dockerfile(name: str) -> bool:
    return (
        name in ("Dockerfile", "Containerfile")
        or name.startswith("Dockerfile.")
        or name.endswith(".Dockerfile")
    )


def _inspect_image(ref: str) -> dict | None:
    if not _IMAGE_REF.match(ref):
        return None
    try:
        out = subprocess.check_output(
            ["docker", "inspect", "--", ref],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
        data = json.loads(out)
        return data[0] if data else None
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
        return None


@scanner
class ContainerImageScanner(Scanner):
    name = "container-image"
    category = "container"
    description = (
        "Inspect local OCI/Docker images for root user, privileged mode, and exposed ports."
    )

    def applies_to(self, project) -> bool:
        return True

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        option = ctx.config.options_for("container-image").get("images") or []
        if isinstance(option, str):
            refs = [r.strip() for r in option.split(",") if r.strip()]
        else:
            refs = [str(r).strip() for r in option]  # copy: never mutate config
        if not refs:
            # Every Dockerfile, not just the first one found.
            for f in ctx.project.files():
                if _is_dockerfile(f.name):
                    refs.extend(_from_refs(f.text()))
        refs = [r for r in dict.fromkeys(refs) if _IMAGE_REF.match(r)]
        if not refs:
            return

        for ref in refs[:_MAX_IMAGES]:
            info = _inspect_image(ref)
            if not info:
                continue
            cfg = info.get("Config") or {}
            user = (cfg.get("User") or "").strip()
            if not user or user in ("0", "root"):
                yield Finding(
                    id=f"container-image:root:{ref}",
                    rule_id="container-image.root-user",
                    scanner="container-image",
                    title=f"Image {ref} runs as root",
                    description="Container default user is root, increasing escape impact.",
                    location=Location(path=ref, snippet=f"User={user or '0'}"),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    likelihood=Likelihood.POSSIBLE,
                    why_vulnerable="Root in containers expands privilege escalation blast radius.",
                    remediation=Remediation(
                        summary="Add a non-root USER directive in the Dockerfile."
                    ),
                    tags=["container", "image"],
                    metadata={"verification": "confirmed"},
                )
            if info.get("HostConfig", {}).get("Privileged"):
                yield Finding(
                    id=f"container-image:privileged:{ref}",
                    rule_id="container-image.privileged",
                    scanner="container-image",
                    title=f"Image/container {ref} is privileged",
                    description="Privileged containers have full host capabilities.",
                    location=Location(path=ref, snippet="Privileged=true"),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    likelihood=Likelihood.LIKELY,
                    remediation=Remediation(
                        summary="Drop privileged mode unless strictly required."
                    ),
                    tags=["container", "image"],
                    metadata={"verification": "confirmed"},
                )
            exposed = cfg.get("ExposedPorts") or {}
            for port in list(exposed.keys())[:10]:
                yield Finding(
                    id=f"container-image:port:{ref}:{port}",
                    rule_id="container-image.exposed-port",
                    scanner="container-image",
                    title=f"Image {ref} exposes port {port}",
                    description="Declared exposed port may be unintentionally published.",
                    location=Location(path=ref, snippet=port),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    likelihood=Likelihood.POSSIBLE,
                    remediation=Remediation(summary="Expose only required ports at runtime."),
                    tags=["container", "image"],
                    metadata={"verification": "detected"},
                )
