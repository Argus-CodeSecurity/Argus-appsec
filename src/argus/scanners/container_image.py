"""Container image layer analysis via local Docker CLI (spec §19)."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable

from argus.core.models import Confidence, Finding, Likelihood, Location, Remediation, Severity
from argus.core.plugin import Scanner, ScannerContext, scanner


def _inspect_image(ref: str) -> dict | None:
    try:
        out = subprocess.check_output(
            ["docker", "inspect", ref],
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
    description = "Inspect local OCI/Docker images for root user, privileged mode, and exposed ports."

    def applies_to(self, project) -> bool:
        opts = project.root  # always optional via config
        return True

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        refs = ctx.config.options_for("container-image").get("images") or []
        if isinstance(refs, str):
            refs = [r.strip() for r in refs.split(",") if r.strip()]
        if not refs:
            for f in ctx.project.files():
                if f.name == "Dockerfile":
                    for line in f.text().splitlines():
                        if line.strip().upper().startswith("FROM "):
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                refs.append(parts[1].strip("\"'"))
                    break
        if not refs:
            return

        for ref in refs[:5]:
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
                    remediation=Remediation(summary="Add a non-root USER directive in the Dockerfile."),
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
                    remediation=Remediation(summary="Drop privileged mode unless strictly required."),
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
