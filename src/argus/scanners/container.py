"""Container and compose security (extends Dockerfile checks in the IaC scanner)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from argus.core.plugin import Scanner, ScannerContext, scanner

_COMPOSE = re.compile(r"(?i)docker-compose\.(ya?ml)$|compose\.ya?ml$")
_HELM_VALUES = re.compile(r"(?i)(^|/)values\.ya?ml$|(^|/)helm/.+\.ya?ml$")
_SECRET_ENV = re.compile(
    r"(?i)(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*[=:]\s*[^\s${}]+",
)
_IMAGE_LATEST = re.compile(r"(?i)image:\s*['\"]?[\w./-]+:latest['\"]?\s*$")
_IMAGE_NO_DIGEST = re.compile(
    r"(?i)image:\s*['\"]?[\w./-]+:[\w.-]+['\"]?\s*$",
)
_PRIVILEGED = re.compile(r"(?i)privileged:\s*true")
_HOST_NETWORK = re.compile(r"(?i)network_mode:\s*['\"]?host['\"]?")
_CAP_ADD = re.compile(r"(?i)cap_add:\s*\n(?:\s*-\s*\S+\n)*\s*-\s*SYS_ADMIN")
_DOCKERFILE_ENV_SECRET = re.compile(
    r"(?im)^\s*ENV\s+.*(PASSWORD|SECRET|TOKEN|API_KEY)\s*=",
)


def _is_k8s_manifest(f) -> bool:
    if f.suffix not in (".yml", ".yaml"):
        return False
    head = f.text()[:400]
    return "apiVersion:" in head and "kind:" in head


@scanner
class ContainerScanner(Scanner):
    name = "container"
    category = "container"
    description = "Docker Compose, Kubernetes manifests, Helm values, and container runtime misconfigurations."

    file_local = True

    def applies_to(self, project) -> bool:
        return bool(
            project.files_matching("docker-compose.yml", "docker-compose.yaml", "compose.yaml")
            or [f for f in project.files() if f.name.startswith("Dockerfile")]
            or [f for f in project.files() if _is_k8s_manifest(f)]
            or [f for f in project.files() if _HELM_VALUES.search(f.rel_path)]
        )

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if _COMPOSE.search(f.rel_path):
                for finding in self._iter_compose(f):
                    counter += 1
                    finding.id = f"container:{finding.rule_id}:{counter}"
                    yield finding
            elif f.name.startswith("Dockerfile") or f.name == "Containerfile":
                for finding in self._iter_dockerfile_extra(f):
                    counter += 1
                    finding.id = f"container:{finding.rule_id}:{counter}"
                    yield finding
            elif _is_k8s_manifest(f):
                for finding in self._iter_k8s(f):
                    counter += 1
                    finding.id = f"container:{finding.rule_id}:{counter}"
                    yield finding
            elif _HELM_VALUES.search(f.rel_path):
                for finding in self._iter_helm_values(f):
                    counter += 1
                    finding.id = f"container:{finding.rule_id}:{counter}"
                    yield finding

    def _iter_compose(self, f) -> Iterable[Finding]:
        text = f.text()
        lines = f.lines()
        checks = [
            (_PRIVILEGED, "container.privileged", Severity.HIGH,
             "Privileged compose service", "Remove privileged: true."),
            (_HOST_NETWORK, "container.host-network", Severity.HIGH,
             "Compose service uses host network", "Use bridge networks."),
            (_IMAGE_LATEST, "container.image-latest", Severity.LOW,
             "Compose image uses :latest tag", "Pin image digest or version."),
            (_SECRET_ENV, "container.env-secret", Severity.CRITICAL,
             "Secret-like value in compose environment", "Use secrets/files, not plain env."),
        ]
        if _CAP_ADD.search(text):
            yield self._finding(
                f.rel_path, "container.cap-sys-admin", "CAP_SYS_ADMIN in compose",
                Severity.HIGH, "Avoid granting SYS_ADMIN in compose services.",
                1, "cap_add: SYS_ADMIN", 0,
            )
        for pattern, rule, sev, title, fix in checks:
            for lineno, line in enumerate(lines, start=1):
                if pattern.search(line):
                    yield self._finding(f.rel_path, rule, title, sev, fix, lineno, line, 0)

    def _iter_k8s(self, f) -> Iterable[Finding]:
        for lineno, line in enumerate(f.lines(), start=1):
            if _IMAGE_LATEST.search(line):
                yield self._finding(
                    f.rel_path, "container.k8s-image-latest",
                    "Kubernetes workload uses :latest image tag", Severity.MEDIUM,
                    "Pin container images to a digest or immutable version tag.",
                    lineno, line, 0,
                )
            elif _IMAGE_NO_DIGEST.search(line) and "@" not in line:
                yield self._finding(
                    f.rel_path, "container.k8s-image-no-digest",
                    "Kubernetes image reference has no digest", Severity.LOW,
                    "Prefer image@sha256:... for immutable deploys.",
                    lineno, line, 0,
                )

    def _iter_helm_values(self, f) -> Iterable[Finding]:
        for lineno, line in enumerate(f.lines(), start=1):
            if _SECRET_ENV.search(line):
                yield self._finding(
                    f.rel_path, "container.helm-values-secret",
                    "Secret-like value in Helm values", Severity.HIGH,
                    "Use Kubernetes secrets or external secret stores, not plain values.",
                    lineno, line, 0,
                )

    def _iter_dockerfile_extra(self, f) -> Iterable[Finding]:
        for lineno, line in enumerate(f.lines(), start=1):
            if _DOCKERFILE_ENV_SECRET.search(line):
                yield self._finding(
                    f.rel_path, "container.dockerfile-env-secret",
                    "Secret-like ENV in Dockerfile", Severity.HIGH,
                    "Use runtime secrets or build-args from CI, not committed ENV.",
                    lineno, line, 0,
                )

    @staticmethod
    def _finding(path, rule, title, severity, fix, lineno, line, counter) -> Finding:
        return Finding(
            id=f"container:{rule}:{counter}",
            rule_id=rule,
            scanner="container",
            title=title,
            description=fix,
            location=Location(path=path, start_line=lineno, snippet=line.strip()[:200]),
            severity=severity,
            confidence=Confidence.MEDIUM,
            likelihood=Likelihood.POSSIBLE,
            cwe=["CWE-250", "CWE-798"],
            owasp=["A05:2021-Security Misconfiguration"],
            why_vulnerable=fix,
            remediation=Remediation(summary=fix, guidance=fix),
            tags=["container"],
        )
