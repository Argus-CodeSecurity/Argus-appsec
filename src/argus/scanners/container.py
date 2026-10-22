"""Container and compose security (extends Dockerfile checks in the IaC scanner)."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from argus.core.plugin import Scanner, ScannerContext, scanner
from argus.scanners._text import MAX_SCAN_LINE, iter_scan_windows, match_columns
from argus.scanners.secrets import redact_line

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
_CAP_ADD_KEY = re.compile(r"(?i)^\s*cap_add:[ \t]*(?P<inline>\[[^\]]*\][ \t]*)?(?:#.*)?$")
_CAP_ITEM = re.compile(r"^\s*-\s*['\"]?(?P<cap>[\w-]+)")
_DOCKERFILE_ENV_SECRET = re.compile(
    r"(?im)^\s*ENV\s+.*(PASSWORD|SECRET|TOKEN|API_KEY)\s*=",
)


def _sys_admin_cap_lines(lines: list[str]) -> list[int]:
    """Line numbers of `cap_add:` entries that grant SYS_ADMIN (block or flow list).

    Walks the lines instead of running one multi-line regex over the file, whose
    nested whitespace quantifiers backtracked badly on hostile input.
    """
    out: list[int] = []
    for idx, line in enumerate(lines):
        if len(line) > MAX_SCAN_LINE:
            continue
        m = _CAP_ADD_KEY.match(line)
        if not m:
            continue
        if m.group("inline"):
            if "SYS_ADMIN" in m.group("inline").upper():
                out.append(idx + 1)
            continue
        for item in lines[idx + 1 : idx + 50]:
            if not item.strip() or item.lstrip().startswith("#"):
                continue
            im = _CAP_ITEM.match(item[:MAX_SCAN_LINE])
            if not im:
                break  # end of the list
            if im.group("cap").upper() in ("SYS_ADMIN", "CAP_SYS_ADMIN"):
                out.append(idx + 1)
                break
    return out


def _line_matches(
    pattern: re.Pattern[str], lines: list[str]
) -> Iterator[tuple[int, str, tuple[int, int]]]:
    """``(lineno, segment, columns)`` of the first match of ``pattern`` on each line."""
    done: set[int] = set()
    for lineno, offset, seg in iter_scan_windows(lines):
        if lineno in done:
            continue
        m = pattern.search(seg)
        if m:
            done.add(lineno)
            yield lineno, seg, match_columns(m, offset)


def _key_columns(line: str, key: str) -> tuple[int, int]:
    """Columns of a YAML ``key`` that starts the line after its indentation."""
    start = len(line) - len(line.lstrip()) + 1
    return start, start + len(key)


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
        lines = f.lines()
        checks = [
            (
                _PRIVILEGED,
                "container.privileged",
                Severity.HIGH,
                "Privileged compose service",
                "Remove privileged: true.",
            ),
            (
                _HOST_NETWORK,
                "container.host-network",
                Severity.HIGH,
                "Compose service uses host network",
                "Use bridge networks.",
            ),
            (
                _IMAGE_LATEST,
                "container.image-latest",
                Severity.LOW,
                "Compose image uses :latest tag",
                "Pin image digest or version.",
            ),
            (
                _SECRET_ENV,
                "container.env-secret",
                Severity.CRITICAL,
                "Secret-like value in compose environment",
                "Use secrets/files, not plain env.",
            ),
        ]
        for lineno in _sys_admin_cap_lines(lines):
            yield self._finding(
                f.rel_path,
                "container.cap-sys-admin",
                "CAP_SYS_ADMIN in compose",
                Severity.HIGH,
                "Avoid granting SYS_ADMIN in compose services.",
                lineno,
                "cap_add: SYS_ADMIN",
                0,
                _key_columns(lines[lineno - 1], "cap_add:"),
            )
        for pattern, rule, sev, title, fix in checks:
            for lineno, seg, cols in _line_matches(pattern, lines):
                yield self._finding(f.rel_path, rule, title, sev, fix, lineno, seg, 0, cols)

    def _iter_k8s(self, f) -> Iterable[Finding]:
        for lineno, line in enumerate(f.lines(), start=1):
            if len(line) > MAX_SCAN_LINE:
                continue  # an image reference is never this long
            m = _IMAGE_LATEST.search(line)
            nd = None if m else _IMAGE_NO_DIGEST.search(line)
            if m:
                yield self._finding(
                    f.rel_path,
                    "container.k8s-image-latest",
                    "Kubernetes workload uses :latest image tag",
                    Severity.MEDIUM,
                    "Pin container images to a digest or immutable version tag.",
                    lineno,
                    line,
                    0,
                    match_columns(m),
                )
            elif nd and "@" not in line:
                yield self._finding(
                    f.rel_path,
                    "container.k8s-image-no-digest",
                    "Kubernetes image reference has no digest",
                    Severity.LOW,
                    "Prefer image@sha256:... for immutable deploys.",
                    lineno,
                    line,
                    0,
                    match_columns(nd),
                )

    def _iter_helm_values(self, f) -> Iterable[Finding]:
        for lineno, seg, cols in _line_matches(_SECRET_ENV, f.lines()):
            yield self._finding(
                f.rel_path,
                "container.helm-values-secret",
                "Secret-like value in Helm values",
                Severity.HIGH,
                "Use Kubernetes secrets or external secret stores, not plain values.",
                lineno,
                seg,
                0,
                cols,
            )

    def _iter_dockerfile_extra(self, f) -> Iterable[Finding]:
        for lineno, seg, cols in _line_matches(_DOCKERFILE_ENV_SECRET, f.lines()):
            yield self._finding(
                f.rel_path,
                "container.dockerfile-env-secret",
                "Secret-like ENV in Dockerfile",
                Severity.HIGH,
                "Use runtime secrets or build-args from CI, not committed ENV.",
                lineno,
                seg,
                0,
                cols,
            )

    @staticmethod
    def _finding(path, rule, title, severity, fix, lineno, line, counter, cols) -> Finding:
        return Finding(
            id=f"container:{rule}:{counter}",
            rule_id=rule,
            scanner="container",
            title=title,
            description=fix,
            location=Location(
                path=path,
                start_line=lineno,
                end_line=lineno,
                start_column=cols[0],
                end_column=cols[1],
                snippet=redact_line(line).rstrip("\r\n")[:200],
            ),
            severity=severity,
            confidence=Confidence.MEDIUM,
            likelihood=Likelihood.POSSIBLE,
            cwe=["CWE-250", "CWE-798"],
            owasp=["A05:2021-Security Misconfiguration"],
            why_vulnerable=fix,
            remediation=Remediation(summary=fix, guidance=fix),
            tags=["container"],
        )
