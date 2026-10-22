"""Cloud configuration patterns (AWS/Azure/GCP via Terraform and CloudFormation)."""

from __future__ import annotations

import bisect
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
from argus.scanners._text import iter_scan_windows, match_columns, snippet_line

_CLOUD_FILES = re.compile(
    r"\.(tf|tfvars|hcl)$|cloudformation\.(ya?ml|json)$|/template\.(ya?ml|json)$",
    re.I,
)


def _is_cloudformation(f) -> bool:
    if f.suffix not in (".yml", ".yaml", ".json", ".template"):
        return False
    head = f.text()[:500]
    return "AWSTemplateFormatVersion" in head or "AWS::CloudFormation" in head


_IAM_ACTION = re.compile(r'Action\s*=\s*"\*"')
_IAM_RESOURCE = re.compile(r'Resource\s*=\s*"\*"')
# How far below an `Action = "*"` line its `Resource = "*"` may appear and still
# count as the same policy statement.
_IAM_STATEMENT_LINES = 20


def _iam_wildcard_lines(lines: list[str]) -> list[tuple[int, tuple[int, int]]]:
    """`Action = "*"` lines followed closely by `Resource = "*"`.

    Each item is the line number and the columns of the `Action` match.
    """
    actions: list[tuple[int, tuple[int, int]]] = []
    resources: list[int] = []
    for lineno, offset, seg in iter_scan_windows(lines):
        m = _IAM_ACTION.search(seg)
        if m and (not actions or actions[-1][0] != lineno):
            actions.append((lineno, match_columns(m, offset)))
        if _IAM_RESOURCE.search(seg) and (not resources or resources[-1] != lineno):
            resources.append(lineno)
    out: list[tuple[int, tuple[int, int]]] = []
    for lineno, cols in actions:
        i = bisect.bisect_left(resources, lineno)
        if i < len(resources) and resources[i] <= lineno + _IAM_STATEMENT_LINES:
            out.append((lineno, cols))
    return out


_RULES: list[tuple[str, str, re.Pattern[str], Severity, str, str]] = [
    (
        "cloud.public-s3-acl",
        "Public S3 ACL or public access block disabled",
        re.compile(
            r'acl\s*=\s*"public-read|public_access_block\s*\{[^}]*block_public_acls\s*=\s*false'
        ),
        Severity.HIGH,
        "Public object storage exposes data to the internet.",
        "Enable block public access and use private ACLs with IAM policies.",
    ),
    (
        "cloud.open-security-group",
        "Security group or firewall open to 0.0.0.0/0",
        re.compile(
            r'0\.0\.0\.0/0|cidr\s*=\s*"0\.0\.0\.0/0"|source_ranges\s*=\s*\["0\.0\.0\.0/0"\]'
        ),
        Severity.HIGH,
        "World-open ingress allows anyone to reach the service.",
        "Restrict to known CIDR ranges or private networks.",
    ),
    (
        "cloud.unencrypted-rds",
        "Database storage encryption disabled",
        re.compile(r"(?i)storage_encrypted\s*=\s*false|encrypt\s*=\s*false"),
        Severity.MEDIUM,
        "Unencrypted databases leak data if snapshots or disks are exposed.",
        "Set storage_encrypted / encrypt = true with KMS keys.",
    ),
    (
        "cloud.iam-wildcard",
        "IAM policy allows Action: * on Resource: *",
        # Matched per line against the Action line; the Resource half is looked
        # up in the following lines by _iam_wildcard_lines (no DOTALL search over
        # the whole file, which was quadratic on hostile input).
        _IAM_ACTION,
        Severity.CRITICAL,
        "Overly broad IAM policies enable full account takeover.",
        "Scope actions and resources to least privilege.",
    ),
    (
        "cloud.azure-public-blob",
        "Azure storage allows public blob access",
        re.compile(r"allow_blob_public_access\s*=\s*true"),
        Severity.HIGH,
        "Anonymous blob access can expose sensitive objects.",
        "Set allow_blob_public_access = false.",
    ),
    (
        "cloud.gcp-public-bucket",
        "GCP bucket IAM allUsers or allAuthenticatedUsers",
        re.compile(r"allUsers|allAuthenticatedUsers"),
        Severity.HIGH,
        "Public bucket IAM bindings expose objects globally.",
        "Remove allUsers bindings; use signed URLs or IAP.",
    ),
]


@scanner
class CloudScanner(Scanner):
    name = "cloud"
    category = "cloud"
    description = "Detects risky AWS/Azure/GCP patterns in Terraform and CloudFormation."

    file_local = True

    def applies_to(self, project) -> bool:
        arch = project.architecture or {}
        if arch.get("cloud") or arch.get("iac"):
            return True
        return any(
            _CLOUD_FILES.search(f.rel_path) or _is_cloudformation(f) for f in project.files()
        )

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if not (_CLOUD_FILES.search(f.rel_path) or _is_cloudformation(f)):
                continue
            lines = f.lines()
            for rule_id, title, pattern, severity, why, fix in _RULES:
                if rule_id == "cloud.iam-wildcard":
                    for lineno, cols in _iam_wildcard_lines(lines):
                        counter += 1
                        yield self._mk(
                            f.rel_path,
                            rule_id,
                            title,
                            severity,
                            why,
                            fix,
                            lineno,
                            lines[lineno - 1][:2000],
                            counter,
                            cols,
                        )
                    continue
                reported: set[int] = set()
                for lineno, offset, line in iter_scan_windows(lines):
                    if lineno in reported:
                        continue
                    m = pattern.search(line)
                    if m:
                        reported.add(lineno)
                        counter += 1
                        yield self._mk(
                            f.rel_path,
                            rule_id,
                            title,
                            severity,
                            why,
                            fix,
                            lineno,
                            line,
                            counter,
                            match_columns(m, offset),
                        )

    @staticmethod
    def _mk(path, rule, title, severity, why, fix, lineno, line, counter, cols) -> Finding:
        snippet = snippet_line(line, 200) if isinstance(line, str) else "(policy block)"
        return Finding(
            id=f"cloud:{rule}:{counter}",
            rule_id=rule,
            scanner="cloud",
            title=title,
            description=why,
            location=Location(
                path=path,
                start_line=lineno,
                end_line=lineno,
                start_column=cols[0],
                end_column=cols[1],
                snippet=snippet,
            ),
            severity=severity,
            confidence=Confidence.MEDIUM,
            likelihood=Likelihood.POSSIBLE,
            cwe=["CWE-284"],
            owasp=["A05:2021-Security Misconfiguration"],
            why_vulnerable=why,
            remediation=Remediation(summary=fix, guidance=fix),
            tags=["cloud"],
        )
