"""Secret detection scanner.

Finds committed credentials two ways:

1. **Signatures**, high-precision regexes for well-known token formats (AWS keys,
   GitHub tokens, private keys, Slack tokens, ...). These are reported with high
   confidence because the format itself is distinctive.
2. **High-entropy strings**, generic assignments (``api_key = "..."``) whose
   value looks random. Reported with lower confidence and filtered heavily to
   keep noise down.
"""

from __future__ import annotations

import math
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

# name -> (compiled pattern, severity). Ordered most to least specific.
_SIGNATURES: dict[str, re.Pattern[str]] = {
    "aws-access-key-id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws-secret-access-key": re.compile(
        r"(?i)aws.{0,20}?(secret|sk).{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "github-token": re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    "gitlab-token": re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "stripe-secret-key": re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"),
    "private-key-block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    "generic-bearer": re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}"),
}

# Generic key-ish assignments whose RHS we entropy-check.
_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<key>[A-Za-z0-9_\-\.]*(?:secret|token|passw(?:or)?d|api[_\-]?key|access[_\-]?key|
        private[_\-]?key|client[_\-]?secret|auth)[A-Za-z0-9_\-\.]*)
    \s*[:=]\s*
    ['"](?P<val>[^'"\n]{12,120})['"]
    """
)

# Values that look like placeholders, not real secrets.
_PLACEHOLDER = re.compile(
    r"(?i)^(x{3,}|\*{3,}|<[^>]+>|\$\{[^}]+\}|change[_\- ]?me|your[_\-]|example|"
    r"placeholder|dummy|sample|test|todo|none|null|redacted|\.{3})")

# Files where secrets are expected to be templates or fixtures, so downgrade
# confidence. Anchored with (^|/) so a top-level tests/ or fixtures/ dir matches,
# not just nested ones (a real repo often has tests/certs/*.key test material).
_EXAMPLE_FILE = re.compile(
    r"(?i)(\.example$|\.sample$|\.template$|(^|/)tests?/|(^|/)fixtures?/|"
    r"(^|/)testdata/|\.md$)")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@scanner
class SecretsScanner(Scanner):
    name = "secrets"
    category = "secrets"
    file_local = True
    description = "Detects committed credentials via signatures and entropy analysis."

    # Only scan plausible text/source/config files.
    _SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz",
                      ".jar", ".class", ".woff", ".woff2", ".ttf", ".ico", ".lock"}

    def cacheable(self, ctx: ScannerContext) -> bool:
        # Live verification makes network calls whose result depends on the
        # credential's current state, and history scanning is a repo-level pass,
        # neither fits the per-file content cache, so skip caching for both.
        opts = ctx.config.options_for(self.name)
        return self.file_local and not opts.get("verify") and not opts.get("history")

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        opts = ctx.config.options_for(self.name)
        entropy_threshold = float(opts.get("entropy_threshold", 4.0))
        entropy_enabled = bool(opts.get("entropy", True))
        verify = bool(opts.get("verify", False))
        counter = 0
        if verify:
            import warnings

            warnings.warn(
                "Live secret verification makes outbound network requests that include "
                "detected credential material. Use only on local targets you own.",
                stacklevel=2,
            )

        for f in ctx.project.files():
            if f.suffix in self._SKIP_SUFFIXES or f.is_probably_binary():
                continue
            is_example = bool(_EXAMPLE_FILE.search(f.rel_path))

            for lineno, line in enumerate(f.lines(), start=1):
                if len(line) > 1000:  # skip minified/huge lines
                    continue

                for rule, pattern in _SIGNATURES.items():
                    m = pattern.search(line)
                    if not m:
                        continue
                    counter += 1
                    finding = self._make_finding(
                        rule_id=rule, index=counter, path=f.rel_path, lineno=lineno,
                        line=line, matched=m.group(0),
                        severity=Severity.LOW if is_example else Severity.CRITICAL,
                        confidence=Confidence.LOW if is_example else Confidence.HIGH,
                        title=f"Hardcoded credential: {rule.replace('-', ' ')}",
                    )
                    if verify:
                        self._apply_verification(finding, rule, m.group(0))
                    yield finding

                if not entropy_enabled:
                    continue
                am = _ASSIGNMENT.search(line)
                if am:
                    val = am.group("val")
                    if _PLACEHOLDER.search(val) or " " in val.strip():
                        continue
                    if _shannon_entropy(val) >= entropy_threshold:
                        counter += 1
                        yield self._make_finding(
                            rule_id="high-entropy-string", index=counter,
                            path=f.rel_path, lineno=lineno, line=line, matched=val,
                            severity=Severity.LOW if is_example else Severity.HIGH,
                            confidence=Confidence.LOW if is_example else Confidence.MEDIUM,
                            title=f"Possible hardcoded secret in '{am.group('key')}'",
                        )

        if opts.get("history"):
            yield from self._scan_history(ctx.project.root)

    def _scan_history(self, root) -> Iterable[Finding]:
        """Report secrets found anywhere in git history (including deleted ones)."""
        from argus.scanners import secrets_history

        secrets, truncated = secrets_history.find_history_secrets(root)
        for i, hs in enumerate(secrets, start=1):
            yield self._history_finding(hs, i, truncated)

    def _history_finding(self, hs, index: int, truncated: bool) -> Finding:
        note = (" (history scan was truncated at the size cap; some older commits "
                "were not read)") if truncated else ""
        return Finding(
            id=f"{self.name}:history:{hs.rule}:{index}",
            rule_id=f"{self.name}.history.{hs.rule}",
            scanner=self.name,
            title=f"Secret in git history: {hs.rule.replace('-', ' ')}",
            description=(
                f"A value matching the `{hs.rule}` pattern was committed in git "
                f"history (introduced around commit {hs.commit or 'unknown'}). Even "
                f"if it has been removed from the current files, it remains "
                f"recoverable from history and must be treated as compromised.{note}"
            ),
            location=Location(path=hs.path or "(git history)", snippet=hs.redacted),
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            likelihood=Likelihood.LIKELY,
            cwe=["CWE-798"],
            owasp=["A07:2021-Identification and Authentication Failures"],
            remediation=Remediation(
                summary="Rotate the credential; deleting it from history is not enough.",
                guidance=(
                    "1. Rotate/revoke the credential now, assume it is compromised.\n"
                    "2. Removing it from the latest commit does NOT remove it from "
                    "history; anyone with the repo can recover it.\n"
                    "3. If you must purge it, rewrite history (git-filter-repo) and "
                    "force-push, then have collaborators re-clone.\n"
                    "4. Add a pre-commit secret scan to prevent recurrence."
                ),
                references=["https://cwe.mitre.org/data/definitions/798.html"],
            ),
            tags=["secret", "history", hs.rule],
        )

    def _make_finding(self, *, rule_id: str, index: int, path: str, lineno: int,
                      line: str, matched: str, severity: Severity,
                      confidence: Confidence, title: str) -> Finding:
        redacted = self._redact(matched)
        snippet = line.strip().replace(matched, redacted)
        return Finding(
            id=f"{self.name}:{rule_id}:{index}",
            rule_id=f"{self.name}.{rule_id}",
            scanner=self.name,
            title=title,
            description=(
                f"A value matching the `{rule_id}` pattern was found committed in "
                f"source. Secrets in version control are exposed to everyone with "
                f"repository access and remain in history even after removal."
            ),
            location=Location(path=path, start_line=lineno, snippet=snippet),
            severity=severity,
            confidence=confidence,
            likelihood=Likelihood.LIKELY,
            cwe=["CWE-798"],
            owasp=["A07:2021-Identification and Authentication Failures"],
            remediation=Remediation(
                summary="Remove the secret from source and rotate it.",
                guidance=(
                    "1. Revoke/rotate the exposed credential now, assume it is "
                    "compromised.\n2. Move the value to a secret manager or an "
                    "environment variable loaded at runtime.\n3. Purge it from git "
                    "history (e.g. git-filter-repo) so it is not recoverable.\n"
                    "4. Add a pre-commit secret scan to prevent recurrence."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/798.html",
                    "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                ],
            ),
            tags=["secret", rule_id],
        )

    @staticmethod
    def _apply_verification(finding: Finding, rule_id: str, secret: str) -> None:
        """Live-check a detected secret and reflect the result on the finding.

        A confirmed-live credential is escalated to CRITICAL/almost-certain; a
        provider-rejected one is downgraded (likely a stale or example value).
        The verdict is recorded in metadata; the secret itself is never stored.
        """
        from argus.scanners import secret_verify

        verdict = secret_verify.verify(rule_id, secret)
        finding.metadata["verification"] = verdict
        if verdict == secret_verify.LIVE:
            finding.severity = Severity.CRITICAL
            finding.confidence = Confidence.HIGH
            finding.likelihood = Likelihood.ALMOST_CERTAIN
            finding.title = f"{finding.title}, VERIFIED LIVE"
            finding.description = (
                "VERIFIED LIVE: this credential was confirmed active against the "
                "provider. Rotate it immediately.\n\n" + finding.description
            )
        elif verdict == secret_verify.INVALID:
            finding.severity = Severity(max(Severity.LOW, finding.severity - 1))
            finding.description = (
                "The provider rejected this credential (invalid/expired or an "
                "example value); still remove it from source.\n\n" + finding.description
            )

    @staticmethod
    def _redact(value: str) -> str:
        """Mask a matched secret for reports.

        Reports are often committed or shared, so we reveal only a short leading
        fragment for identification, never the tail, and disclose the length so
        the value is still recognizable without being usable.
        """
        if len(value) <= 6:
            return "****"
        return f"{value[:3]}… [redacted, {len(value)} chars]"
