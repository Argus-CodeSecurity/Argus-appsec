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

import logging
import math
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
from argus.scanners._text import iter_scan_lines

log = logging.getLogger("argus.scanners.secrets")

# name -> compiled pattern. Ordered most to least specific. A `val` group, when
# present, marks the secret part of the match (what redact_line masks).
_SIGNATURES: dict[str, re.Pattern[str]] = {
    "aws-access-key-id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws-secret-access-key": re.compile(
        r"(?i)aws.{0,20}?(secret|sk).{0,20}?['\"](?P<val>[0-9a-zA-Z/+]{40})['\"]"),
    "github-token": re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    "gitlab-token": re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "stripe-secret-key": re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"),
    "private-key-block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    "generic-bearer": re.compile(r"(?i)bearer\s+(?P<val>[A-Za-z0-9_\-\.=]{20,})"),
}

# Generic key-ish assignments whose RHS we entropy-check. The key must start at a
# name boundary and is bounded, and whether it names a secret is checked
# separately (_SECRET_KEY_NAME): the old single pattern put two unbounded name
# classes around an alternation they could also match, which made a failed
# search cubic in the line length.
_ASSIGNMENT = re.compile(
    r"""(?x)
    (?<![A-Za-z0-9_\-\.])(?P<key>[A-Za-z0-9_\-\.]{1,80})
    \s*[:=]\s*
    ['"](?P<val>[^'"\n]{12,120})['"]
    """
)
_SECRET_KEY_NAME = re.compile(
    r"(?i)secret|token|passw(?:or)?d|api[_\-]?key|access[_\-]?key|"
    r"private[_\-]?key|client[_\-]?secret|auth")


def _secret_assignments(line: str) -> Iterator[re.Match[str]]:
    """Assignments on ``line`` whose key name looks like it holds a secret."""
    for m in _ASSIGNMENT.finditer(line):
        if _SECRET_KEY_NAME.search(m.group("key")):
            yield m


# Any `key = value` / `key: value` pair, quoted or bare, for redaction only. It is
# deliberately broader than _ASSIGNMENT (no length or entropy floor): masking a
# value that was not a secret costs nothing, leaving one in clear does.
_REDACT_PAIR = re.compile(
    r"""(?<![A-Za-z0-9_\-\.])(?P<key>[A-Za-z0-9_\-\.]{1,80})['"]?\s*[:=]\s*"""
    r"""(?:"(?P<dq>[^"\n]{1,500})"|'(?P<sq>[^'\n]{1,500})'|(?P<bare>[^\s'",;]{1,500}))"""
)


def _secret_span(m: re.Match[str]) -> tuple[int, int]:
    """The part of a signature match that is the secret itself."""
    if "val" in m.re.groupindex and m.group("val") is not None:
        return m.span("val")
    return m.span()


def redact_line(line: str) -> str:
    """Return ``line`` with every secret-looking value masked.

    Applies every signature (all matches, not just the first) and masks the
    value of any pair whose key names a secret. Used for the snippet of every
    secret-type finding, since snippets end up in SARIF uploads and PR comments
    that are public on fork pull requests. Pass the full line (at most
    MAX_SCAN_LINE characters) and truncate afterwards, never before: a token cut
    in half no longer matches its signature and would leak partially.
    """
    spans: list[tuple[int, int]] = []
    for pattern in _SIGNATURES.values():
        spans.extend(_secret_span(m) for m in pattern.finditer(line))
    for m in _REDACT_PAIR.finditer(line):
        if not _SECRET_KEY_NAME.search(m.group("key")):
            continue
        group = next(g for g in ("dq", "sq", "bare") if m.group(g) is not None)
        spans.append(m.span(group))
    spans.extend(m.span("val") for m in _secret_assignments(line))
    if not spans:
        return line
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    out: list[str] = []
    pos = 0
    for start, end in merged:
        out.append(line[pos:start])
        out.append(SecretsScanner._redact(line[start:end]))
        pos = end
    out.append(line[pos:])
    return "".join(out)


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

            # Over-long (minified) lines are windowed, not skipped, so padding a
            # line cannot hide a key and no single search sees unbounded text.
            # Every match is reported, not just the first per rule and line, and a
            # value seen in two overlapping windows of a long line only once.
            seen: set[tuple[str, int, str]] = set()
            for lineno, line in iter_scan_lines(f.lines()):
                for rule, pattern in _SIGNATURES.items():
                    for m in pattern.finditer(line):
                        key = (rule, lineno, m.group(0))
                        if key in seen:
                            continue
                        seen.add(key)
                        counter += 1
                        finding = self._make_finding(
                            rule_id=rule, index=counter, path=f.rel_path, lineno=lineno,
                            line=line,
                            severity=Severity.LOW if is_example else Severity.CRITICAL,
                            confidence=Confidence.LOW if is_example else Confidence.HIGH,
                            title=f"Hardcoded credential: {rule.replace('-', ' ')}",
                        )
                        if verify:
                            self._apply_verification(finding, rule, m.group(0))
                        yield finding

                if not entropy_enabled:
                    continue
                for am in _secret_assignments(line):
                    val = am.group("val")
                    if _PLACEHOLDER.search(val) or " " in val.strip():
                        continue
                    key = ("high-entropy-string", lineno, val)
                    if key in seen:
                        continue
                    seen.add(key)
                    if _shannon_entropy(val) >= entropy_threshold:
                        counter += 1
                        yield self._make_finding(
                            rule_id="high-entropy-string", index=counter,
                            path=f.rel_path, lineno=lineno, line=line,
                            severity=Severity.LOW if is_example else Severity.HIGH,
                            confidence=Confidence.LOW if is_example else Confidence.MEDIUM,
                            title=f"Possible hardcoded secret in '{am.group('key')}'",
                        )

        if opts.get("history"):
            # The history pass runs git and parses its output. If it fails, the
            # working-tree findings already produced must survive: an exception
            # escaping this generator makes the engine drop all of them.
            try:
                history = list(self._scan_history(ctx.project.root))
            except Exception as exc:
                log.warning("secrets: git history scan failed (%s); reporting "
                            "working-tree findings only", type(exc).__name__)
                history = [self._history_failed_finding(exc)]
            yield from history

    def _scan_history(self, root) -> Iterable[Finding]:
        """Report secrets found anywhere in git history (including deleted ones)."""
        from argus.scanners import secrets_history

        secrets, truncated = secrets_history.find_history_secrets(root)
        for i, hs in enumerate(secrets, start=1):
            yield self._history_finding(hs, i, truncated)

    def _history_failed_finding(self, exc: BaseException) -> Finding:
        """An INFO note that the history pass did not complete."""
        return Finding(
            id=f"{self.name}:history-failed:1",
            rule_id=f"{self.name}.history-scan-failed",
            scanner=self.name,
            title="Git history secret scan did not complete",
            description=(
                f"The git history pass failed ({type(exc).__name__}), so secrets "
                "that exist only in history are not covered by this scan. "
                "Working-tree findings are unaffected."
            ),
            location=Location(path="(git history)"),
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            likelihood=Likelihood.UNLIKELY,
            remediation=Remediation(summary="Re-run the history scan or run it locally."),
            tags=["secret", "history", "analysis-gap"],
            metadata={"error": type(exc).__name__},
        )

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
                      line: str, severity: Severity,
                      confidence: Confidence, title: str) -> Finding:
        # Mask every secret on the line, not only the one this finding is about:
        # a second token or an AWS secret next to its key id would otherwise
        # stay in clear in the snippet.
        snippet = redact_line(line).strip()
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
