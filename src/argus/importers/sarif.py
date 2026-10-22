"""SARIF 2.1.0 import: turn other scanners' results into Argus findings.

Organizations already run Semgrep, CodeQL, gitleaks, Trivy, Bandit and others,
and nearly all of them can write SARIF. Importing that output as ordinary
:class:`~argus.core.models.Finding` objects lets the rest of Argus (baselines,
allowlists, exceptions, policy, every reporter, enrichment and fix
generation) work on those results unchanged.

The input is untrusted: it may come from a CI artifact or a pull request, and
secret scanners put the raw credential in the snippet. So the parser

* caps the file size and JSON nesting depth (:mod:`argus.importers._safejson`)
  and the number of results;
* reads every field through a type check and tolerates any optional field
  being absent or of the wrong type (a bad field is ignored, never trusted);
* drops locations that resolve outside the project root, with a warning, and
  never opens a file outside it (:mod:`argus.importers._paths`);
* redacts snippets and messages with the secrets scanner's redaction before
  anything is stored, and masks the reported span of secret findings;
* strips terminal control characters from all text and only keeps
  ``http(s)`` help links.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from argus.core.models import Confidence, Finding, Location, Remediation, Severity
from argus.importers._paths import PathResolver, ResolvedPath, UnsafePathError
from argus.importers._safejson import (
    DEFAULT_MAX_BYTES,
    ImportFormatError,
    loads_untrusted,
    read_bounded,
)
from argus.scanners.secrets import SecretsScanner, redact_line

#: Results imported across all files before the import is refused. A run this
#: large is not something a reviewer can triage; split it instead.
MAX_RESULTS = 100_000
MAX_RUNS = 1_000

_MAX_TITLE = 200
_MAX_TEXT = 4_000
_MAX_SNIPPET_CHARS = 500
_MAX_SNIPPET_LINES = 5
_MAX_TAGS = 20
_MAX_TAG_CHARS = 64
_MAX_CWES = 10
_MAX_FINGERPRINTS = 10
_MAX_WARNINGS_PER_FILE = 20

# C0 controls (except tab and newline), DEL and C1 controls. They have no place
# in a finding and an ESC sequence in a title would drive the user's terminal.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CWE_TAG = re.compile(r"(?i)(?:^|[/\s(\[])cwe[-_: ]?0*(\d{1,5})(?!\d)")
_CWE_ID = re.compile(r"(?i)^(?:cwe[-_: ]?)?0*(\d{1,5})$")
_OWASP_TAG = re.compile(
    r"(?i)\bA(\d{1,2})[:_ ](20\d\d)\b(?:\s*[-:]\s*([A-Za-z][A-Za-z ,()/'-]{0,60}))?"
)
_ADVISORY = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b", re.I)
_PLACEHOLDER = re.compile(r"\{(\d{1,2})\}")
_SLUG = re.compile(r"[^a-z0-9._-]+")

# Tools whose every result is a credential, whatever the rule says.
_SECRET_TOOLS = {"gitleaks", "trufflehog", "detect-secrets", "ggshield", "talisman"}
_SECRET_CWES = {"CWE-798", "CWE-259", "CWE-321", "CWE-522", "CWE-540", "CWE-312"}
_SECRET_WORDS = re.compile(
    r"(?i)secret|token|passw(?:or)?d|credential|api[_-]?key|private[_-]?key|access[_-]?key"
)

_LEVEL_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}
_PROBLEM_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "recommendation": Severity.LOW,
}
_NAMED_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "negligible": Severity.INFO,
}
# One step below what the tool claims: Argus has not verified the result.
_CONFIDENCE = {
    "very-high": Confidence.HIGH,
    "high": Confidence.MEDIUM,
    "medium": Confidence.LOW,
    "low": Confidence.LOW,
}
# Result kinds that do not describe a problem.
_NON_PROBLEM_KINDS = {"pass", "notApplicable", "informational"}


class SarifImportError(ImportFormatError):
    """A SARIF file was rejected as a whole (unreadable, malformed, too big)."""


# --- strict accessors ---------------------------------------------------------
def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _str(value: Any) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _int(value: Any, *, minimum: int = 0) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if minimum <= value < 2**31 else None


def _clean(text: str, limit: int) -> str:
    text = _CONTROL.sub("", _ANSI.sub("", text)).strip()
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return text


def _redact_text(text: str) -> str:
    return "\n".join(redact_line(line) for line in text.splitlines())


_TOKEN = re.compile(r"[^\s'\"`=:,;()\[\]{}<>]{6,}")


def _masked_tokens(before: str, after: str) -> list[str]:
    """Tokens of ``before`` that redaction removed (fully or partly) from ``after``.

    A token that no longer appears after redaction is, or contains, the
    secret, so it is what must also be scrubbed from the message text.
    """
    if before == after:
        return []
    return [t for t in _TOKEN.findall(before) if t not in after]


def _message_text(message: Any, rule: dict[str, Any]) -> str | None:
    """A result's message, with ``{0}`` placeholders filled from its arguments."""
    msg = _obj(message)
    text = _str(msg.get("text")) or _str(msg.get("markdown"))
    if text is None:
        msg_id = _str(msg.get("id"))
        if msg_id:
            strings = _obj(rule.get("messageStrings"))
            entry = _obj(strings.get(msg_id))
            text = _str(entry.get("text")) or _str(entry.get("markdown"))
    if text is None:
        return None
    args = [a if isinstance(a, str) else "" for a in _list(msg.get("arguments"))]

    def fill(m: re.Match[str]) -> str:
        i = int(m.group(1))
        return args[i] if i < len(args) else m.group(0)

    return _PLACEHOLDER.sub(fill, text)


def _text_field(value: Any) -> str | None:
    """The ``text`` (or ``markdown``) of a SARIF multiformat message string."""
    obj = _obj(value)
    return _str(obj.get("text")) or _str(obj.get("markdown"))


def _slug(name: str) -> str:
    slug = _SLUG.sub("-", name.strip().lower()).strip("-.")
    return slug[:40] or "unknown"


def _http_uri(value: Any) -> str | None:
    """Keep only http(s) links: a ``javascript:`` help URI would run in HTML reports."""
    uri = _str(value)
    if uri and re.match(r"(?i)^https?://[^\s\"'<>]+$", uri) and len(uri) <= 2_000:
        return uri
    return None


def _cwe(raw: str) -> str | None:
    m = _CWE_ID.match(raw.strip())
    if not m:
        return None
    number = int(m.group(1))
    return f"CWE-{number}" if number > 0 else None


def _score(value: Any) -> float | None:
    """A ``security-severity`` score (0.0 to 10.0), as GitHub and CodeQL use."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str):
        try:
            score = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    if not math.isfinite(score) or not 0.0 <= score <= 10.0:
        return None
    return score


def _severity_from_score(score: float) -> Severity:
    # GitHub code scanning buckets: >= 9.0 critical, 7.0 high, 4.0 medium,
    # 0.1 low; 0.0 is "none".
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 0.1:
        return Severity.LOW
    return Severity.INFO


# --- result of an import -----------------------------------------------------
@dataclass
class SarifImport:
    """Findings imported from one or more SARIF files, plus what was skipped."""

    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Scanner names, e.g. ``sarif:semgrep``, in first-seen order.
    tools: list[str] = field(default_factory=list)
    #: Counters: results, imported, suppressed, not_a_problem, absent,
    #: unsafe_path, duplicate.
    stats: Counter[str] = field(default_factory=Counter)
    sources: list[str] = field(default_factory=list)

    def merge(self, other: SarifImport) -> None:
        seen = {f.id for f in self.findings}
        for finding in other.findings:
            if finding.id in seen:
                self.stats["duplicate"] += 1
                continue
            seen.add(finding.id)
            self.findings.append(finding)
        self.warnings.extend(other.warnings)
        self.tools.extend(t for t in other.tools if t not in self.tools)
        self.stats.update(other.stats)
        self.sources.extend(other.sources)

    def summary(self) -> dict[str, Any]:
        """A JSON-friendly summary for ``ScanResult.project_summary``."""
        return {
            "files": list(self.sources),
            "tools": list(self.tools),
            **{k: v for k, v in sorted(self.stats.items())},
        }


# --- the parser -----------------------------------------------------------------
class _Run:
    """One ``runs[]`` entry: its tool, rules, taxonomies and path resolver."""

    def __init__(self, run: dict[str, Any], project_root: Path) -> None:
        tool = _obj(run.get("tool"))
        driver = _obj(tool.get("driver"))
        self.tool_name = _clean(_str(driver.get("name")) or "unknown", 80)
        self.slug = _slug(self.tool_name)
        self.scanner = f"sarif:{self.slug}"
        self.tool_version = _str(driver.get("semanticVersion")) or _str(driver.get("version"))
        self.components: list[dict[str, Any]] = [driver] + [
            _obj(e) for e in _list(tool.get("extensions"))
        ]
        self.rules_by_id: dict[str, dict[str, Any]] = {}
        for component in self.components:
            for rule in _list(component.get("rules")):
                rule = _obj(rule)
                rule_id = _str(rule.get("id"))
                if rule_id and rule_id not in self.rules_by_id:
                    self.rules_by_id[rule_id] = rule
        self.taxonomies = [_obj(t) for t in _list(run.get("taxonomies"))]
        self.artifacts = _list(run.get("artifacts"))
        self.paths = PathResolver(project_root, _obj(run.get("originalUriBaseIds")))
        self.secret_tool = self.slug in _SECRET_TOOLS or any(
            self.slug.startswith(t) for t in _SECRET_TOOLS
        )

    # --- rules -------------------------------------------------------------
    def _component(self, ref: dict[str, Any]) -> dict[str, Any] | None:
        tc = _obj(ref.get("toolComponent"))
        if not tc:
            return self.components[0]
        index = _int(tc.get("index"))
        if index is not None:
            # toolComponent.index points into tool.extensions.
            return self.components[index + 1] if index + 1 < len(self.components) else None
        name = _str(tc.get("name"))
        for component in self.components:
            if name and _str(component.get("name")) == name:
                return component
        return None

    def rule_for(self, result: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        ref = _obj(result.get("rule"))
        rule_id = _str(result.get("ruleId")) or _str(ref.get("id"))
        index = _int(result.get("ruleIndex"))
        if index is None:
            index = _int(ref.get("index"))
        descriptor: dict[str, Any] = {}
        component = self._component(ref)
        if index is not None and component is not None:
            rules = _list(component.get("rules"))
            if index < len(rules):
                descriptor = _obj(rules[index])
        described = _str(descriptor.get("id"))
        if rule_id and described and described != rule_id and rule_id in self.rules_by_id:
            descriptor = {}  # an index that disagrees with the id: trust the id
        if not descriptor and rule_id:
            descriptor = self.rules_by_id.get(rule_id, {})
            if not descriptor and "/" in rule_id:
                # Hierarchical ids ("RULE/subrule") may only describe the parent.
                descriptor = self.rules_by_id.get(rule_id.split("/", 1)[0], {})
        rule_id = rule_id or _str(descriptor.get("id")) or "unknown-rule"
        return _clean(rule_id, 200), descriptor

    # --- taxonomy -------------------------------------------------------------
    def _taxonomy_name(self, ref: dict[str, Any]) -> str | None:
        tc = _obj(ref.get("toolComponent"))
        name = _str(tc.get("name"))
        if name:
            return name
        index = _int(tc.get("index"))
        if index is not None and index < len(self.taxonomies):
            return _str(self.taxonomies[index].get("name"))
        return None

    def _taxon_id(self, ref: dict[str, Any]) -> str | None:
        taxon_id = _str(ref.get("id"))
        if taxon_id:
            return taxon_id
        index = _int(ref.get("index"))
        tc = _obj(ref.get("toolComponent"))
        tax_index = _int(tc.get("index"))
        if index is None or tax_index is None or tax_index >= len(self.taxonomies):
            return None
        taxa = _list(self.taxonomies[tax_index].get("taxa"))
        return _str(_obj(taxa[index]).get("id")) if index < len(taxa) else None

    def cwes(self, result: dict[str, Any], rule: dict[str, Any], tags: Iterable[str]) -> list[str]:
        found: list[str] = []
        for tag in tags:
            found.extend(f"CWE-{int(m.group(1))}" for m in _CWE_TAG.finditer(tag))
        for props in (_obj(result.get("properties")), _obj(rule.get("properties"))):
            raw = props.get("cwe")
            for item in [raw] if isinstance(raw, str) else _list(raw):
                cwe = _cwe(item) if isinstance(item, str) else None
                if cwe:
                    found.append(cwe)
        refs = [_obj(r) for r in _list(result.get("taxa"))]
        refs += [_obj(_obj(r).get("target")) for r in _list(rule.get("relationships"))]
        for ref in refs:
            name = self._taxonomy_name(ref)
            taxon = self._taxon_id(ref)
            if taxon and (name or "").upper() == "CWE":
                cwe = _cwe(taxon)
                if cwe:
                    found.append(cwe)
        unique = [c for c in dict.fromkeys(found) if c != "CWE-0"]
        return unique[:_MAX_CWES]

    # --- locations ------------------------------------------------------------
    def artifact_location(self, physical: dict[str, Any]) -> dict[str, Any]:
        art = _obj(physical.get("artifactLocation"))
        if _str(art.get("uri")) is None:
            index = _int(art.get("index"))
            if index is not None and index < len(self.artifacts):
                fallback = _obj(_obj(self.artifacts[index]).get("location"))
                return {**fallback, **{k: v for k, v in art.items() if k != "index"}}
        return art


class SarifParser:
    """Map one SARIF document to findings for a project rooted at ``project_root``."""

    def __init__(self, project_root: Path, *, source: str, max_results: int = MAX_RESULTS):
        self.root = project_root.resolve()
        self.source = source
        self.max_results = max_results
        self.out = SarifImport(sources=[source])
        self._dropped: list[str] = []

    def warn(self, message: str) -> None:
        self.out.warnings.append(f"{self.source}: {message}")

    def parse(self, doc: Any) -> SarifImport:
        if not isinstance(doc, dict):
            raise SarifImportError(f"{self.source} is not a SARIF log (expected a JSON object)")
        version = doc.get("version")
        if version is not None and version != "2.1.0":
            raise SarifImportError(
                f"{self.source} is SARIF version {version!r}; only 2.1.0 is supported"
            )
        runs = doc.get("runs")
        if not isinstance(runs, list):
            raise SarifImportError(f"{self.source} has no 'runs' array; is it a SARIF file?")
        if version is None:
            self.warn("no 'version' property; reading it as SARIF 2.1.0")
        if len(runs) > MAX_RUNS:
            raise SarifImportError(f"{self.source} has {len(runs)} runs; the limit is {MAX_RUNS}")
        for run_index, run in enumerate(runs):
            if not isinstance(run, dict):
                self.warn(f"runs[{run_index}] is not an object; skipped")
                continue
            self._parse_run(run, run_index)
        if self._dropped:
            shown = self._dropped[:_MAX_WARNINGS_PER_FILE]
            more = len(self._dropped) - len(shown)
            for item in shown:
                self.warn(item)
            if more:
                self.warn(f"... and {more} more result(s) dropped for unsafe paths")
        return self.out

    def _parse_run(self, run_obj: dict[str, Any], run_index: int) -> None:
        run = _Run(run_obj, self.root)
        if run.scanner not in self.out.tools:
            self.out.tools.append(run.scanner)
        rebased_warned = False
        for result_index, result in enumerate(_list(run_obj.get("results"))):
            self.out.stats["results"] += 1
            if self.out.stats["results"] > self.max_results:
                raise SarifImportError(
                    f"{self.source} has more than {self.max_results} results; split the "
                    "import or filter the scanner output first"
                )
            if not isinstance(result, dict):
                self.out.stats["invalid"] += 1
                continue
            where = f"runs[{run_index}].results[{result_index}]"
            finding = self._finding(run, result, where)
            if finding is None:
                continue
            if finding.metadata["sarif"].get("rebased") and not rebased_warned:
                rebased_warned = True
                self.warn(
                    f"{run.tool_name}: a uriBaseId points outside the project root; "
                    "its paths were read relative to the project root instead"
                )
            self.out.findings.append(finding)
            self.out.stats["imported"] += 1

    # --- one result ------------------------------------------------------------
    def _skip_reason(self, result: dict[str, Any]) -> str | None:
        kind = _str(result.get("kind"))
        if kind in _NON_PROBLEM_KINDS:
            return "not_a_problem"
        if _str(result.get("baselineState")) == "absent":
            return "absent"
        for sup in _list(result.get("suppressions")):
            status = _str(_obj(sup).get("status"))
            # A suppression without a status counts as accepted.
            if isinstance(sup, dict) and status in (None, "accepted"):
                return "suppressed"
        return None

    def _finding(self, run: _Run, result: dict[str, Any], where: str) -> Finding | None:
        reason = self._skip_reason(result)
        if reason:
            self.out.stats[reason] += 1
            return None

        rule_id, rule = run.rule_for(result)
        rule_props = _obj(rule.get("properties"))
        result_props = _obj(result.get("properties"))
        raw_tags = [
            t
            for t in _list(rule_props.get("tags")) + _list(result_props.get("tags"))
            if isinstance(t, str)
        ]
        cwes = run.cwes(result, rule, raw_tags)
        secret = (
            run.secret_tool
            or bool(_SECRET_CWES.intersection(cwes))
            or bool(_SECRET_WORDS.search(rule_id))
            or any(t.lower() in ("secret", "secrets") for t in raw_tags)
        )
        if run.secret_tool and not cwes:
            cwes = ["CWE-798"]

        try:
            location, loc_meta = self._location(run, result, secret)
        except UnsafePathError as exc:
            self.out.stats["unsafe_path"] += 1
            self._dropped.append(f"{where} ({rule_id}) dropped: {exc}")
            return None

        severity, severity_source = self._severity(result, rule, result_props, rule_props)
        if severity_source == "default" and secret:
            # gitleaks and similar tools give no level at all. A committed
            # credential is never a "warning", so do not let it hide under
            # a --fail-on high gate.
            severity, severity_source = Severity.HIGH, "secret-default"
        confidence = Confidence.LOW
        for props in (result_props, rule_props):
            for key in ("precision", "confidence", "issue_confidence"):
                value = _str(props.get(key))
                if value and value.lower() in _CONFIDENCE:
                    confidence = _CONFIDENCE[value.lower()]
                    break
            else:
                continue
            break

        # Values masked in a secret's snippet are also scrubbed from the text
        # fields, where some tools repeat them. They are never stored.
        secrets: list[str] = loc_meta.pop("secret_values", [])
        message = _message_text(result.get("message"), rule) or ""
        title = self._title(rule, rule_id, message)
        full = _text_field(rule.get("fullDescription"))
        title = self._safe_text(title, _MAX_TITLE, secrets)
        description = self._safe_text(message or title, _MAX_TEXT, secrets)
        why = self._safe_text(full, _MAX_TEXT, secrets) if full and full != title else ""

        help_text = _text_field(rule.get("help"))
        help_uri = _http_uri(rule.get("helpUri"))
        remediation = None
        if help_text or help_uri:
            guidance = self._safe_text(help_text or "", _MAX_TEXT, secrets)
            first = next(
                (ln.strip().lstrip("#").strip() for ln in guidance.splitlines() if ln.strip()), ""
            )
            remediation = Remediation(
                summary=_clean(first, _MAX_TITLE) or f"See the {run.tool_name} rule documentation.",
                guidance=guidance,
                references=[help_uri] if help_uri else [],
            )

        owasp = self._owasp(raw_tags)
        tags = self._tags(run, raw_tags)
        advisories = sorted({m.group(1).upper() for m in _ADVISORY.finditer(rule_id)})

        fingerprints = self._fingerprints(result)
        basis = [run.slug, rule_id, location.path]
        if fingerprints:
            basis.append(json.dumps(sorted(fingerprints.items())))
        else:
            basis += [
                str(location.start_line or 0),
                re.sub(r"\s+", "", location.snippet or ""),
            ]
        digest = hashlib.sha256("\x1f".join(basis).encode("utf-8")).hexdigest()[:16]

        sarif_meta: dict[str, Any] = {
            "tool": run.tool_name,
            "tool_version": run.tool_version,
            "rule_id": rule_id,
            "source": self.source,
            "severity_source": severity_source,
            "fingerprint": digest,
            **loc_meta,
        }
        level = _str(result.get("level"))
        if level:
            sarif_meta["level"] = level
        if fingerprints:
            sarif_meta["fingerprints"] = fingerprints
        sarif_meta = {k: v for k, v in sarif_meta.items() if v not in (None, "", [], {})}
        metadata: dict[str, Any] = {"sarif": sarif_meta, "imported": True}
        if advisories:
            metadata["cve"] = advisories[0]
            metadata["advisories"] = advisories

        short_rule = _slug(rule_id.rsplit("/", 1)[-1].rsplit(".", 1)[-1])[:40]
        return Finding(
            id=f"{run.scanner}:{short_rule}:{digest}",
            rule_id=f"{run.slug}.{rule_id}",
            scanner=run.scanner,
            title=title or rule_id,
            description=description or title or rule_id,
            location=location,
            severity=severity,
            confidence=confidence,
            cwe=cwes,
            owasp=owasp,
            why_vulnerable=why,
            remediation=remediation,
            tags=tags,
            metadata=metadata,
        )

    # --- helpers -----------------------------------------------------------------
    @staticmethod
    def _title(rule: dict[str, Any], rule_id: str, message: str) -> str:
        """A short, readable title.

        Tools fill the rule fields differently: CodeQL and Trivy have a good
        ``shortDescription``; Semgrep's only repeats the rule id; gitleaks
        writes a long sentence there but a readable ``name``; Bandit has a
        snake_case ``name`` and only the message is readable.
        """
        short = _text_field(rule.get("shortDescription"))
        name = _str(rule.get("name"))
        first = next((ln.strip() for ln in message.splitlines() if ln.strip()), None)
        if short and rule_id not in short and len(short) <= 80:
            return short
        if name and name != rule_id and " " in name:
            return name
        return first or short or name or rule_id

    @staticmethod
    def _safe_text(text: str | None, limit: int, secrets: list[str]) -> str:
        """Clean, redact and truncate text, also masking known secret values."""
        if not text:
            return ""
        for value in sorted(set(secrets), key=len, reverse=True):
            if len(value) >= 6:
                text = text.replace(value, SecretsScanner._redact(value))
        return _clean(_redact_text(_ANSI.sub("", text)), limit)

    @staticmethod
    def _severity(
        result: dict[str, Any],
        rule: dict[str, Any],
        result_props: dict[str, Any],
        rule_props: dict[str, Any],
    ) -> tuple[Severity, str]:
        for props in (result_props, rule_props):
            score = _score(props.get("security-severity"))
            if score is not None:
                return _severity_from_score(score), "security-severity"
        for props in (result_props, rule_props):
            for key in ("severity", "issue_severity"):
                name = _str(props.get(key))
                if name and name.lower() in _NAMED_SEVERITY:
                    return _NAMED_SEVERITY[name.lower()], key
        for props in (result_props, rule_props):
            problem = _str(props.get("problem.severity")) or _str(
                _obj(props.get("problem")).get("severity")
            )
            if problem and problem.lower() in _PROBLEM_SEVERITY:
                return _PROBLEM_SEVERITY[problem.lower()], "problem.severity"
        level = _str(result.get("level")) or _str(
            _obj(rule.get("defaultConfiguration")).get("level")
        )
        if level and level.lower() in _LEVEL_SEVERITY:
            return _LEVEL_SEVERITY[level.lower()], "level"
        # SARIF's default level is "warning".
        return Severity.MEDIUM, "default"

    @staticmethod
    def _fingerprints(result: dict[str, Any]) -> dict[str, str]:
        out: dict[str, str] = {}
        for key in ("fingerprints", "partialFingerprints"):
            for name, value in _obj(result.get(key)).items():
                if not isinstance(name, str) or not isinstance(value, str):
                    continue
                if value.strip() and name not in out:
                    out[_clean(name, 100)] = _clean(value, 200)
                if len(out) >= _MAX_FINGERPRINTS:
                    return out
        return out

    @staticmethod
    def _owasp(tags: Iterable[str]) -> list[str]:
        found: list[str] = []
        for tag in tags:
            if "owasp" not in tag.lower():
                continue
            m = _OWASP_TAG.search(tag)
            if not m:
                continue
            label = f"A{int(m.group(1)):02d}:{m.group(2)}"
            if m.group(3):
                label += "-" + m.group(3).strip()
            found.append(label[:80])
        return list(dict.fromkeys(found))[:5]

    @staticmethod
    def _tags(run: _Run, raw_tags: Iterable[str]) -> list[str]:
        tags = ["sarif", run.slug]
        for tag in raw_tags:
            clean = _clean(tag, _MAX_TAG_CHARS)
            lowered = clean.lower()
            if not clean or _CWE_TAG.search(clean) or "owasp" in lowered:
                continue  # already in cwe / owasp
            tags.append(clean)
        return list(dict.fromkeys(tags))[:_MAX_TAGS]

    def _location(
        self, run: _Run, result: dict[str, Any], secret: bool
    ) -> tuple[Location, dict[str, Any]]:
        locations = _list(result.get("locations"))
        first = _obj(locations[0]) if locations else {}
        physical = _obj(first.get("physicalLocation"))
        logical = [_obj(x) for x in _list(first.get("logicalLocations"))]
        logical_names = [
            _clean(n, 200)
            for n in (_str(x.get("fullyQualifiedName")) or _str(x.get("name")) for x in logical)
            if n
        ][:5]
        meta: dict[str, Any] = {}
        if logical_names:
            meta["logical_locations"] = logical_names

        art = run.artifact_location(physical)
        uri = _str(art.get("uri"))
        if uri is None:
            label = logical_names[0] if logical_names else run.tool_name
            return Location(path=f"({label})"), meta

        base_id = _str(art.get("uriBaseId"))
        resolved: ResolvedPath = run.paths.resolve(uri, base_id)
        if resolved.rebased:
            meta["rebased"] = True
        if resolved.kind == "external":
            return Location(path=_clean(resolved.path, 2_000)), meta

        region = _obj(physical.get("region"))
        start = _int(region.get("startLine"), minimum=1)
        end = _int(region.get("endLine"), minimum=1)
        if start is None:
            end = None
        elif end is None or end < start:
            end = start
        start_col = _int(region.get("startColumn"), minimum=1) if start else None
        end_col = _int(region.get("endColumn"), minimum=1) if start else None

        raw_snippet = _str(_obj(region.get("snippet")).get("text"))
        if raw_snippet is None:
            raw_snippet = _str(_obj(_obj(physical.get("contextRegion")).get("snippet")).get("text"))

        masked: list[str] = []
        snippet = self._snippet(
            run, resolved.path, start, end, start_col, end_col, raw_snippet, secret, masked
        )
        if secret and masked:
            # Never stored: the caller scrubs these values from the message.
            meta["secret_values"] = masked
        return (
            Location(
                path=resolved.path,
                start_line=start,
                end_line=end,
                start_column=start_col,
                end_column=end_col,
                snippet=snippet,
            ),
            meta,
        )

    @staticmethod
    def _snippet(
        run: _Run,
        path: str,
        start: int | None,
        end: int | None,
        start_col: int | None,
        end_col: int | None,
        raw_snippet: str | None,
        secret: bool,
        masked: list[str],
    ) -> str | None:
        """The redacted snippet: the source lines if readable, else the SARIF text.

        Reading the project's own lines keeps the snippet (and therefore
        :meth:`Finding.fingerprint`) identical to what Argus's scanners record
        for the same line, which is what makes baselines and de-duplication
        line up. For secret findings the reported column span is masked first,
        so a value the redactor does not recognize is still hidden; if nothing
        could be located, the whole line is masked. Every value masked for a
        secret finding is appended to ``masked``.
        """
        lines: list[str] = []
        span: str | None = None
        bare = (raw_snippet or "").strip()
        if secret and bare and not re.search(r"\s", bare):
            masked.append(bare)  # the snippet is the value itself
        if start is not None and end is not None:
            source = run.paths.read_lines(path)
            if source is not None and start <= len(source):
                last = min(end, start + _MAX_SNIPPET_LINES - 1, len(source))
                lines = source[start - 1 : last]
                if secret and start_col and end_col and end == start and lines:
                    a, b = start_col - 1, min(end_col - 1, len(lines[0]))
                    if 0 <= a < b and lines[0][a:b].strip():
                        span = lines[0][a:b]
        if not lines and raw_snippet:
            lines = raw_snippet.splitlines()[:_MAX_SNIPPET_LINES]
        if not lines:
            return None
        redacted = [redact_line(ln) for ln in lines]
        if span is not None:
            masked.append(span)
            if span in redacted[0]:
                # The redactor did not recognize the value the tool reported.
                redacted[0] = redacted[0].replace(span, SecretsScanner._redact(span))
        if secret:
            for before, after in zip(lines, redacted, strict=True):
                masked.extend(_masked_tokens(before, after))
            if span is None and redacted == lines:
                # A bare value (gitleaks puts only the secret in the snippet)
                # matches no pattern; mask all of it rather than store it.
                masked.extend(ln.strip() for ln in lines if ln.strip())
                redacted = [SecretsScanner._redact(ln.strip()) for ln in lines]
        text = _clean("\n".join(ln.strip() for ln in redacted), _MAX_SNIPPET_CHARS)
        return text or None


# --- public entry points -----------------------------------------------------------
def load_sarif(path: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Any:
    """Read and decode a SARIF file with the size and depth limits applied."""
    try:
        return loads_untrusted(read_bounded(path, max_bytes), source=str(path))
    except SarifImportError:
        raise
    except ImportFormatError as exc:
        raise SarifImportError(str(exc)) from exc


def parse_sarif(
    doc: Any, *, project_root: Path, source: str = "<sarif>", max_results: int = MAX_RESULTS
) -> SarifImport:
    """Map a decoded SARIF document to Argus findings."""
    return SarifParser(project_root, source=source, max_results=max_results).parse(doc)


def _unique_ids(findings: list[Finding]) -> Iterator[Finding]:
    """Keep ids unique: identical results collapse, distinct ones get a suffix."""
    seen: dict[str, str] = {}
    for f in findings:
        key = f.fingerprint()
        if f.id not in seen:
            seen[f.id] = key
            yield f
            continue
        if seen[f.id] == key:
            continue
        n = 2
        while f"{f.id}:{n}" in seen:
            n += 1
        f.id = f"{f.id}:{n}"
        seen[f.id] = key
        yield f


def import_sarif(
    paths: Iterable[Path],
    *,
    project_root: Path,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_results: int = MAX_RESULTS,
) -> SarifImport:
    """Import every SARIF file in ``paths`` for the project at ``project_root``.

    Raises :class:`SarifImportError` if any file is unreadable or not SARIF;
    individual bad results are skipped and counted instead.
    """
    total = SarifImport()
    remaining = max_results
    for path in paths:
        doc = load_sarif(path, max_bytes=max_bytes)
        one = parse_sarif(doc, project_root=project_root, source=str(path), max_results=remaining)
        remaining -= one.stats["results"]
        before = len(one.findings)
        one.findings = list(_unique_ids(one.findings))
        one.stats["duplicate"] += before - len(one.findings)
        one.stats["imported"] -= before - len(one.findings)
        total.merge(one)
    total.stats["imported"] = len(total.findings)
    return total
