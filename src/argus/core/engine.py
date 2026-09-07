"""The scan engine: orchestrates a full analysis.

Pipeline:

1. **Analyze**, build the project model (languages, frameworks, architecture).
2. **Scan**, run every applicable scanner, collecting findings.
3. **Enrich**, run agents over each finding (reasoning, attack simulation,
   patch generation) according to config.
4. **Assemble**, filter by severity, sort, and package into a ``ScanResult``.

The engine returns a ``ScanResult`` and never modifies the target; its only
write is to Argus's own cache directory (disable with ``--no-cache``).
Reporting and PR creation are separate steps.

Performance: scanners run concurrently (they are independent by design), and
file-local scanners cache findings per file content hash so warm scans only
re-analyze changed files. Both are on by default and both preserve Argus's
determinism guarantee, findings, ids, and ordering are identical with or
without cache and parallelism.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from typing import TYPE_CHECKING

from argus import __version__
from argus.agents import (
    AgentContext,
    AttackSimulationAgent,
    EnrichmentAgent,
    PatchAgent,
)
from argus.ai.factory import build_provider
from argus.analysis.repository import RepositoryAnalyzer
from argus.core.config import Config
from argus.core.models import Finding, ScanResult
from argus.core.plugin import Scanner, ScannerContext, registry
from argus.core.project import Project

if TYPE_CHECKING:
    from argus.ai.base import AIProvider

# A callback the CLI uses to render progress. No-op by default.
ProgressFn = Callable[[str], None]


class ScanEngine:
    def __init__(self, config: Config, progress: ProgressFn | None = None) -> None:
        self.config = config
        self._progress = progress or (lambda _msg: None)

    def scan(self, project: Project) -> ScanResult:
        started = datetime.now(timezone.utc)
        result = ScanResult(
            target=str(project.root),
            started_at=started,
            argus_version=__version__,
        )

        # 1. Analyze
        self._progress("Analyzing project structure...")
        project.extra_ignores = tuple(self.config.exclude_paths)
        RepositoryAnalyzer().analyze(project)
        result.project_summary = project.summary()

        # AI provider (shared by all agents). Falls back to heuristic if needed.
        ai = build_provider(self.config.ai)
        self._progress(
            f"AI provider: {ai.name}"
            + ("" if ai.is_remote else " (local / offline)")
        )

        # 2. Scan. Scanners are independent, so they run concurrently; results
        # are merged in selection order to keep output deterministic. File-local
        # scanners consult the per-file cache so unchanged files skip re-analysis.
        scanners = self._select_scanners(project)
        result.scanners_run = [s.name for s in scanners]
        scan_ctx = ScannerContext(project=project, config=self.config, ai=ai)
        cache = self._open_cache(project)
        project.files()  # materialize the file walk once before threads share it

        def run_one(scanner: Scanner) -> tuple[list[Finding], str | None]:
            try:
                if cache is not None and scanner.cacheable(scan_ctx):
                    return self._scan_cached(scanner, scan_ctx, cache), None
                findings = list(scanner.scan(scan_ctx))
                # Renumber file-local scanners the same way the cached path does,
                # so finding ids are identical whether or not the cache is used.
                if scanner.file_local:
                    findings = self._renumber(scanner.name, findings)
                return findings, None
            except Exception as exc:  # a broken scanner must not sink the scan
                return [], f"scanner '{scanner.name}' failed: {exc}"

        for s in scanners:
            self._progress(f"Running scanner: {s.name}")
        if self.config.parallel and len(scanners) > 1:
            with ThreadPoolExecutor(max_workers=min(len(scanners), 8)) as pool:
                outcomes = list(pool.map(run_one, scanners))
        else:
            outcomes = [run_one(s) for s in scanners]
        failed: list[str] = []
        for scanner, (findings, error) in zip(scanners, outcomes, strict=True):
            for finding in findings:
                result.add(finding)
            if error:
                result.errors.append(error)
                failed.append(scanner.name)
        if failed:
            result.scanners_failed = failed
            result.scanners_run = [n for n in result.scanners_run if n not in failed]
        if cache is not None:
            cache.save()

        # 3. Prefer AST over regex where the AST tier is authoritative, de-duplicate
        # across scanners, filter, then enrich. Filtering first means agents (and any
        # paid model calls they make) only run on findings we will actually report.
        result.findings = self._apply_inline_suppressions(result.findings, project)
        result.findings = self._apply_allowlist(result.findings, self.config)
        result.findings = self._prefer_ast(result.findings, result.scanners_run)
        result.findings = self._dedupe(result.findings)
        # Correlate the surviving findings into higher-impact attack chains, then
        # apply the severity filter to findings and chains together.
        from argus.analysis.attack_chains import find_chains
        result.findings.extend(c.to_finding() for c in find_chains(result.findings))
        result.findings = self._filter(result.findings)
        if self.config.ai.enabled:
            self._run_agents(result, project, ai)

        from argus.analysis.risk_engine import enrich_contextual_risk
        from argus.analysis.security_graph import build_security_graph
        from argus.analysis.verification import apply_verification_states
        from argus.exceptions import apply_exceptions, default_exceptions_path, load_exceptions
        from argus.observability.metrics import MetricsTimer, ScanMetrics

        timer = MetricsTimer()
        apply_verification_states(result.findings)
        enrich_contextual_risk(result)
        result.project_summary["security_graph"] = build_security_graph(result)
        exc_path = default_exceptions_path(project.root)
        excs = load_exceptions(exc_path)
        result.findings, suppressed = apply_exceptions(result.findings, excs)
        if suppressed:
            result.project_summary["exceptions_applied"] = suppressed
        result.project_summary["metrics"] = ScanMetrics(
            scanners_run=result.scanners_run,
            findings_total=len(result.findings),
            duration_ms=timer.elapsed_ms(),
        ).to_dict()

        # 4. Assemble
        result.findings = result.sorted_findings()
        result.finished_at = datetime.now(timezone.utc)
        self._progress(
            f"Done: {len(result.findings)} finding(s), "
            f"highest severity {result.highest_severity().label}."
        )
        return result

    # --- caching --------------------------------------------------------------
    def _open_cache(self, project: Project):
        """Open the per-project scan cache, or None when caching is off.

        Remote targets are cloned to a fresh temp dir every run, so a cache
        keyed on that path could never hit, skip it rather than litter the
        cache directory.
        """
        if not self.config.cache or project.origin != "local":
            return None
        from argus.core.cache import ScanCache
        try:
            return ScanCache(project.root, __version__)
        except Exception:  # cache trouble must never break a scan
            return None

    def _scan_cached(self, scanner: Scanner, ctx: ScannerContext,
                     cache) -> list[Finding]:
        """Run a file-local scanner, reusing cached findings for unchanged files.

        Unchanged files (matched by content hash) contribute their cached
        findings; only changed/new files are re-scanned, via a filtered view of
        the project. Zero-finding files are cached too, that is most files.
        """
        from argus.core.cache import file_key, scanner_key

        skey = scanner_key(scanner.name, self.config.options_for(scanner.name))
        files = ctx.project.files()
        keys = {f.rel_path: file_key(f.rel_path, f.text()) for f in files}

        hits: list[Finding] = []
        misses = []
        for f in files:
            cached = cache.lookup(skey, keys[f.rel_path])
            if cached is None:
                misses.append(f)
            else:
                hits.extend(cached)

        fresh: list[Finding] = []
        if misses:
            import copy
            subset = copy.copy(ctx.project)
            subset._files_cache = tuple(misses)
            sub_ctx = ScannerContext(project=subset, config=ctx.config, ai=ctx.ai)
            fresh = list(scanner.scan(sub_ctx))
            by_file: dict[str, list[Finding]] = {f.rel_path: [] for f in misses}
            for finding in fresh:
                by_file.setdefault(finding.location.path, []).append(finding)
            for f in misses:
                cache.store(skey, keys[f.rel_path], by_file.get(f.rel_path, []))
        cache.prune(skey, set(keys.values()))
        return self._renumber(scanner.name, hits + fresh)

    @staticmethod
    def _renumber(scanner_name: str, findings: list[Finding]) -> list[Finding]:
        """Re-assign per-scan counters in ``scanner:rule:N`` ids after a cache merge.

        Scanners allocate those counters in (file, line) order during a full
        scan; sorting the merged cached+fresh findings the same way and
        renumbering makes ids match what an uncached scan produces, keeping
        ids unique and reports reproducible. Ids keyed by path/line (taint and
        AST findings) are already stable and pass through untouched.
        """
        findings.sort(key=lambda f: (f.location.path, f.location.start_line or 0,
                                     f.rule_id, f.id))
        pattern = re.compile(rf"^{re.escape(scanner_name)}:([^:]+):(\d+)$")
        counter = 0
        for f in findings:
            m = pattern.match(f.id)
            if m:
                counter += 1
                f.id = f"{scanner_name}:{m.group(1)}:{counter}"
        return findings

    # --- steps --------------------------------------------------------------
    def _select_scanners(self, project: Project) -> list[Scanner]:
        available = registry.scanners()
        explicit = bool(self.config.scanners)
        chosen_names = self.config.scanners or list(available)
        selected: list[Scanner] = []
        for name in chosen_names:
            if name in self.config.exclude_scanners:
                continue
            cls = available.get(name)
            if cls is None:
                # Only warn for names the user asked for explicitly; the "all"
                # default is derived from the registry and can't contain unknowns.
                if explicit:
                    self._progress(
                        f"Unknown scanner '{name}' (available: "
                        f"{', '.join(sorted(available))})."
                    )
                continue
            instance = cls()
            if instance.applies_to(project):
                selected.append(instance)
            else:
                self._progress(f"Skipping scanner '{name}' (not applicable).")
        return selected

    def _run_agents(self, result: ScanResult, project: Project,
                    ai: AIProvider) -> None:
        agent_ctx = AgentContext(project=project, config=self.config, ai=ai)
        enrichment = EnrichmentAgent()
        simulator = AttackSimulationAgent()
        patcher = PatchAgent()

        total = len(result.findings)
        for i, finding in enumerate(result.findings, start=1):
            self._progress(f"Enriching findings ({i}/{total})...")
            enrichment.process(finding, agent_ctx)
            if self.config.attack_simulation:
                simulator.process(finding, agent_ctx)
            if self.config.generate_patches:
                patcher.process(finding, agent_ctx)

    def _filter(self, findings: list[Finding]) -> list[Finding]:
        return [f for f in findings if f.severity >= self.config.min_severity]

    # Inline suppression comment, e.g.
    #   subprocess.run(cmd, shell=True)  # argus-ignore: python-shell-true reason="trusted"
    # The `reason` is required (so suppressions are documented). The rule id is
    # optional; without it every finding on the line is suppressed. An optional
    # `until=YYYY-MM-DD` makes the suppression expire so accepted risk resurfaces.
    # `#` and `//` comment styles are both accepted.
    _INLINE_IGNORE = re.compile(
        r"""(?:\#|//)\s*argus-ignore
            (?::\s*(?P<rule>[A-Za-z0-9_.\-]+))?
            [^\n]*?reason\s*=\s*['"](?P<reason>[^'"]+)['"]
            (?:[^\n]*?until\s*=\s*(?P<until>\d{4}-\d{2}-\d{2}))?
        """,
        re.VERBOSE,
    )

    @staticmethod
    def _rule_matches(rule_id: str, target: str) -> bool:
        """A suppression rule id matches by full id, short id, or last segment."""
        return (rule_id == target or rule_id.endswith("." + target)
                or rule_id.split(".")[-1] == target)

    @classmethod
    def _apply_inline_suppressions(cls, findings: list[Finding],
                                   project: Project) -> list[Finding]:
        """Drop findings whose source line carries a matching argus-ignore comment."""
        needed = {f.location.path for f in findings if f.location.start_line is not None}
        lines_by_path: dict[str, list[str]] = {
            fref.rel_path: fref.lines() for fref in project.files()
            if fref.rel_path in needed
        }
        today = datetime.now(timezone.utc).date()
        kept: list[Finding] = []
        for finding in findings:
            line_no = finding.location.start_line
            lines = lines_by_path.get(finding.location.path)
            if line_no is None or lines is None or not 1 <= line_no <= len(lines):
                kept.append(finding)
                continue
            m = cls._INLINE_IGNORE.search(lines[line_no - 1])
            if m is None:
                kept.append(finding)
                continue
            until = m.group("until")
            if until:
                try:
                    if date.fromisoformat(until) < today:
                        kept.append(finding)  # suppression expired: resurface it
                        continue
                except ValueError:
                    kept.append(finding)  # malformed date: do not suppress
                    continue
            rule = m.group("rule")
            if rule and not cls._rule_matches(finding.rule_id, rule):
                kept.append(finding)
                continue
            # otherwise: suppressed, drop it
        return kept

    @classmethod
    def _apply_allowlist(cls, findings: list[Finding], config: Config) -> list[Finding]:
        """Drop findings matched by a committed allowlist entry (config ``allow:``).

        Each entry is {rule?, path?, reason (required), until? (YYYY-MM-DD)}. A
        `reason` is required so acceptance is documented; an entry with neither a
        rule nor a path is rejected (it would suppress everything); an expired
        `until` no longer suppresses, so the finding resurfaces.
        """
        entries = getattr(config, "allow", None)
        if not entries:
            return findings
        today = datetime.now(timezone.utc).date()
        active: list[dict] = []
        for e in entries:
            if not e.get("reason") or (not e.get("rule") and not e.get("path")):
                continue
            until = e.get("until")
            if until:
                try:
                    if date.fromisoformat(str(until)) < today:
                        continue
                except ValueError:
                    continue
            active.append(e)
        if not active:
            return findings
        return [f for f in findings if not any(cls._allow_matches(f, e) for e in active)]

    @classmethod
    def _allow_matches(cls, finding: Finding, entry: dict) -> bool:
        rule = entry.get("rule")
        if rule and not cls._rule_matches(finding.rule_id, str(rule)):
            return False
        path = entry.get("path")
        if path:
            path = str(path)
            p = finding.location.path or ""
            name = p.rsplit("/", 1)[-1]
            if not (fnmatch.fnmatch(p, path) or fnmatch.fnmatch(name, path)
                    or (path.endswith("/**") and p.startswith(path[:-2]))):
                return False
        return True

    # Vulnerability classes the AST taint tiers analyze authoritatively via data
    # flow. Where an AST scanner ran over a file, the regex tier's guesses for these
    # classes are redundant (the AST tier already confirmed or cleared them), so
    # they are dropped to avoid false positives like flagging a sanitized innerHTML.
    #
    # Note: CWE-78 (command injection) is intentionally NOT here. The regex tier's
    # command-injection rules flag taint-independent smells such as
    # `subprocess(..., shell=True)` and `os.system(<dynamic>)`, which are dangerous
    # regardless of whether a tracked taint source reaches them, so the AST tier's
    # silence must not suppress them. Genuinely tainted cases where both tiers fire
    # are still collapsed by _dedupe, so this does not double-report.
    _AST_OWNED_CWE = {"CWE-89", "CWE-79", "CWE-22", "CWE-95"}
    _AST_LANG_EXT = {
        "ast-python": (".py",),
        "ast-js": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"),
    }

    @classmethod
    def _prefer_ast(cls, findings: list[Finding], scanners_run: list[str]) -> list[Finding]:
        covered_ext = tuple(
            ext for name, exts in cls._AST_LANG_EXT.items() if name in scanners_run
            for ext in exts
        )
        if not covered_ext:
            return findings
        out: list[Finding] = []
        for f in findings:
            redundant = (
                f.scanner == "patterns"
                and any(c in cls._AST_OWNED_CWE for c in f.cwe)
                and f.location.path.endswith(covered_ext)
            )
            if not redundant:
                out.append(f)
        return out

    # Two different tiers reporting the same weakness within this many lines are
    # treated as one (e.g. the regex tier flags an unsafe query where it is built,
    # the AST tier flags it where it is executed a line later).
    _DEDUPE_WINDOW = 3

    @classmethod
    def _dedupe(cls, findings: list[Finding]) -> list[Finding]:
        """Collapse the same weakness reported by more than one scanner.

        When the regex ``patterns`` tier and the AST ``ast-python`` tier both catch
        one injection, often a line or two apart (construction vs. execution),
        keep the higher-confidence (then higher-severity) finding so the report is
        not doubled. Only merges findings from *different* scanners with the same
        CWE in the same file within a small line window, so distinct issues and
        within-tier findings are preserved. Findings with no line or CWE pass through.
        """
        passthrough = [f for f in findings
                       if f.location.start_line is None or not f.cwe]
        mergeable = [f for f in findings
                     if f.location.start_line is not None and f.cwe]
        mergeable.sort(key=lambda f: (f.location.path, tuple(sorted(f.cwe)),
                                      f.location.start_line or 0))
        kept: list[Finding] = []
        for f in mergeable:
            prev = kept[-1] if kept else None
            if (prev is not None
                    and prev.scanner != f.scanner
                    and prev.location.path == f.location.path
                    and sorted(prev.cwe) == sorted(f.cwe)
                    and (f.location.start_line or 0)
                        - (prev.location.start_line or 0) <= cls._DEDUPE_WINDOW):
                if (f.confidence, f.severity) > (prev.confidence, prev.severity):
                    kept[-1] = f
                continue
            kept.append(f)
        return passthrough + kept

    # --- CI gating helper ---------------------------------------------------
    def should_fail(self, result: ScanResult) -> bool:
        if self.config.fail_on_error and result.errors:
            return True
        if self.config.fail_on is None:
            return False
        return result.highest_severity() >= self.config.fail_on
