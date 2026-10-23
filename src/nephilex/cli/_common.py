"""Helpers shared by the CLI commands.

Parsing of severity and list options, target resolution, progress output,
config assembly from command-line flags, and the scanner-failure gate. Nothing
here registers a command; the command modules under :mod:`nephilex.cli.commands`
call into it.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.markup import escape

from nephilex import __version__
from nephilex.cli._console import err_console
from nephilex.cli.output import print_scanner_failure
from nephilex.core.config import Config, load_project_config
from nephilex.core.models import ScanResult, Severity

if TYPE_CHECKING:
    from nephilex.core.project import Project
    from nephilex.targets import ResolvedTarget

CONFIG_FROM_REF_HELP = (
    "Read .nephilex.yml (or the --config path, which must be inside the repository) "
    "from this git ref instead of the working tree, and treat the checked-out "
    "tree as untrusted: its .nephilex/rules, .nephilex/exceptions.yml and inline "
    "nephilex-ignore comments are not honored. Use it in CI on pull requests with "
    "the base branch (e.g. origin/main) so a PR cannot change the settings it is "
    "checked against. The ref must exist locally; an unknown ref is an error."
)


def cli_severity(value: str, option: str) -> Severity:
    """Parse a severity flag, turning a typo into a usage error (exit 2).

    Exit 1 means "the gate found something"; a misspelled ``--fail-on`` must
    not be confused with that, nor crash with a traceback.
    """
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint=option) from exc


def split_csv(value: str) -> list[str]:
    """Split a comma-separated option value, dropping blanks and whitespace."""
    return [s.strip() for s in value.split(",") if s.strip()]


def progress_printer(quiet: bool) -> Callable[[str], None] | None:
    """The engine progress callback: dim lines on stderr, or None when quiet."""
    if quiet:
        return None
    return lambda msg: err_console.print(f"[dim]- {escape(msg)}[/dim]")


def resolve_target(target: str, *, branch: str | None = None) -> ResolvedTarget:
    """Resolve a target string, exiting 2 with a message if that fails."""
    from nephilex.targets import resolve

    try:
        return resolve(target, branch=branch)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc


def resolve_project(target: str, error: str) -> tuple[ResolvedTarget, Project]:
    """Resolve a target that must be source code; exit 2 with ``error`` if not.

    The caller owns the returned :class:`ResolvedTarget` and must call its
    ``cleanup()`` (normally in a ``finally`` block).
    """
    resolved = resolve_target(target)
    if resolved.project is None:
        err_console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(2)
    return resolved, resolved.project


def fail_on_scanner_errors(result: ScanResult, cfg: Config, *, gating: bool) -> None:
    """Exit 1 when scanners crashed in a run that gates (fail closed).

    A crashed scanner contributes no findings, so treating its silence as a
    pass would let a parser crash (possibly provoked by the scanned repo)
    open the gate.
    """
    if result.errors and cfg.errors_fail_gate(gating):
        print_scanner_failure(result)
        raise typer.Exit(1)


def posture_result(url: str, *, quiet: bool) -> ScanResult:
    """Build a ScanResult from live posture checks against a URL."""
    from datetime import datetime, timezone

    from nephilex.dynamic import probe

    started = datetime.now(timezone.utc)
    result = ScanResult(
        target=url, started_at=started, nephilex_version=__version__, scanners_run=["posture"]
    )
    for finding in probe(url):
        result.add(finding)
    result.findings = result.sorted_findings()
    result.finished_at = datetime.now(timezone.utc)
    result.project_summary = {"name": url, "origin": "url", "target": url}
    return result


def apply_baseline(
    result: ScanResult,
    baseline: Path,
    *,
    quiet: bool,
    project: Project | None = None,
    cfg: Config | None = None,
) -> None:
    """Drop findings already present in a baseline report (diff-aware scanning).

    With ``project`` and ``cfg``, the findings the baseline hid are recorded
    in ``.nephilex/audit.log`` (kind ``baseline``) under the same rule as every
    other suppression: a trusted, local project with the audit log on.
    """
    from nephilex.baseline import BaselineError, filter_new, load_fingerprints

    try:
        known = load_fingerprints(baseline)
    except BaselineError as exc:
        err_console.print(f"[yellow]Baseline ignored:[/yellow] {exc}")
        return
    before = result.findings
    result.findings, suppressed = filter_new(result.findings, known)
    if not quiet:
        err_console.print(
            f"[dim]- Baseline: {suppressed} known finding(s) suppressed, "
            f"{len(result.findings)} new.[/dim]"
        )
    if project is None or cfg is None or not suppressed:
        return
    if not cfg.trust_project_config or project.origin != "local":
        return
    from nephilex.audit import record_baseline

    kept = {id(f) for f in result.findings}
    hidden = [f for f in before if id(f) not in kept]
    outcome = record_baseline(project.root, baseline, hidden, config=cfg)
    if outcome.warning:
        err_console.print(f"[yellow]Audit log:[/yellow] {escape(outcome.warning)}")


def apply_diff(result: ScanResult, root: Path, ref_spec: str, *, quiet: bool) -> None:
    """Keep only findings that touch the git diff described by ``ref_spec``."""
    from nephilex.analysis.diff_scan import filter_findings, resolve_diff
    from nephilex.remediation import git_ops

    if not git_ops.is_git_repo(root):
        err_console.print(f"[yellow]Diff ignored:[/yellow] not a git repository ({root}).")
        return
    try:
        scope = resolve_diff(root, ref_spec)
    except Exception as exc:
        err_console.print(f"[yellow]Diff ignored:[/yellow] {exc}")
        return
    if scope.empty:
        if not quiet:
            err_console.print("[dim]- Diff: no changed files in range.[/dim]")
        result.findings = []
        return
    result.findings, suppressed = filter_findings(result.findings, scope)
    if not quiet:
        err_console.print(
            f"[dim]- Diff ({ref_spec}): {suppressed} finding(s) outside changed "
            f"lines/files suppressed, {len(result.findings)} in scope.[/dim]"
        )


def build_config(
    *,
    config,
    project,
    trust_remote=False,
    config_from_ref=None,
    scanners,
    profile=None,
    exclude,
    ai_provider,
    ai_model,
    no_ai,
    attack_sim,
    patches,
    min_severity,
    fail_on,
    fail_on_error: bool | None = None,
    reachability=False,
    symbol_reachability=False,
    no_cache=False,
    verify_secrets=False,
    secrets_history=False,
    diff_ref: str | None = None,
    include_ignored: bool = False,
) -> Config:
    """Load the project config and apply the ``nephilex scan`` flags on top of it."""
    cfg = load_project_config(
        project, config, trust_remote=trust_remote, config_from_ref=config_from_ref
    )
    if profile:
        from nephilex.profiles import PROFILES, apply_profile

        key = profile.strip().lower()
        selected = apply_profile(profile)
        if selected:
            cfg.scanners = selected
        prof = PROFILES.get(key)
        if prof and prof.fail_on_error:
            cfg.fail_on_error = True
        if prof and not prof.cache:
            cfg.cache = False
    if reachability or symbol_reachability:
        dep = cfg.scanner_options.setdefault("dependencies", {})
        dep["reachability"] = True
        if symbol_reachability:
            dep["symbol_reachability"] = True
    if diff_ref:
        cfg.scanner_options.setdefault("dependency-diff", {})["ref"] = diff_ref
        if cfg.scanners and "dependency-diff" not in cfg.scanners:
            cfg.scanners = [*cfg.scanners, "dependency-diff"]
    if no_cache:
        cfg.cache = False
    if include_ignored:
        cfg.include_ignored = True
    if verify_secrets:
        cfg.scanner_options.setdefault("secrets", {})["verify"] = True
    if secrets_history:
        cfg.scanner_options.setdefault("secrets", {})["history"] = True
    if scanners:
        cfg.scanners = split_csv(scanners)
    if exclude:
        cfg.exclude_scanners = split_csv(exclude)
    if ai_provider:
        cfg.ai.provider = ai_provider
    if ai_model:
        cfg.ai.model = ai_model
    if no_ai:
        cfg.ai.enabled = False
    if attack_sim:
        cfg.attack_simulation = True
    if patches:
        cfg.generate_patches = True
    if min_severity:
        cfg.min_severity = cli_severity(min_severity, "--min-severity")
    if fail_on:
        cfg.fail_on = cli_severity(fail_on, "--fail-on")
    if fail_on_error is not None:
        cfg.fail_on_error = fail_on_error
    return cfg
