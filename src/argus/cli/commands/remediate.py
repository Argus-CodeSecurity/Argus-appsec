"""Acting on findings: ``argus fix``, ``argus review`` and ``argus learn``."""

from __future__ import annotations

from pathlib import Path

import typer

from argus.cli._common import (
    CONFIG_FROM_REF_HELP,
    apply_baseline,
    cli_severity,
    fail_on_scanner_errors,
    progress_printer,
    resolve_project,
    split_csv,
)
from argus.cli._console import console, err_console
from argus.cli.output import print_fix_outcome
from argus.core.config import load_project_config


def fix(
    target: str = typer.Argument(".", help="Local path to a git repository to fix."),
    open_pr: bool = typer.Option(
        False, "--open-pr", help="Push the branch and open a pull request."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be fixed without writing anything."
    ),
    branch: str | None = typer.Option(
        None,
        "--branch",
        help="Name of the branch to create "
        "(default: argus/security-fixes, or argus/auto-fixes with --auto).",
    ),
    base: str | None = typer.Option(
        None, "--base", help="Base branch for the PR (default: repo's default branch)."
    ),
    auto: bool = typer.Option(
        False,
        "--auto",
        help="Autonomy Rung 3: apply only the curated auto-tier rules (safe, "
        "reversible), for unattended use. Still lands on a revertible PR. "
        "Graduate more rules via autofix.graduate in .argus.yml.",
    ),
    include_unverified: bool = typer.Option(
        False,
        "--include-unverified",
        help="Also apply fixes that did not self-verify (review carefully).",
    ),
    force_branch: bool = typer.Option(
        False, "--force-branch", help="Reuse/overwrite the branch if it already exists."
    ),
    annotate_pr: bool = typer.Option(
        False,
        "--annotate-pr",
        help="Post inline review comments on the opened PR explaining each fix "
        "(GitHub only; implies --open-pr).",
    ),
    scanners_opt: str | None = typer.Option(
        None, "--scanners", "-s", help="Comma-separated scanners to run (default: all)."
    ),
    min_severity: str | None = typer.Option(
        None, "--min-severity", help="Only consider findings at/above this severity."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
    no_verify: bool = typer.Option(
        False,
        "--no-verify",
        help="Skip the repository's git commit hooks when committing fixes (hooks run by default).",
    ),
) -> None:
    """Scan a repo, apply Argus's deterministic fixes on a branch, and open a PR.

    Only fixes Argus can generate and verify locally are applied (e.g. unsafe
    yaml.load, weak hashes, shell=True). Nothing is pushed or opened unless you
    pass --open-pr; --open-pr requires a GITHUB_TOKEN or GITLAB_TOKEN.
    """
    from argus.core.engine import ScanEngine
    from argus.remediation.pullrequest import FixOptions, run_fix_workflow

    resolved, project = resolve_project(target, "`argus fix` requires a local code path.")
    try:
        # Only honor an in-repo config for local targets (a cloned repo is untrusted).
        cfg = load_project_config(project)
        # Fixing is deterministic; AI enrichment is not needed and slows things down.
        cfg.ai.enabled = False
        if scanners_opt:
            cfg.scanners = split_csv(scanners_opt)
        if min_severity:
            cfg.min_severity = cli_severity(min_severity, "--min-severity")

        result = ScanEngine(cfg, progress=progress_printer(quiet)).scan(project)

        only_rules = None
        if auto:
            from argus.remediation.rewrites import auto_apply_rules

            only_rules = auto_apply_rules(cfg)
            if not quiet:
                err_console.print(
                    f"[dim]· Auto mode: {len(only_rules)} auto-tier rule(s) eligible "
                    f"({', '.join(sorted(only_rules)) or 'none'}).[/dim]"
                )
        branch_name = branch or ("argus/auto-fixes" if auto else "argus/security-fixes")

        options = FixOptions(
            branch=branch_name,
            base=base,
            open_pr=open_pr or annotate_pr,
            include_unverified=include_unverified,
            dry_run=dry_run,
            force_branch=force_branch,
            annotate=annotate_pr,
            only_rules=only_rules,
            no_verify=no_verify,
        )
        outcome = run_fix_workflow(project, result.findings, options)
        print_fix_outcome(outcome, open_pr=open_pr or annotate_pr, dry_run=dry_run)

        if outcome.error:
            raise typer.Exit(1)
    finally:
        resolved.cleanup()


def review(
    target: str = typer.Argument(".", help="Local path to the checked-out repository."),
    pr: int | None = typer.Option(
        None, "--pr", help="Pull-request number (default: from GITHUB_REF in CI)."
    ),
    base: str | None = typer.Option(
        None,
        "--base",
        help="Base ref to diff against for changed lines "
        "(default: origin/$GITHUB_BASE_REF in CI, else the default branch).",
    ),
    repo: str | None = typer.Option(
        None,
        "--repo",
        help="owner/repo (default: from GITHUB_REPOSITORY or the git remote).",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help="Previous Argus JSON report; comment only on findings not in it.",
    ),
    scanners_opt: str | None = typer.Option(
        None, "--scanners", "-s", help="Comma-separated scanners to run (default: all)."
    ),
    exclude: str | None = typer.Option(None, "--exclude", help="Comma-separated scanners to skip."),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to an .argus.yml config file."
    ),
    config_from_ref: str | None = typer.Option(
        None,
        "--config-from-ref",
        metavar="REF",
        help=CONFIG_FROM_REF_HELP,
    ),
    min_severity: str | None = typer.Option(
        None, "--min-severity", help="Only review findings at/above this severity."
    ),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit non-zero if a reviewed finding is at/above this."
    ),
    fail_on_error: bool | None = typer.Option(
        None,
        "--fail-on-error/--no-fail-on-error",
        help="Exit non-zero if any scanner crashes (default: on when --fail-on is set).",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be posted without calling GitHub."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Scan a checked-out PR and post the findings it introduces as review comments.

    Diff-aware: with --baseline (a scan of the base branch), only findings the PR
    introduces are posted; findings on changed lines are inline, the rest go in
    the review summary. Reads GITHUB_TOKEN to post. Designed to run in CI on
    pull_request events, but works locally with --pr/--repo/--base.
    """
    import os
    import re

    from argus.core.engine import ScanEngine
    from argus.remediation import git_ops, pr_review
    from argus.remediation.hosting import HostingError, RepoRef, parse_remote

    threshold = cli_severity(fail_on, "--fail-on") if fail_on else None

    # --- resolve repo, PR number, and base ref (flags, then CI env) ---
    ref: RepoRef | None = None
    if repo and "/" in repo:
        owner, _, name = repo.partition("/")
        ref = RepoRef(host="github", owner=owner, repo=name, web_base="https://github.com")
    elif os.environ.get("GITHUB_REPOSITORY", "").count("/") == 1:
        owner, _, name = os.environ["GITHUB_REPOSITORY"].partition("/")
        ref = RepoRef(host="github", owner=owner, repo=name, web_base="https://github.com")

    pr_number = pr
    if pr_number is None:
        m = re.search(r"refs/pull/(\d+)/", os.environ.get("GITHUB_REF", ""))
        if m:
            pr_number = int(m.group(1))

    resolved, project = resolve_project(target, "`argus review` needs a local repository path.")

    if ref is None:
        remote = git_ops.remote_url(project.root)
        ref = parse_remote(remote) if remote else None
    if ref is None or pr_number is None:
        err_console.print(
            "[red]Error:[/red] could not determine the repository and PR number. "
            "Pass --repo owner/repo and --pr N (they are auto-detected in GitHub Actions)."
        )
        resolved.cleanup()
        raise typer.Exit(2)

    base_ref = base or (
        f"origin/{os.environ['GITHUB_BASE_REF']}"
        if os.environ.get("GITHUB_BASE_REF")
        else git_ops.default_branch(project.root)
    )

    try:
        cfg = load_project_config(project, config, config_from_ref=config_from_ref)
        cfg.ai.enabled = False  # a PR gate should be fast and deterministic
        if scanners_opt:
            cfg.scanners = split_csv(scanners_opt)
        if exclude:
            cfg.exclude_scanners = split_csv(exclude)
        if min_severity:
            cfg.min_severity = cli_severity(min_severity, "--min-severity")

        result = ScanEngine(cfg, progress=progress_printer(quiet)).scan(project)

        if baseline is not None:
            apply_baseline(result, baseline, quiet=quiet)

        changed = pr_review.changed_lines(project.root, base_ref)
        try:
            outcome = pr_review.post_findings_review(
                ref,
                pr_number,
                result.findings,
                changed=changed,
                dry_run=dry_run,
                path_prefix=git_ops.path_prefix(project.root),
            )
        except HostingError as exc:
            err_console.print(f"[red]Could not post review:[/red] {exc}")
            raise typer.Exit(1) from exc

        verb = "Would post" if dry_run else ("Posted" if outcome.posted else "No")
        console.print(
            f"[green]{verb} review:[/green] {outcome.total} finding(s) "
            f"({outcome.inline} inline, {outcome.leftover} in summary) on PR #{pr_number}."
        )

        if fail_on_error is not None:
            cfg.fail_on_error = fail_on_error
        fail_on_scanner_errors(result, cfg, gating=threshold is not None)
        if threshold is not None and result.highest_severity() >= threshold and result.findings:
            err_console.print(f"[red]Failing:[/red] findings at/above {threshold.label}.")
            raise typer.Exit(1)
    finally:
        resolved.cleanup()


def learn(
    target: str = typer.Argument(".", help="Local path or repo URL to learn from."),
    scanners_opt: str | None = typer.Option(
        None, "--scanners", "-s", help="Comma-separated scanners to run (default: all)."
    ),
    min_severity: str | None = typer.Option(
        None, "--min-severity", help="Only teach findings at/above this severity."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Explain each finding in your own code as a hands-on security lesson."""
    from argus.core.engine import ScanEngine
    from argus.reporting.learn import render_lessons

    resolved, project = resolve_project(target, "`argus learn` needs a local code path or repo.")
    try:
        cfg = load_project_config(project)
        cfg.attack_simulation = True  # richer exploit walkthroughs make better lessons
        if scanners_opt:
            cfg.scanners = split_csv(scanners_opt)
        if min_severity:
            cfg.min_severity = cli_severity(min_severity, "--min-severity")
        result = ScanEngine(cfg, progress=progress_printer(quiet)).scan(project)
        console.print(render_lessons(result))
    finally:
        resolved.cleanup()
