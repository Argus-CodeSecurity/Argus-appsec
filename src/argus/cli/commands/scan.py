"""``argus scan``: the full scan with every report format and gate."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.markup import escape

from argus.cli._common import (
    CONFIG_FROM_REF_HELP,
    apply_baseline,
    apply_diff,
    build_config,
    cli_severity,
    posture_result,
    progress_printer,
    resolve_target,
)
from argus.cli._console import err_console
from argus.cli.output import emit, print_posture, print_scanner_failure
from argus.reporting.posture import evaluate_posture


def scan(
    target: str = typer.Argument(
        ..., help="Local path, git URL (GitHub/GitLab/Bitbucket), or website URL."
    ),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to an .argus.yml config file."
    ),
    scanners: str | None = typer.Option(
        None, "--scanners", "-s", help="Comma-separated scanners to run (default: all)."
    ),
    exclude: str | None = typer.Option(None, "--exclude", help="Comma-separated scanners to skip."),
    fmt: list[str] = typer.Option(
        ["table"],
        "--format",
        "-f",
        help="Output format(s): table, json, sarif, gitlab, markdown, html, csv, "
        "badge, vex. Repeatable.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write reports here. A directory writes one file per non-table format.",
    ),
    ai_provider: str | None = typer.Option(
        None, "--ai-provider", help="heuristic | anthropic | openai | ollama."
    ),
    ai_model: str | None = typer.Option(None, "--ai-model", help="Model id override."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI enrichment entirely."),
    attack_sim: bool = typer.Option(False, "--attack-sim", help="Enable Attack Simulation Mode."),
    patches: bool = typer.Option(
        False, "--patches", help="Generate (and where possible verify) fix patches."
    ),
    reachability: bool = typer.Option(
        False,
        "--reachability",
        help="Experimental: annotate dependency findings with import-level "
        "reachability (Python + npm). Findings for packages never imported "
        "are deprioritized, not suppressed.",
    ),
    symbol_reachability: bool = typer.Option(
        False,
        "--symbol-reachability",
        help="Experimental tier-2: Python symbol-level reachability when OSV "
        "provides affected symbol hints (implies --reachability).",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Re-analyze every file instead of reusing cached findings for unchanged files.",
    ),
    verify_secrets: bool = typer.Option(
        False,
        "--verify-secrets",
        help="Opt-in: make read-only calls to confirm detected secrets are LIVE "
        "(GitHub, Stripe, Slack, OpenAI, Google). Local targets only; makes "
        "network requests with the candidate credential. Off by default and "
        "never in CI templates.",
    ),
    secrets_history: bool = typer.Option(
        False,
        "--secrets-history",
        help="Also scan git history for secrets in past commits (even if later "
        "deleted). Needs a local git repository with full history.",
    ),
    track_secrets: Path | None = typer.Option(
        None,
        "--track-secrets",
        help="Path to a rotation-state file. With --verify-secrets, flags live "
        "secrets that have gone unrotated across scans (found but not rotated).",
    ),
    min_severity: str | None = typer.Option(
        None, "--min-severity", help="Report findings at/above this severity."
    ),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit non-zero if any finding is at/above this severity."
    ),
    fail_on_error: bool | None = typer.Option(
        None,
        "--fail-on-error/--no-fail-on-error",
        help="Exit non-zero if any scanner crashes. Default: on whenever --fail-on "
        "(or fail_on in config) is set, since a crashed scanner reports "
        "nothing; --no-fail-on-error opts out.",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help="Path to a previous Argus JSON report; report only findings not in it.",
    ),
    diff_ref: str | None = typer.Option(
        None,
        "--diff",
        help="Git ref range (e.g. origin/main...HEAD); report only findings on "
        "changed lines or dependency manifests. Local git repo required.",
    ),
    branch: str | None = typer.Option(
        None, "--branch", "-b", help="Branch to clone for remote targets."
    ),
    trust_remote_config: bool = typer.Option(
        False,
        "--trust-remote-config",
        help="Load .argus.yml from a cloned remote repo (off by default; a scanned "
        "repo is untrusted and could suppress its own findings).",
    ),
    config_from_ref: str | None = typer.Option(
        None,
        "--config-from-ref",
        metavar="REF",
        help=CONFIG_FROM_REF_HELP,
    ),
    live_target: str | None = typer.Option(
        None,
        "--live-target",
        help="Also run safe, read-only runtime posture checks against this URL "
        "(security headers, cookie flags, TLS, exposed paths). Non-intrusive; "
        "only assess systems you are authorized to test.",
    ),
    audience: str | None = typer.Option(
        None,
        "--audience",
        help="Re-render the console output for a reader: dev, exec, or auditor "
        "(only affects the default table output, not -f formats).",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="Scan profile: fast, standard, deep, supply-chain, ci, production.",
    ),
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Shorthand for --profile deep (maximum scanner depth).",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Scan a target and report findings."""
    from argus.core.engine import ScanEngine

    # Reject a misspelled threshold before doing any work (e.g. cloning).
    for value, flag in ((min_severity, "--min-severity"), (fail_on, "--fail-on")):
        if value:
            cli_severity(value, flag)

    # Resolve the target first so config discovery can use the project root.
    resolved = resolve_target(target, branch=branch)

    # A URL target runs the posture layer directly (no source to analyze).
    if resolved.web is not None:
        if not quiet:
            err_console.print(
                "[dim]· Running read-only posture checks (not full DAST). "
                "Only assess systems you are authorized to test.[/dim]"
            )
        result = posture_result(resolved.web.url, quiet=quiet)
        if min_severity:
            floor = cli_severity(min_severity, "--min-severity")
            result.findings = [f for f in result.findings if f.severity >= floor]
        emit(result, fmt, output)
        gated = fail_on is not None and result.highest_severity() >= cli_severity(
            fail_on, "--fail-on"
        )
        raise typer.Exit(1 if gated else 0)

    project = resolved.project
    assert project is not None

    # Secret verification makes authenticated calls with the found credential.
    # Doing that with secrets pulled from someone else's cloned repo is out of
    # scope by design, restrict it to local targets.
    if verify_secrets and project.origin != "local":
        err_console.print(
            "[red]Error:[/red] --verify-secrets is only allowed for local targets "
            "(it would otherwise make authenticated calls with credentials from a "
            "remote repository you do not control)."
        )
        resolved.cleanup()
        raise typer.Exit(2)

    # Security: a cloned remote repository is untrusted. Do not honor a config file
    # discovered inside it (which could disable scanners or hide paths) unless the
    # user explicitly opts in. An explicit --config path is always respected.
    if project.origin != "local" and not trust_remote_config and not quiet:
        err_console.print(
            "[dim]· Ignoring any .argus.yml inside the remote repo "
            "(use --trust-remote-config to honor it).[/dim]"
        )

    try:
        profile_name = "deep" if deep else profile
        if profile_name and scanners:
            err_console.print(
                "[red]Error:[/red] use either --profile/--deep or --scanners, not both."
            )
            raise typer.Exit(2)
        cfg = build_config(
            config=config,
            project=project,
            trust_remote=trust_remote_config,
            config_from_ref=config_from_ref,
            scanners=scanners,
            profile=profile_name,
            exclude=exclude,
            ai_provider=ai_provider,
            ai_model=ai_model,
            no_ai=no_ai,
            attack_sim=attack_sim,
            patches=patches,
            min_severity=min_severity,
            fail_on=fail_on,
            fail_on_error=fail_on_error,
            reachability=reachability,
            symbol_reachability=symbol_reachability,
            no_cache=no_cache,
            verify_secrets=verify_secrets,
            secrets_history=secrets_history,
            diff_ref=diff_ref,
        )

        if live_target:
            cfg.dast_url = live_target

        engine = ScanEngine(cfg, progress=progress_printer(quiet))
        result = engine.scan(project)

        # Optional runtime posture layer alongside the static scan.
        if live_target:
            if not quiet:
                err_console.print(
                    f"[dim]· Posture checks against {escape(live_target)} "
                    "(read-only; authorized use only)[/dim]"
                )
            result.project_summary["live_target"] = live_target
            from argus.dynamic import probe

            for finding in probe(live_target):
                result.add(finding)
            result.findings = result.sorted_findings()

        if baseline is not None:
            apply_baseline(result, baseline, quiet=quiet)

        if diff_ref is not None:
            apply_diff(result, project.root, diff_ref, quiet=quiet)

        if track_secrets is not None:
            from argus.scanners.secret_rotation import track_rotations

            track_rotations(result.findings, track_secrets)

        emit(result, fmt, output, audience=audience)

        if not quiet and ("table" in fmt or audience):
            print_posture(result, cfg.fail_on)

        if engine.should_fail(result):
            if engine.fails_on_errors(result):
                # The table output already listed each failure.
                print_scanner_failure(result, details="table" not in fmt)
            else:
                err_console.print(
                    f"[red]Failing:[/red] findings at/above "
                    f"{cfg.fail_on.label if cfg.fail_on else ''}."
                )
                if quiet:
                    s = evaluate_posture(result, cfg.fail_on)
                    err_console.print(f"[dim]{s.headline}[/dim]")
            raise typer.Exit(1)
    except FileNotFoundError as exc:
        # e.g. an explicit --config path that doesn't exist. Fail loudly with a
        # clear message rather than silently scanning with default gating.
        err_console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc
    finally:
        resolved.cleanup()
