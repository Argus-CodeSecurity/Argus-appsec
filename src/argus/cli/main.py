"""The ``argus`` command-line interface.

Commands:

* ``argus scan TARGET``: run a full scan and write reports.
* ``argus fix TARGET``: apply verified fixes on a branch and open a pull request.
* ``argus sbom TARGET``: generate a CycloneDX or SPDX SBOM from dependency manifests.
* ``argus supply-chain TARGET``: malicious deps, dependency diffs, provenance.
* ``argus cicd TARGET``: CI/CD pipeline security (GitHub Actions, GitLab CI).
* ``argus container TARGET``: Docker, Compose, and container runtime checks.
* ``argus cloud TARGET``: cloud IaC patterns (AWS, Azure, GCP).
* ``argus infrastructure TARGET``: all infrastructure scanners in one pass.
* ``argus inventory TARGET``: export static asset inventory (Phase 4 foundation).
* ``argus drift BEFORE AFTER``: configuration drift between two reports.
* ``argus policy check TARGET``: evaluate security policies against scan findings.
* ``argus scanners``: list available scanners.
* ``argus reporters``: list available report formats.
* ``argus providers``: list AI providers and their availability.
* ``argus init``: write a starter ``.argus.yml``.
* ``argus version``: print the version.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from argus import __version__
from argus.core.config import Config
from argus.core.models import ScanResult, Severity
from argus.core.plugin import registry
from argus.plugins import register_builtins
from argus.reporting.posture import evaluate_posture

# On Windows the legacy console defaults to a codepage that can't encode the
# Unicode Argus uses in reports/tables. Force UTF-8 on the streams when possible.
for _stream in (sys.stdout, sys.stderr):
    with contextlib.suppress(AttributeError, ValueError):
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

# Register built-in plugins up front so `scanners`/`reporters`/`providers` work
# even without the entry-point discovery path (e.g. running from source).
register_builtins()

app = typer.Typer(
    name="argus",
    help="Argus, an open-source AI Security Engineer.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"Argus v{__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show the Argus version and exit.",
        callback=_version_callback, is_eager=True,
    ),
) -> None:
    """Argus, an open-source AI Security Engineer.

    Point Argus at a codebase and it finds vulnerabilities, explains them, and can
    fix them. Run `argus COMMAND --help` for details on any command, e.g.
    `argus scan --help`.
    """


@app.command()
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
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated scanners to skip."
    ),
    fmt: list[str] = typer.Option(
        ["table"], "--format", "-f",
        help="Output format(s): table, json, sarif, gitlab, markdown, html, csv, "
             "badge, vex. Repeatable.",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o",
        help="Write reports here. A directory writes one file per non-table format.",
    ),
    ai_provider: str | None = typer.Option(
        None, "--ai-provider", help="heuristic | anthropic | openai | ollama."
    ),
    ai_model: str | None = typer.Option(None, "--ai-model", help="Model id override."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI enrichment entirely."),
    attack_sim: bool = typer.Option(
        False, "--attack-sim", help="Enable Attack Simulation Mode."
    ),
    patches: bool = typer.Option(
        False, "--patches", help="Generate (and where possible verify) fix patches."
    ),
    reachability: bool = typer.Option(
        False, "--reachability",
        help="Experimental: annotate dependency findings with import-level "
             "reachability (Python + npm). Findings for packages never imported "
             "are deprioritized, not suppressed.",
    ),
    symbol_reachability: bool = typer.Option(
        False, "--symbol-reachability",
        help="Experimental tier-2: Python symbol-level reachability when OSV "
             "provides affected symbol hints (implies --reachability).",
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache",
        help="Re-analyze every file instead of reusing cached findings for "
             "unchanged files.",
    ),
    verify_secrets: bool = typer.Option(
        False, "--verify-secrets",
        help="Opt-in: make read-only calls to confirm detected secrets are LIVE "
             "(GitHub, Stripe, Slack, OpenAI, Google). Local targets only; makes "
             "network requests with the candidate credential. Off by default and "
             "never in CI templates.",
    ),
    secrets_history: bool = typer.Option(
        False, "--secrets-history",
        help="Also scan git history for secrets in past commits (even if later "
             "deleted). Needs a local git repository with full history.",
    ),
    track_secrets: Path | None = typer.Option(
        None, "--track-secrets",
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
        None, "--fail-on-error/--no-fail-on-error",
        help="Exit non-zero if any scanner crashes (default: off; on for ci/production profiles).",
    ),
    baseline: Path | None = typer.Option(
        None, "--baseline",
        help="Path to a previous Argus JSON report; report only findings not in it.",
    ),
    diff_ref: str | None = typer.Option(
        None, "--diff",
        help="Git ref range (e.g. origin/main...HEAD); report only findings on "
             "changed lines or dependency manifests. Local git repo required.",
    ),
    branch: str | None = typer.Option(
        None, "--branch", "-b", help="Branch to clone for remote targets."
    ),
    trust_remote_config: bool = typer.Option(
        False, "--trust-remote-config",
        help="Load .argus.yml from a cloned remote repo (off by default; a scanned "
             "repo is untrusted and could suppress its own findings).",
    ),
    live_target: str | None = typer.Option(
        None, "--live-target",
        help="Also run safe, read-only runtime posture checks against this URL "
             "(security headers, cookie flags, TLS, exposed paths). Non-intrusive; "
             "only assess systems you are authorized to test.",
    ),
    audience: str | None = typer.Option(
        None, "--audience",
        help="Re-render the console output for a reader: dev, exec, or auditor "
             "(only affects the default table output, not -f formats).",
    ),
    profile: str | None = typer.Option(
        None, "--profile",
        help="Scan profile: fast, standard, deep, supply-chain, ci, production.",
    ),
    deep: bool = typer.Option(
        False, "--deep",
        help="Shorthand for --profile deep (maximum scanner depth).",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Scan a target and report findings."""
    from argus.core.engine import ScanEngine
    from argus.targets import resolve

    # Resolve the target first so config discovery can use the project root.
    try:
        resolved = resolve(target, branch=branch)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc

    # A URL target runs the posture layer directly (no source to analyze).
    if resolved.web is not None:
        if not quiet:
            err_console.print(
                "[dim]· Running read-only posture checks (not full DAST). "
                "Only assess systems you are authorized to test.[/dim]"
            )
        result = _posture_result(resolved.web.url, quiet=quiet)
        if min_severity:
            floor = Severity.parse(min_severity)
            result.findings = [f for f in result.findings if f.severity >= floor]
        _emit(result, fmt, output)
        gated = fail_on is not None and result.highest_severity() >= \
            Severity.parse(fail_on)
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
    trust_project_config = project.origin == "local" or trust_remote_config
    if project.origin != "local" and not trust_remote_config and not quiet:
        err_console.print(
            "[dim]· Ignoring any .argus.yml inside the remote repo "
            "(use --trust-remote-config to honor it).[/dim]"
        )

    try:
        profile_name = "deep" if deep else profile
        if profile_name and scanners:
            err_console.print("[red]Error:[/red] use either --profile/--deep or --scanners, not both.")
            raise typer.Exit(2)
        cfg = _build_config(
            config=config,
            project_root=project.root if trust_project_config else None,
            scanners=scanners,
            profile=profile_name,
            exclude=exclude, ai_provider=ai_provider, ai_model=ai_model, no_ai=no_ai,
            attack_sim=attack_sim, patches=patches, min_severity=min_severity,
            fail_on=fail_on, fail_on_error=fail_on_error,
            reachability=reachability, symbol_reachability=symbol_reachability,
            no_cache=no_cache,
            verify_secrets=verify_secrets, secrets_history=secrets_history,
            diff_ref=diff_ref,
        )
        # A cloned, untrusted repo must not inject scanner rules via its own
        # in-repo .argus/rules directory; gate it on the same trust decision.
        cfg.trust_project_config = trust_project_config

        if live_target:
            cfg.scanner_options.setdefault("dast", {})["url"] = live_target

        progress = None if quiet else (lambda msg: err_console.print(f"[dim]· {escape(msg)}[/dim]"))
        engine = ScanEngine(cfg, progress=progress)
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
            _apply_baseline(result, baseline, quiet=quiet)

        if diff_ref is not None:
            _apply_diff(result, project.root, diff_ref, quiet=quiet)

        if track_secrets is not None:
            from argus.scanners.secret_rotation import track_rotations
            track_rotations(result.findings, track_secrets)

        _emit(result, fmt, output, audience=audience)

        if not quiet and ("table" in fmt or audience):
            _print_posture(result, cfg.fail_on)

        if engine.should_fail(result):
            if cfg.fail_on_error and result.errors:
                err_console.print(
                    "[red]Failing:[/red] one or more scanners failed "
                    f"({', '.join(result.scanners_failed or ['unknown'])})."
                )
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


@app.command()
def sbom(
    target: str = typer.Argument(
        ".", help="Local path or git URL to generate an SBOM for."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write SBOM JSON here (stdout if omitted)."
    ),
    fmt: str = typer.Option(
        "cyclonedx", "--format", "-f",
        help="SBOM format: cyclonedx or spdx.",
    ),
    name: str | None = typer.Option(
        None, "--name", help="Application name in the SBOM metadata."
    ),
    version: str = typer.Option("0.0.0", "--version", help="Application version."),
    diff_ref: str | None = typer.Option(
        None, "--diff",
        help="Compare SBOM to a git ref (e.g. origin/main...HEAD); emit component diff JSON.",
    ),
    branch: str | None = typer.Option(None, "--branch", "-b", help="Branch for remote targets."),
    push: bool = typer.Option(False, "--push", help="Upload the SBOM to Argus Cloud."),
    url: str | None = typer.Option(
        None, "--url", help="Argus Cloud base URL (or set ARGUS_CLOUD_URL)."
    ),
    token: str | None = typer.Option(
        None, "--token", help="Cloud API token (or set ARGUS_CLOUD_TOKEN)."
    ),
) -> None:
    """Generate an SBOM (CycloneDX or SPDX) or diff components vs a git ref."""
    import json

    from argus.remediation import git_ops
    from argus.sbom import build_cyclonedx, build_spdx, diff_components, diff_to_dict
    from argus.targets import resolve

    fmt_norm = fmt.strip().lower()
    if fmt_norm not in ("cyclonedx", "spdx"):
        err_console.print(f"[red]Error:[/red] unknown SBOM format {fmt!r} (use cyclonedx or spdx).")
        raise typer.Exit(2)

    try:
        resolved = resolve(target, branch=branch)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if resolved.project is None:
        err_console.print("[red]Error:[/red] SBOM generation requires a source repository.")
        raise typer.Exit(2)
    try:
        if diff_ref:
            if not git_ops.is_git_repo(resolved.project.root):
                err_console.print("[red]Error:[/red] --diff requires a local git repository.")
                raise typer.Exit(2)
            changes = diff_components(resolved.project.root, diff_ref)
            doc = diff_to_dict(changes, ref_spec=diff_ref)
            text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
            if output:
                output.write_text(text, encoding="utf-8")
            else:
                console.print(text, end="")
            s = doc["summary"]
            console.print(
                f"[green]SBOM diff:[/green] +{s['added']} ~{s['changed']} -{s['removed']}"
            )
            return

        builder = build_cyclonedx if fmt_norm == "cyclonedx" else build_spdx
        doc = builder(resolved.project, name=name, version=version)
        text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
        count = len(doc.get("components", doc.get("packages", []))) - (
            1 if fmt_norm == "spdx" else 0
        )
        if push:
            import os

            from argus.upload import PushError, push_sbom

            cloud_url = url or os.environ.get("ARGUS_CLOUD_URL")
            cloud_token = token or os.environ.get("ARGUS_CLOUD_TOKEN")
            if not cloud_url or not cloud_token:
                err_console.print(
                    "[red]Error:[/red] --push requires --url/--token or "
                    "ARGUS_CLOUD_URL/ARGUS_CLOUD_TOKEN."
                )
                raise typer.Exit(2)
            target_label = str(resolved.project.root)
            try:
                resp = push_sbom(
                    doc,
                    target=target_label,
                    fmt=fmt_norm,
                    url=cloud_url,
                    token=cloud_token,
                )
            except PushError as exc:
                err_console.print(f"[red]Error:[/red] {exc}")
                raise typer.Exit(1) from exc
            console.print(f"[green]SBOM uploaded[/green] ({count} components) → {resp.get('url', 'dashboard')}")
        elif output:
            output.write_text(text, encoding="utf-8")
            console.print(f"[green]SBOM written:[/green] {output} ({count} components)")
        else:
            console.print(text, end="")
    finally:
        resolved.cleanup()


@app.command()
def dependencies(
    target: str = typer.Argument(".", help="Local git repository path."),
    diff_ref: str | None = typer.Option(
        None, "--diff",
        help="Git ref range (e.g. origin/main...HEAD) to compare dependency changes.",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write JSON report here (table to stdout if omitted).",
    ),
    behavior: bool = typer.Option(
        True, "--behavior/--no-behavior",
        help="Fetch npm registry metadata for version-change anomalies (network).",
    ),
) -> None:
    """List dependency changes between git refs (for pull-request review)."""
    import json

    from argus.core.config import Config
    from argus.core.engine import ScanEngine
    from argus.inventory.dependency_diff import diff_packages
    from argus.remediation import git_ops
    from argus.targets import resolve

    if not diff_ref:
        err_console.print("[red]Error:[/red] --diff is required (e.g. origin/main...HEAD).")
        raise typer.Exit(2)

    try:
        resolved = resolve(target)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if resolved.project is None or not git_ops.is_git_repo(resolved.project.root):
        err_console.print("[red]Error:[/red] requires a local git repository.")
        raise typer.Exit(2)

    try:
        changes = diff_packages(resolved.project.root, diff_ref)
        payload = {
            "diff": diff_ref,
            "changes": [
                {
                    "ecosystem": c.ecosystem,
                    "package": c.package,
                    "manifest": c.manifest,
                    "change": c.change,
                    "old_version": c.old_version,
                    "new_version": c.new_version,
                }
                for c in changes
            ],
        }

        behavior_findings = []
        if behavior and changes:
            cfg = Config()
            cfg.scanners = ["dependency-diff"]
            cfg.scanner_options["dependency-diff"] = {
                "ref": diff_ref,
                "behavior": True,
            }
            cfg.ai.enabled = False
            result = ScanEngine(cfg).scan(resolved.project)
            behavior_findings = [
                {
                    "title": f.title,
                    "rule": f.rule_id,
                    "severity": f.severity.label,
                    "location": f.location.as_ref(),
                }
                for f in result.findings
                if f.rule_id == "dependency-diff.behavior-anomaly"
            ]
            payload["behavior_anomalies"] = behavior_findings

        if output:
            output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            console.print(f"[green]Wrote[/green] {len(changes)} change(s) to {output}")
        else:
            table = Table(title=f"Dependency changes ({diff_ref})")
            table.add_column("Change")
            table.add_column("Package")
            table.add_column("Versions")
            table.add_column("Manifest")
            for c in changes:
                vers = f"{c.old_version or 'n/a'} -> {c.new_version or 'n/a'}"
                table.add_row(c.change, c.package, vers, c.manifest)
            console.print(table)
            if behavior_findings:
                err_console.print(
                    f"[yellow]{len(behavior_findings)} behavioral anomal(y/ies) detected.[/yellow]"
                )
    finally:
        resolved.cleanup()


@app.command(name="supply-chain")
def supply_chain_cmd(
    target: str = typer.Argument(".", help="Local git repository path."),
    diff_ref: str | None = typer.Option(
        None, "--diff",
        help="Git ref range for dependency/version analysis (e.g. origin/main...HEAD).",
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON report."),
    behavior: bool = typer.Option(True, "--behavior/--no-behavior", help="npm metadata anomaly checks."),
    sandbox: str = typer.Option(
        "auto", "--sandbox",
        help="Behavioral fetch isolation: auto | host | docker (never installs packages).",
    ),
    auth_map: bool = typer.Option(False, "--auth-map", help="Include endpoint authorization map."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit non-zero on findings at/above severity."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Run supply-chain scanners: malicious packages, typosquats, dependency diffs, provenance."""
    import json

    from argus.analysis.auth_map import build_auth_map
    from argus.core.config import Config
    from argus.core.engine import ScanEngine
    from argus.inventory.dependency_diff import diff_packages
    from argus.remediation import git_ops
    from argus.targets import resolve

    try:
        resolved = resolve(target)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if resolved.project is None:
        err_console.print("[red]Error:[/red] supply-chain requires a source repository.")
        raise typer.Exit(2)

    try:
        cfg = Config()
        cfg.ai.enabled = False
        cfg.scanners = [
            "supply-chain", "dependency-diff", "dependencies", "provenance",
        ]
        cfg.scanner_options["supply-chain"] = {
            "online_intel": True,
        }
        if diff_ref:
            cfg.scanner_options["dependency-diff"] = {
                "ref": diff_ref,
                "behavior": behavior,
                "sandbox": sandbox,
            }
        elif git_ops.is_git_repo(resolved.project.root):
            base = git_ops.default_branch(resolved.project.root)
            cfg.scanner_options["dependency-diff"] = {
                "ref": f"{base}...HEAD",
                "behavior": behavior,
                "sandbox": sandbox,
            }

        progress = None if quiet else (lambda m: err_console.print(f"[dim]· {escape(m)}[/dim]"))
        result = ScanEngine(cfg, progress=progress).scan(resolved.project)

        payload: dict = {
            "findings": len(result.findings),
            "highest_severity": result.highest_severity().label,
            "dependency_changes": [],
            "items": [
                {
                    "rule": f.rule_id,
                    "severity": f.severity.label,
                    "title": f.title,
                    "location": f.location.as_ref(),
                }
                for f in result.findings
            ],
        }
        if git_ops.is_git_repo(resolved.project.root):
            ref = diff_ref or f"{git_ops.default_branch(resolved.project.root)}...HEAD"
            payload["dependency_changes"] = [
                {
                    "ecosystem": c.ecosystem,
                    "package": c.package,
                    "change": c.change,
                    "old_version": c.old_version,
                    "new_version": c.new_version,
                }
                for c in diff_packages(resolved.project.root, ref)
            ]
        if auth_map:
            payload["auth_map"] = [e.to_dict() for e in build_auth_map(resolved.project)]

        if output:
            output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            console.print(f"[green]Supply-chain report:[/green] {output}")
        elif not quiet:
            table = Table(title="Supply-chain findings")
            table.add_column("Severity")
            table.add_column("Rule")
            table.add_column("Title")
            for f in result.sorted_findings()[:50]:
                table.add_row(f.severity.label, f.rule_id, f.title[:60])
            console.print(table)
            if len(result.findings) > 50:
                err_console.print(f"[dim]… and {len(result.findings) - 50} more[/dim]")

        if fail_on and result.highest_severity() >= Severity.parse(fail_on):
            raise typer.Exit(1)
    finally:
        resolved.cleanup()


@app.command()
def secrets(
    target: str = typer.Argument(".", help="Local path or git URL."),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Run secret detection only (source, config, and optional git history via scan flags)."""
    _focused_scan(
        target, ["secrets"], output=output, fail_on=fail_on, quiet=quiet,
        title="Secret findings", config=config,
    )


@app.command()
def iac(
    target: str = typer.Argument(".", help="Local path or git URL."),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Run infrastructure-as-code security checks (Terraform, K8s, CloudFormation)."""
    _focused_scan(
        target, ["iac", "cloud"], output=output, fail_on=fail_on, quiet=quiet,
        title="IaC findings", config=config,
    )


@app.command(name="api")
def api_scan(
    target: str = typer.Argument(".", help="Local path or git URL with OpenAPI specs."),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Analyze OpenAPI/REST API definitions for auth and exposure issues."""
    _focused_scan(
        target, ["api", "authz"], output=output, fail_on=fail_on, quiet=quiet,
        title="API security findings", config=config,
    )


@app.command()
def cicd(
    target: str = typer.Argument(".", help="Local path or git URL to scan."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON report."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit non-zero on findings at/above severity."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Optional .argus.yml path."),
) -> None:
    """Scan CI/CD workflows for risky patterns (GitHub Actions, GitLab CI, Jenkinsfile)."""
    _focused_scan(
        target, ["cicd"], output=output, fail_on=fail_on, quiet=quiet,
        title="CI/CD findings", config=config,
    )


@app.command()
def container(
    target: str = typer.Argument(".", help="Local path or git URL to scan."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON report."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit non-zero on findings at/above severity."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Optional .argus.yml path."),
) -> None:
    """Scan Dockerfiles, Compose files, and container runtime settings."""
    _focused_scan(
        target, ["container", "iac"], output=output, fail_on=fail_on, quiet=quiet,
        title="Container findings", config=config,
    )


@app.command()
def cloud(
    target: str = typer.Argument(".", help="Local path or git URL to scan."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON report."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit non-zero on findings at/above severity."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Optional .argus.yml path."),
) -> None:
    """Scan Terraform and CloudFormation for risky AWS, Azure, and GCP patterns."""
    _focused_scan(
        target, ["cloud", "iac"], output=output, fail_on=fail_on, quiet=quiet,
        title="Cloud configuration findings", config=config,
    )


@app.command()
def infrastructure(
    target: str = typer.Argument(".", help="Local path or git URL to scan."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON report."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit non-zero on findings at/above severity."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Optional .argus.yml path."),
) -> None:
    """Run all infrastructure scanners: CI/CD, containers, cloud, and IaC."""
    _focused_scan(
        target, ["cicd", "container", "cloud", "iac"], output=output, fail_on=fail_on,
        quiet=quiet, title="Infrastructure findings", config=config,
    )


@app.command()
def inventory(
    target: str = typer.Argument(".", help="Local path or git URL to analyze."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON inventory here."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Export static asset inventory: languages, architecture, dependencies, infra files."""
    import json

    from argus.inventory.asset_map import build_inventory
    from argus.targets import resolve

    try:
        resolved = resolve(target)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if resolved.project is None:
        err_console.print("[red]Error:[/red] inventory requires a source repository or local path.")
        raise typer.Exit(2)
    try:
        payload = build_inventory(resolved.project)
        if output:
            output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            console.print(f"[green]Inventory:[/green] {output}")
        else:
            console.print(json.dumps(payload, indent=2))
        if not quiet:
            c = payload["counts"]
            err_console.print(
                f"[dim]· {c['files']} files, {c['dependencies']} dependencies, "
                f"{c['ci_cd_files']} CI/CD, {c['container_files']} container, "
                f"{c['iac_files']} IaC[/dim]"
            )
    finally:
        resolved.cleanup()


@app.command()
def drift(
    before: Path = typer.Argument(..., help="Earlier Argus JSON report or inventory."),
    after: Path = typer.Argument(..., help="Later Argus JSON report or inventory."),
    inventory: bool = typer.Option(
        False, "--inventory",
        help="Compare inventory JSON files (from `argus inventory -o`).",
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write drift JSON here."),
    fail_on: str | None = typer.Option(
        None, "--fail-on",
        help="Exit non-zero if added/changed findings meet this severity (scan mode).",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Detect configuration drift between two scan or inventory snapshots."""
    import json

    from argus.analysis.drift import (
        compare_inventories,
        compare_scans,
        highest_added_severity,
    )

    try:
        before_data = json.loads(before.read_text(encoding="utf-8"))
        after_data = json.loads(after.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        err_console.print(f"[red]Error:[/red] invalid JSON input: {exc}")
        raise typer.Exit(2) from exc

    if inventory or before_data.get("dependencies") is not None and "findings" not in before_data:
        payload = compare_inventories(before_data, after_data)
        if output:
            output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        if not quiet:
            s = payload["summary"]
            table = Table(title="Inventory drift")
            table.add_column("Change")
            table.add_column("Count")
            table.add_row("Dependencies added", str(s["deps_added"]))
            table.add_row("Dependencies removed", str(s["deps_removed"]))
            table.add_row("Dependencies changed", str(s["deps_changed"]))
            table.add_row("Architecture areas changed", str(s["arch_areas_changed"]))
            console.print(table)
        raise typer.Exit(0)

    try:
        before_scan = ScanResult.model_validate(before_data)
        after_scan = ScanResult.model_validate(after_data)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] expected Argus scan JSON: {exc}")
        raise typer.Exit(2) from exc

    report = compare_scans(before_scan, after_scan)
    payload = report.to_dict()
    if output:
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if not quiet:
        s = report.summary()
        table = Table(title="Scan drift (configuration / posture change)")
        table.add_column("Change")
        table.add_column("Count")
        table.add_row("Findings added", str(s["added"]))
        table.add_row("Findings removed", str(s["removed"]))
        table.add_row("Severity escalations", str(s["severity_changed"]))
        console.print(table)
        for item in report.added[:15]:
            err_console.print(
                f"  [red]+[/red] {item.severity} {item.rule_id} {item.title} ({item.location})"
            )
        if len(report.added) > 15:
            err_console.print(f"  [dim]… and {len(report.added) - 15} more added[/dim]")

    if fail_on and highest_added_severity(report) >= Severity.parse(fail_on):
        raise typer.Exit(1)


@app.command()
def watch(
    target: str = typer.Argument(".", help="Local path or git URL to monitor."),
    interval: int = typer.Option(300, "--interval", "-i", help="Seconds between scans."),
    state_dir: Path = typer.Option(
        Path(".argus/watch"), "--state-dir",
        help="Directory for scan snapshots and drift history.",
    ),
    once: bool = typer.Option(False, "--once", help="Run a single cycle and exit."),
    push: bool = typer.Option(False, "--push", help="Upload each scan to Argus Cloud."),
    url: str | None = typer.Option(None, "--url", help="Cloud base URL (or ARGUS_CLOUD_URL)."),
    token: str | None = typer.Option(None, "--token", help="Cloud API token (or ARGUS_CLOUD_TOKEN)."),
    scanners_opt: str | None = typer.Option(None, "--scanners", "-s", help="Comma-separated scanners."),
    config: Path | None = typer.Option(None, "--config", "-c", help="Optional .argus.yml path."),
    fail_on_drift: str | None = typer.Option(
        None, "--fail-on-drift",
        help="Exit non-zero when new/changed findings meet this severity.",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Run periodic scans, track drift locally, and optionally push to Argus Cloud."""
    import os

    from argus.core.engine import ScanEngine
    from argus.targets import resolve
    from argus.upload import PushError, build_ingest_payload, push_result
    from argus.watch import run_watch_loop, state_dir_for

    try:
        resolved = resolve(target)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if resolved.project is None:
        err_console.print("[red]Error:[/red] watch requires a source repository or local path.")
        raise typer.Exit(2)

    cfg = Config.load(path=config, project_root=resolved.project.root if resolved.project.origin == "local" else None)
    cfg.trust_project_config = resolved.project.origin == "local"
    if scanners_opt:
        cfg.scanners = [s.strip() for s in scanners_opt.split(",") if s.strip()]

    drift_floor = Severity.parse(fail_on_drift) if fail_on_drift else None
    store = state_dir_for(target, state_dir)
    cloud_url = url or os.environ.get("ARGUS_CLOUD_URL")
    cloud_token = token or os.environ.get("ARGUS_CLOUD_TOKEN")
    if push and (not cloud_url or not cloud_token):
        err_console.print(
            "[red]Error:[/red] --push requires --url/--token or ARGUS_CLOUD_URL/ARGUS_CLOUD_TOKEN."
        )
        raise typer.Exit(2)

    def scan_once() -> ScanResult:
        proj = resolved.project
        assert proj is not None
        return ScanEngine(cfg).scan(proj)

    def maybe_push(result: ScanResult) -> None:
        if not push:
            return
        payload = build_ingest_payload(result)
        push_result(payload, url=cloud_url, token=cloud_token)  # type: ignore[arg-type]

    def on_cycle(outcome) -> None:
        if quiet:
            return
        counts = outcome.scan.counts_by_severity()
        err_console.print(
            f"[dim]· watch {outcome.snapshot_path.name}: "
            f"{len(outcome.scan.findings)} findings "
            f"({counts.get('critical', 0)} critical)[/dim]"
        )
        if outcome.drift:
            ds = outcome.drift.summary()
            if ds["added"] or ds["severity_changed"]:
                err_console.print(
                    f"[yellow]drift[/yellow] +{ds['added']} added, "
                    f"{ds['severity_changed']} severity changes"
                )

    try:
        code = run_watch_loop(
            scan_fn=scan_once,
            state_dir=store,
            interval_seconds=interval,
            once=once,
            fail_on_drift=drift_floor,
            push_fn=maybe_push if push else None,
            on_cycle=on_cycle,
        )
    except PushError as exc:
        err_console.print(f"[red]Push failed:[/red] {exc}")
        raise typer.Exit(2) from exc
    finally:
        resolved.cleanup()

    if code:
        raise typer.Exit(code)


@app.command()
def agent(
    config: Path = typer.Option(
        Path(".argus/agent.yml"), "--config", "-c",
        help="Agent config file (see examples/agent.yml).",
    ),
    init: bool = typer.Option(False, "--init", help="Write a starter agent config and exit."),
    once: bool = typer.Option(False, "--once", help="Run one cycle across all targets and exit."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Run the server agent: monitor multiple paths on this host on a schedule.

    Designed for cron, systemd, or long-running deployment. Each target is scanned,
    drift is tracked locally, and results can be pushed to Argus Cloud.
    """
    from argus.agent import load_agent_config, run_agent_loop, write_default_agent_config
    from argus.upload import PushError

    if init:
        path = write_default_agent_config(config)
        console.print(f"[green]Agent config:[/green] {path}")
        raise typer.Exit(0)

    try:
        cfg = load_agent_config(config)
    except (OSError, ValueError, FileNotFoundError) as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        err_console.print("[dim]Run `argus agent --init` to create a starter config.[/dim]")
        raise typer.Exit(2) from exc

    if not quiet:
        err_console.print(
            f"[dim]· agent monitoring {len(cfg.targets)} target(s) "
            f"every {cfg.interval}s (host: {cfg.host_label})[/dim]"
        )

    def on_cycle(summary) -> None:
        if quiet:
            return
        err_console.print(
            f"[dim]· agent cycle: {summary.targets_scanned} targets, "
            f"{summary.total_findings} findings[/dim]"
        )

    try:
        code = run_agent_loop(cfg, once=once, on_cycle=on_cycle)
    except PushError as exc:
        err_console.print(f"[red]Push failed:[/red] {exc}")
        raise typer.Exit(2) from exc

    if code:
        raise typer.Exit(code)


baseline_app = typer.Typer(help="Security baseline: gate on new findings only.")
app.add_typer(baseline_app, name="baseline")


@baseline_app.command("create")
def baseline_create(
    target: str = typer.Argument(".", help="Local path or git URL to scan."),
    output: Path = typer.Option(..., "--output", "-o", help="Write baseline JSON here."),
    config: Path | None = typer.Option(None, "--config", "-c"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Scan a target and save the result as a baseline for diff-aware CI gating."""
    from argus.core.engine import ScanEngine
    from argus.targets import resolve

    try:
        resolved = resolve(target)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if resolved.project is None:
        err_console.print("[red]Error:[/red] baseline create requires a source path or repo.")
        raise typer.Exit(2)
    try:
        cfg = Config.load(path=config, project_root=resolved.project.root)
        cfg.trust_project_config = resolved.project.origin == "local"
        progress = None if quiet else (lambda m: err_console.print(f"[dim]· {escape(m)}[/dim]"))
        result = ScanEngine(cfg, progress=progress).scan(resolved.project)
        output.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
        console.print(f"[green]Baseline:[/green] {output} ({len(result.findings)} findings recorded)")
    finally:
        resolved.cleanup()


server_app = typer.Typer(help="Authorized host/server posture (read-only).")
app.add_typer(server_app, name="server")


@server_app.command("scan")
def server_scan(
    label: str | None = typer.Option(None, "--label", help="Host label in reports."),
    fmt: list[str] = typer.Option(["table"], "--format", "-f"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Read-only host posture: listeners, SSH config, and exposure signals."""
    from argus.agent.host_posture import assess_host

    if not quiet:
        err_console.print(
            "[dim]· Read-only host checks on this machine. "
            "Only run on systems you are authorized to assess.[/dim]"
        )
    result = assess_host(label=label)
    _emit(result, fmt, output)
    if fail_on and result.highest_severity() >= Severity.parse(fail_on):
        raise typer.Exit(1)


policy_app = typer.Typer(help="Evaluate security policies against scan findings.")
app.add_typer(policy_app, name="policy")


@policy_app.command("check")
def policy_check(
    target: str = typer.Argument(".", help="Local path or git URL to scan."),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to an .argus.yml with policies:."
    ),
    report: Path | None = typer.Option(
        None, "--report", "-r",
        help="Evaluate policies against an existing Argus JSON report instead of scanning.",
    ),
    scanners_opt: str | None = typer.Option(
        None, "--scanners", "-s", help="Comma-separated scanners (when scanning)."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Run (or load) a scan and evaluate ``policies:`` from config."""
    from argus.core.engine import ScanEngine
    from argus.policy import evaluate
    from argus.targets import resolve

    if report is not None:
        try:
            result = ScanResult.model_validate_json(report.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            err_console.print(f"[red]Error:[/red] invalid report: {exc}")
            raise typer.Exit(2) from exc
        cfg = Config.load(path=config)
    else:
        try:
            resolved = resolve(target)
        except Exception as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(2) from exc
        if resolved.project is None:
            err_console.print("[red]Error:[/red] policy check requires a source repository.")
            raise typer.Exit(2)
        try:
            cfg = Config.load(path=config, project_root=resolved.project.root)
            cfg.ai.enabled = False
            if scanners_opt:
                cfg.scanners = [s.strip() for s in scanners_opt.split(",") if s.strip()]
            progress = None if quiet else (
                lambda m: err_console.print(f"[dim]· {escape(m)}[/dim]")
            )
            result = ScanEngine(cfg, progress=progress).scan(resolved.project)
        finally:
            resolved.cleanup()

    if not cfg.policies:
        err_console.print(
            "[yellow]No policies configured.[/yellow] Add a ``policies:`` section "
            "to .argus.yml (see docs/configuration.md)."
        )
        raise typer.Exit(0)

    outcome = evaluate(result, cfg.policies)
    if outcome.blocked:
        table = Table(title="Policy violations (BLOCK)")
        table.add_column("Policy", style="bold")
        table.add_column("Finding")
        table.add_column("Location")
        for v in outcome.blocked:
            table.add_row(v.policy_id, v.finding.title, v.finding.location.as_ref())
        console.print(table)
    if outcome.warned and not quiet:
        for v in outcome.warned:
            err_console.print(
                f"[yellow]WARN[/yellow] {v.policy_id}: {v.finding.title} "
                f"({v.finding.location.as_ref()})"
            )

    if outcome.passed:
        console.print("[green]Policy check passed[/green] "
                      f"({len(outcome.violations)} warning(s)).")
        raise typer.Exit(0)
    err_console.print(
        f"[red]Policy check failed:[/red] {len(outcome.blocked)} blocking violation(s)."
    )
    raise typer.Exit(1)


@app.command()
def fix(
    target: str = typer.Argument(".", help="Local path to a git repository to fix."),
    open_pr: bool = typer.Option(
        False, "--open-pr", help="Push the branch and open a pull request."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be fixed without writing anything."
    ),
    branch: str | None = typer.Option(
        None, "--branch", help="Name of the branch to create "
        "(default: argus/security-fixes, or argus/auto-fixes with --auto)."
    ),
    base: str | None = typer.Option(
        None, "--base", help="Base branch for the PR (default: repo's default branch)."
    ),
    auto: bool = typer.Option(
        False, "--auto",
        help="Autonomy Rung 3: apply only the curated auto-tier rules (safe, "
             "reversible), for unattended use. Still lands on a revertible PR. "
             "Graduate more rules via autofix.graduate in .argus.yml.",
    ),
    include_unverified: bool = typer.Option(
        False, "--include-unverified",
        help="Also apply fixes that did not self-verify (review carefully).",
    ),
    force_branch: bool = typer.Option(
        False, "--force-branch", help="Reuse/overwrite the branch if it already exists."
    ),
    annotate_pr: bool = typer.Option(
        False, "--annotate-pr",
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
) -> None:
    """Scan a repo, apply Argus's deterministic fixes on a branch, and open a PR.

    Only fixes Argus can generate and verify locally are applied (e.g. unsafe
    yaml.load, weak hashes, shell=True). Nothing is pushed or opened unless you
    pass --open-pr; --open-pr requires a GITHUB_TOKEN or GITLAB_TOKEN.
    """
    from argus.core.engine import ScanEngine
    from argus.remediation.pullrequest import FixOptions, run_fix_workflow
    from argus.targets import resolve

    try:
        resolved = resolve(target)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if resolved.project is None:
        err_console.print("[red]Error:[/red] `argus fix` requires a local code path.")
        raise typer.Exit(2)

    project = resolved.project
    try:
        # Only honor an in-repo config for local targets (a cloned repo is untrusted).
        cfg = Config.load(
            project_root=project.root if project.origin == "local" else None
        )
        cfg.trust_project_config = project.origin == "local"
        # Fixing is deterministic; AI enrichment is not needed and slows things down.
        cfg.ai.enabled = False
        if scanners_opt:
            cfg.scanners = [s.strip() for s in scanners_opt.split(",") if s.strip()]
        if min_severity:
            cfg.min_severity = Severity.parse(min_severity)

        progress = None if quiet else (lambda msg: err_console.print(f"[dim]· {escape(msg)}[/dim]"))
        result = ScanEngine(cfg, progress=progress).scan(project)

        only_rules = None
        if auto:
            from argus.remediation.rewrites import auto_apply_rules
            only_rules = auto_apply_rules(cfg)
            if not quiet:
                err_console.print(
                    f"[dim]· Auto mode: {len(only_rules)} auto-tier rule(s) eligible "
                    f"({', '.join(sorted(only_rules)) or 'none'}).[/dim]")
        branch_name = branch or ("argus/auto-fixes" if auto else "argus/security-fixes")

        options = FixOptions(
            branch=branch_name, base=base, open_pr=open_pr or annotate_pr,
            include_unverified=include_unverified, dry_run=dry_run,
            force_branch=force_branch, annotate=annotate_pr, only_rules=only_rules,
        )
        outcome = run_fix_workflow(project, result.findings, options)
        _print_fix_outcome(outcome, open_pr=open_pr or annotate_pr, dry_run=dry_run)

        if outcome.error:
            raise typer.Exit(1)
    finally:
        resolved.cleanup()


@app.command()
def scanners() -> None:
    """List available scanners."""
    table = Table(title="Scanners", show_lines=False)
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Description")
    for name, cls in sorted(registry.scanners().items()):
        table.add_row(name, cls.category, escape(cls.description))
    console.print(table)


@app.command()
def reporters() -> None:
    """List available report formats."""
    table = Table(title="Reporters")
    table.add_column("Name", style="bold")
    table.add_column("Extension")
    table.add_column("Description")
    for name, cls in sorted(registry.reporters().items()):
        table.add_row(name, cls.extension, escape(cls.description))
    console.print(table)


@app.command()
def mcp() -> None:
    """Run Argus as an MCP server (stdio) so AI coding agents can call it.

    Speaks the Model Context Protocol over stdin/stdout and exposes an
    ``argus_scan`` tool. Point an MCP-capable client at ``argus mcp``.
    """
    from argus.mcp.server import run_stdio

    run_stdio()


@app.command()
def push(
    target: str = typer.Argument(
        ".", help="Local path, git URL, or website URL to scan and upload."
    ),
    report: Path | None = typer.Option(
        None, "--report",
        help="Upload an existing Argus JSON report instead of scanning "
             "('-' reads it from stdin, e.g. `argus scan . -f json | argus push --report -`).",
    ),
    url: str | None = typer.Option(
        None, "--url", help="Argus Cloud base URL (or set ARGUS_CLOUD_URL)."
    ),
    token: str | None = typer.Option(
        None, "--token", help="Cloud API token (or set ARGUS_CLOUD_TOKEN)."
    ),
    scanners_opt: str | None = typer.Option(
        None, "--scanners", "-s", help="Comma-separated scanners to run (default: all)."
    ),
    min_severity: str | None = typer.Option(
        None, "--min-severity",
        help="Only upload findings at/above this severity (default: low).",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Scan a target (or read a report) and upload the result to Argus Cloud.

    Sends only finding metadata (rule, severity, title, location, CWE), never
    source or secret values, to the cloud's `/api/scans` ingest endpoint so the
    scan shows up in your dashboard's history and trends.
    """
    import os

    from argus.upload import PushError, build_ingest_payload, push_result

    cloud_url = url or os.environ.get("ARGUS_CLOUD_URL")
    cloud_token = token or os.environ.get("ARGUS_CLOUD_TOKEN")
    if not cloud_url or not cloud_token:
        err_console.print(
            "[red]Error:[/red] provide the cloud URL and API token via --url/--token "
            "or the ARGUS_CLOUD_URL/ARGUS_CLOUD_TOKEN environment variables."
        )
        raise typer.Exit(2)

    floor = Severity.parse(min_severity) if min_severity else Severity.LOW

    if report is not None:
        raw = sys.stdin.read() if str(report) == "-" else report.read_text(encoding="utf-8")
        try:
            result = ScanResult.model_validate_json(raw)
        except Exception as exc:
            err_console.print(f"[red]Error:[/red] not a valid Argus JSON report: {exc}")
            raise typer.Exit(2) from exc
    else:
        from argus.core.engine import ScanEngine
        from argus.targets import resolve

        try:
            resolved = resolve(target)
        except Exception as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(2) from exc
        try:
            if resolved.web is not None:
                result = _posture_result(resolved.web.url, quiet=quiet)
            else:
                project = resolved.project
                assert project is not None
                cfg = Config.load(
                    project_root=project.root if project.origin == "local" else None
                )
                cfg.trust_project_config = project.origin == "local"
                if scanners_opt:
                    cfg.scanners = [s.strip() for s in scanners_opt.split(",") if s.strip()]
                progress = None if quiet else (
                    lambda m: err_console.print(f"[dim]· {escape(m)}[/dim]"))
                result = ScanEngine(cfg, progress=progress).scan(project)
        finally:
            resolved.cleanup()

    payload = build_ingest_payload(result, min_severity=floor)
    try:
        resp = push_result(payload, url=cloud_url, token=cloud_token)
    except PushError as exc:
        err_console.print(f"[red]Upload failed:[/red] {exc}")
        raise typer.Exit(1) from exc

    dash = resp.get("url")
    location = (cloud_url.rstrip("/") + dash) if isinstance(dash, str) and dash else ""
    console.print(
        f"[green]Uploaded {len(payload['findings'])} finding(s) to Argus Cloud.[/green]"
        + (f"\nView it at {location}" if location else "")
    )


@app.command()
def review(
    target: str = typer.Argument(".", help="Local path to the checked-out repository."),
    pr: int | None = typer.Option(
        None, "--pr", help="Pull-request number (default: from GITHUB_REF in CI)."
    ),
    base: str | None = typer.Option(
        None, "--base",
        help="Base ref to diff against for changed lines "
             "(default: origin/$GITHUB_BASE_REF in CI, else the default branch).",
    ),
    repo: str | None = typer.Option(
        None, "--repo",
        help="owner/repo (default: from GITHUB_REPOSITORY or the git remote).",
    ),
    baseline: Path | None = typer.Option(
        None, "--baseline",
        help="Previous Argus JSON report; comment only on findings not in it.",
    ),
    scanners_opt: str | None = typer.Option(
        None, "--scanners", "-s", help="Comma-separated scanners to run (default: all)."
    ),
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated scanners to skip."
    ),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to an .argus.yml config file."
    ),
    min_severity: str | None = typer.Option(
        None, "--min-severity", help="Only review findings at/above this severity."
    ),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit non-zero if a reviewed finding is at/above this."
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
    from argus.targets import resolve

    # --- resolve repo, PR number, and base ref (flags, then CI env) ---
    ref: RepoRef | None = None
    if repo and "/" in repo:
        owner, _, name = repo.partition("/")
        ref = RepoRef(host="github", owner=owner, repo=name,
                      web_base="https://github.com")
    elif os.environ.get("GITHUB_REPOSITORY", "").count("/") == 1:
        owner, _, name = os.environ["GITHUB_REPOSITORY"].partition("/")
        ref = RepoRef(host="github", owner=owner, repo=name,
                      web_base="https://github.com")

    pr_number = pr
    if pr_number is None:
        m = re.search(r"refs/pull/(\d+)/", os.environ.get("GITHUB_REF", ""))
        if m:
            pr_number = int(m.group(1))

    try:
        resolved = resolve(target)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if resolved.project is None:
        err_console.print("[red]Error:[/red] `argus review` needs a local repository path.")
        raise typer.Exit(2)
    project = resolved.project

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
        if os.environ.get("GITHUB_BASE_REF") else git_ops.default_branch(project.root)
    )

    try:
        cfg = Config.load(
            path=config,
            project_root=project.root if project.origin == "local" else None,
        )
        cfg.trust_project_config = project.origin == "local"
        cfg.ai.enabled = False  # a PR gate should be fast and deterministic
        if scanners_opt:
            cfg.scanners = [s.strip() for s in scanners_opt.split(",") if s.strip()]
        if exclude:
            cfg.exclude_scanners = [s.strip() for s in exclude.split(",") if s.strip()]
        if min_severity:
            cfg.min_severity = Severity.parse(min_severity)

        progress = None if quiet else (lambda m: err_console.print(f"[dim]· {escape(m)}[/dim]"))
        result = ScanEngine(cfg, progress=progress).scan(project)

        if baseline is not None:
            _apply_baseline(result, baseline, quiet=quiet)

        changed = pr_review.changed_lines(project.root, base_ref)
        try:
            outcome = pr_review.post_findings_review(
                ref, pr_number, result.findings, changed=changed, dry_run=dry_run
            )
        except HostingError as exc:
            err_console.print(f"[red]Could not post review:[/red] {exc}")
            raise typer.Exit(1) from exc

        verb = "Would post" if dry_run else ("Posted" if outcome.posted else "No")
        console.print(
            f"[green]{verb} review:[/green] {outcome.total} finding(s) "
            f"({outcome.inline} inline, {outcome.leftover} in summary) on PR #{pr_number}."
        )

        if fail_on and result.findings:
            floor = Severity.parse(fail_on)
            if max(f.severity for f in result.findings) >= floor:
                err_console.print(f"[red]Failing:[/red] findings at/above {floor.label}.")
                raise typer.Exit(1)
    finally:
        resolved.cleanup()


@app.command()
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
    from argus.targets import resolve

    try:
        resolved = resolve(target)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if resolved.project is None:
        err_console.print("[red]Error:[/red] `argus learn` needs a local code path or repo.")
        raise typer.Exit(2)

    project = resolved.project
    try:
        cfg = Config.load(
            project_root=project.root if project.origin == "local" else None
        )
        cfg.trust_project_config = project.origin == "local"
        cfg.attack_simulation = True  # richer exploit walkthroughs make better lessons
        if scanners_opt:
            cfg.scanners = [s.strip() for s in scanners_opt.split(",") if s.strip()]
        if min_severity:
            cfg.min_severity = Severity.parse(min_severity)
        progress = None if quiet else (lambda m: err_console.print(f"[dim]· {escape(m)}[/dim]"))
        result = ScanEngine(cfg, progress=progress).scan(project)
        console.print(render_lessons(result))
    finally:
        resolved.cleanup()


@app.command()
def providers() -> None:
    """List AI providers and whether each is currently usable."""
    table = Table(title="AI providers")
    table.add_column("Name", style="bold")
    table.add_column("Location")
    table.add_column("Default model")
    table.add_column("Available")
    for name, cls in sorted(registry.ai_providers().items()):
        loc = "remote" if cls.is_remote else "local"
        ok = "[green]yes[/green]" if cls.is_available() else "[dim]no[/dim]"
        table.add_row(name, loc, escape(cls.default_model or "-"), ok)
    console.print(table)
    console.print("[dim]Argus defaults to 'heuristic' (offline) if the requested "
                  "provider is unavailable.[/dim]")


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", help="Address to bind."),
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on."),
) -> None:
    """Launch the web dashboard (scan history and trends).

    Requires the dashboard extra: pip install "argus-appsec[dashboard]".
    """
    try:
        from argus.dashboard.app import serve
    except ImportError as exc:
        err_console.print(
            "[red]The dashboard needs extra dependencies.[/red] Install them with:\n"
            '  pip install "argus-appsec[dashboard]"'
        )
        raise typer.Exit(1) from exc
    console.print(f"Argus dashboard on [bold]http://{host}:{port}[/bold]  (Ctrl+C to stop)")
    serve(host=host, port=port)


@app.command()
def init(
    path: Path = typer.Argument(Path(".argus.yml"), help="Where to write the config."),
) -> None:
    """Write a starter .argus.yml configuration file."""
    if path.exists():
        err_console.print(f"[yellow]{path} already exists; not overwriting.[/yellow]")
        raise typer.Exit(1)
    path.write_text(_STARTER_CONFIG, encoding="utf-8")
    console.print(f"[green]Wrote {path}.[/green] Edit it to tune your scans.")


@app.command()
def version() -> None:
    """Print the Argus version."""
    console.print(f"Argus v{__version__}")


# --- helpers ---------------------------------------------------------------
def _posture_result(url: str, *, quiet: bool) -> ScanResult:
    """Build a ScanResult from live posture checks against a URL."""
    from datetime import datetime, timezone

    from argus.dynamic import probe

    started = datetime.now(timezone.utc)
    result = ScanResult(target=url, started_at=started, argus_version=__version__,
                        scanners_run=["posture"])
    for finding in probe(url):
        result.add(finding)
    result.findings = result.sorted_findings()
    result.finished_at = datetime.now(timezone.utc)
    result.project_summary = {"name": url, "origin": "url", "target": url}
    return result


def _apply_baseline(result: ScanResult, baseline: Path, *, quiet: bool) -> None:
    """Drop findings already present in a baseline report (diff-aware scanning)."""
    from argus.baseline import BaselineError, filter_new, load_fingerprints

    try:
        known = load_fingerprints(baseline)
    except BaselineError as exc:
        err_console.print(f"[yellow]Baseline ignored:[/yellow] {exc}")
        return
    result.findings, suppressed = filter_new(result.findings, known)
    if not quiet:
        err_console.print(
            f"[dim]· Baseline: {suppressed} known finding(s) suppressed, "
            f"{len(result.findings)} new.[/dim]"
        )


def _apply_diff(result: ScanResult, root: Path, ref_spec: str, *, quiet: bool) -> None:
    """Keep only findings that touch the git diff described by ``ref_spec``."""
    from argus.analysis.diff_scan import filter_findings, resolve_diff
    from argus.remediation import git_ops

    if not git_ops.is_git_repo(root):
        err_console.print(
            "[yellow]Diff ignored:[/yellow] not a git repository "
            f"({root})."
        )
        return
    try:
        scope = resolve_diff(root, ref_spec)
    except Exception as exc:
        err_console.print(f"[yellow]Diff ignored:[/yellow] {exc}")
        return
    if scope.empty:
        if not quiet:
            err_console.print("[dim]· Diff: no changed files in range.[/dim]")
        result.findings = []
        return
    result.findings, suppressed = filter_findings(result.findings, scope)
    if not quiet:
        err_console.print(
            f"[dim]· Diff ({ref_spec}): {suppressed} finding(s) outside changed "
            f"lines/files suppressed, {len(result.findings)} in scope.[/dim]"
        )


def _focused_scan(
    target: str,
    scanners: list[str],
    *,
    output: Path | None = None,
    fail_on: str | None = None,
    quiet: bool = False,
    title: str = "Findings",
    config: Path | None = None,
) -> None:
    """Run a subset of scanners and print or write a JSON summary."""
    import json

    from argus.core.engine import ScanEngine
    from argus.targets import resolve

    try:
        resolved = resolve(target)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if resolved.project is None:
        err_console.print("[red]Error:[/red] requires a source repository or local path.")
        raise typer.Exit(2)

    try:
        cfg = Config.load(path=config, project_root=resolved.project.root)
        cfg.ai.enabled = False
        cfg.scanners = scanners
        progress = None if quiet else (
            lambda m: err_console.print(f"[dim]· {escape(m)}[/dim]")
        )
        result = ScanEngine(cfg, progress=progress).scan(resolved.project)

        payload = {
            "scanners": scanners,
            "findings": len(result.findings),
            "highest_severity": result.highest_severity().label,
            "items": [
                {
                    "rule": f.rule_id,
                    "severity": f.severity.label,
                    "title": f.title,
                    "location": f.location.as_ref(),
                }
                for f in result.sorted_findings()
            ],
        }

        if output:
            output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            console.print(f"[green]Report:[/green] {output} ({len(result.findings)} finding(s))")
        elif not quiet:
            table = Table(title=title)
            table.add_column("Severity")
            table.add_column("Rule")
            table.add_column("Title")
            table.add_column("Location")
            for f in result.sorted_findings()[:50]:
                table.add_row(
                    f.severity.label, f.rule_id, f.title[:50], f.location.as_ref(),
                )
            console.print(table)
            if len(result.findings) > 50:
                err_console.print(f"[dim]… and {len(result.findings) - 50} more[/dim]")
            elif not result.findings:
                console.print("[green]No findings.[/green]")

        if fail_on and result.highest_severity() >= Severity.parse(fail_on):
            raise typer.Exit(1)
    finally:
        resolved.cleanup()


def _build_config(*, config, project_root, scanners, profile=None, exclude, ai_provider, ai_model,
                  no_ai, attack_sim, patches, min_severity, fail_on,
                  fail_on_error: bool | None = None,
                  reachability=False, symbol_reachability=False, no_cache=False,
                  verify_secrets=False, secrets_history=False, diff_ref: str | None = None) -> Config:
    cfg = Config.load(path=config, project_root=project_root)
    if profile:
        from argus.profiles import PROFILES, apply_profile
        key = profile.strip().lower()
        selected = apply_profile(profile)
        if selected:
            cfg.scanners = selected
        prof = PROFILES.get(key)
        if prof and prof.fail_on_error:
            cfg.fail_on_error = True
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
    if verify_secrets:
        cfg.scanner_options.setdefault("secrets", {})["verify"] = True
    if secrets_history:
        cfg.scanner_options.setdefault("secrets", {})["history"] = True
    if scanners:
        cfg.scanners = [s.strip() for s in scanners.split(",") if s.strip()]
    if exclude:
        cfg.exclude_scanners = [s.strip() for s in exclude.split(",") if s.strip()]
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
        cfg.min_severity = Severity.parse(min_severity)
    if fail_on:
        cfg.fail_on = Severity.parse(fail_on)
    if fail_on_error is not None:
        cfg.fail_on_error = fail_on_error
    return cfg


def _print_fix_outcome(outcome, *, open_pr: bool, dry_run: bool) -> None:
    report = outcome.applied
    if report.fixes:
        table = Table(title="Fixes" + (" (dry run)" if dry_run else ""))
        table.add_column("File", style="bold")
        table.add_column("Line", justify="right")
        table.add_column("Rule", style="dim")
        table.add_column("Verified", justify="center")
        for f in report.fixes:
            table.add_row(escape(f.path), str(f.line), escape(f.rule_id),
                          "[green]yes[/green]" if f.verified else "[yellow]no[/yellow]")
        console.print(table)
    else:
        console.print("[yellow]No deterministic fixes were applicable to these "
                      "findings.[/yellow]")

    for msg in outcome.messages:
        console.print(f"[dim]· {escape(msg)}[/dim]")

    if outcome.pull_request:
        console.print(Panel(f"[green]Pull request opened:[/green]\n"
                            f"{outcome.pull_request.url}", border_style="green"))
    elif outcome.committed and not open_pr:
        console.print("[green]Fixes committed to the branch.[/green] "
                      "Add --open-pr to push and open a pull request.")

    if outcome.error:
        err_console.print(f"[red]Stopped:[/red] {outcome.error}")


def _emit(result: ScanResult, formats: list[str], output: Path | None,
          audience: str | None = None) -> None:
    from argus.security import SECURITY_DISCLAIMER
    result.project_summary.setdefault("disclaimer", SECURITY_DISCLAIMER)
    # Count file-bound formats (everything except the console table) so we know
    # whether a single -o file path is enough or we must disambiguate by extension.
    file_formats = [f for f in formats if f != "table"]
    if output is None and len(file_formats) > 1:
        err_console.print(
            "[red]Error:[/red] multiple machine-readable -f formats require -o "
            "(a directory or path); writing them all to stdout would concatenate "
            "and corrupt the streams."
        )
        raise typer.Exit(2)
    treat_as_dir = output is not None and (
        output.is_dir() or (output.suffix == "" and not output.exists())
    )

    for fmt in formats:
        if fmt == "table":
            if audience:
                from argus.reporting.audience import render_for_audience
                console.print(render_for_audience(result, audience))
            else:
                _print_table(result)
            continue
        cls = registry.reporters().get(fmt)
        if cls is None:
            available = ", ".join(["table", *sorted(registry.reporters())])
            err_console.print(
                f"[red]Error:[/red] unknown format {fmt!r}. "
                f"Available: {available}."
            )
            raise typer.Exit(2)
        rendered = cls().render(result)
        extension = cls().extension
        if output is None:
            # Write raw to stdout, never through Rich, which would soft-wrap and
            # corrupt machine-readable formats (JSON/SARIF/CSV) when piped.
            sys.stdout.write(rendered)
            if not rendered.endswith("\n"):
                sys.stdout.write("\n")
        elif treat_as_dir:
            output.mkdir(parents=True, exist_ok=True)
            dest = output / f"argus-report.{extension}"
            dest.write_text(rendered, encoding="utf-8")
            console.print(f"[green]Wrote {dest}[/green]")
        elif len(file_formats) > 1:
            # A single file path was given for several formats: keep the stem and
            # give each format its own extension (report.html, report.sarif, ...).
            dest = output.with_suffix(f".{extension}")
            dest.write_text(rendered, encoding="utf-8")
            console.print(f"[green]Wrote {dest}[/green]")
        else:
            output.write_text(rendered, encoding="utf-8")
            console.print(f"[green]Wrote {output}[/green]")


def _print_table(result: ScanResult) -> None:
    if result.errors:
        for err in result.errors:
            err_console.print(f"[yellow]Scanner failed:[/yellow] {escape(err)}")

    findings = result.sorted_findings()
    counts = result.counts_by_severity()

    summary = " · ".join(f"{label}: {n}" for label, n in counts.items())
    console.print(Panel(
        f"[bold]{result.project_summary.get('name', result.target)}[/bold]\n"
        f"Aggregate risk: [bold]{result.aggregate_risk()}/100[/bold]   "
        f"Findings: [bold]{len(findings)}[/bold]\n{summary}",
        title="Argus scan", border_style="cyan",
    ))

    if not findings:
        if result.errors:
            console.print("[yellow]No findings, but one or more scanners failed.[/yellow]")
        else:
            console.print("[green]No findings at or above the configured severity.[/green]")
        return

    table = Table(show_lines=False)
    table.add_column("Sev", style="bold")
    table.add_column("Risk", justify="right")
    table.add_column("Title")
    table.add_column("Location", style="dim")
    table.add_column("Rule", style="dim")

    colors = {
        Severity.CRITICAL: "red", Severity.HIGH: "orange3",
        Severity.MEDIUM: "yellow", Severity.LOW: "blue", Severity.INFO: "white",
    }
    for f in findings:
        c = colors.get(f.severity, "white")
        table.add_row(
            f"[{c}]{f.severity.label}[/{c}]",
            str(f.risk_score()),
            escape(f.title),
            escape(f.location.as_ref()),
            escape(f.rule_id),
        )
    console.print(table)


def _print_posture(result: ScanResult, fail_on: Severity | None) -> None:
    from argus.reporting.posture import render_posture_panel

    summary = evaluate_posture(result, fail_on)
    border = {
        "pass": "green",
        "clean": "green",
        "review": "yellow",
        "fail": "red",
    }[summary.status.value]
    console.print(Panel(
        render_posture_panel(summary),
        title="Security posture",
        border_style=border,
    ))


def _print_scan_warnings(result: ScanResult) -> None:
    """Print scanner failures (always, including when table output is skipped)."""
    for err in result.errors:
        err_console.print(f"[yellow]Scanner failed:[/yellow] {escape(err)}")


_STARTER_CONFIG = """\
# Argus configuration. See docs/configuration.md for all options.

# Scanners to run (empty = all applicable).
scanners: []
exclude_scanners: []

# Extra path globs to ignore (added to built-in ignores).
exclude_paths: []

# Minimum severity to report: info | low | medium | high | critical
min_severity: info

# Fail the process (non-zero exit) if any finding is at/above this severity.
# Useful in CI. Leave empty to never fail on findings.
fail_on: ""

# Security policies (evaluated by ``argus policy check``).
policies:
  - id: block-critical
    when:
      severity: critical
    action: block
  - id: block-secrets
    when:
      scanner: secrets
    action: block

# Flagship educational feature: safe, sandboxed attack demonstrations.
attack_simulation: false

# Generate (and where possible verify) fix patches.
generate_patches: false

ai:
  # heuristic (offline, no key) | anthropic | openai | ollama (local)
  provider: heuristic
  model: ""
  enabled: true
  temperature: 0.0
  max_tokens: 1500

# Per-scanner options.
scanner_options:
  secrets:
    entropy: true
    entropy_threshold: 4.0
"""


def _load_plugin_commands() -> None:
    """Let installed add-on packages contribute CLI commands.

    Each entry point in the ``argus.commands`` group is a callable that receives
    the Typer ``app`` and registers one or more commands on it. This is how
    optional/commercial add-ons (for example the Kubernetes assessment package)
    add a subcommand without the core shipping or depending on their code. A
    failing plugin is skipped with a warning; it never breaks the core CLI.
    """
    from importlib import metadata

    try:
        eps = metadata.entry_points(group="argus.commands")
    except Exception:  # pragma: no cover - environment dependent
        return
    for ep in eps:
        try:
            ep.load()(app)
        except Exception as exc:  # pragma: no cover - defensive
            import warnings
            warnings.warn(f"Failed to load Argus command plugin {ep.name!r}: {exc}",
                          stacklevel=2)


_load_plugin_commands()


if __name__ == "__main__":  # pragma: no cover
    app()
