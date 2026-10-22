"""Supply-chain commands: ``sbom``, ``dependencies`` and ``supply-chain``."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

import typer
from rich.markup import escape
from rich.table import Table

from argus.cli._common import (
    cli_severity,
    fail_on_scanner_errors,
    progress_printer,
    resolve_project,
    resolve_target,
)
from argus.cli._console import console, err_console
from argus.cli.output import write_stdout

_T = TypeVar("_T")


def _diff_or_exit(diff: Callable[[Path, str], _T], root: Path, ref_spec: str) -> _T:
    """Run a ref-range diff; an invalid or unknown ref is a usage error (exit 2).

    The diff helpers raise ValueError for a ref git does not know or one that
    looks like an option. That is the operator's input, so it gets a one-line
    message, not a traceback.
    """
    try:
        return diff(root, ref_spec)
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc


def sbom(
    target: str = typer.Argument(".", help="Local path or git URL to generate an SBOM for."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write SBOM JSON here (stdout if omitted)."
    ),
    fmt: str = typer.Option(
        "cyclonedx",
        "--format",
        "-f",
        help="SBOM format: cyclonedx or spdx.",
    ),
    name: str | None = typer.Option(None, "--name", help="Application name in the SBOM metadata."),
    version: str = typer.Option("0.0.0", "--version", help="Application version."),
    diff_ref: str | None = typer.Option(
        None,
        "--diff",
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

    fmt_norm = fmt.strip().lower()
    if fmt_norm not in ("cyclonedx", "spdx"):
        err_console.print(f"[red]Error:[/red] unknown SBOM format {fmt!r} (use cyclonedx or spdx).")
        raise typer.Exit(2)

    resolved = resolve_target(target, branch=branch)
    if resolved.project is None:
        err_console.print("[red]Error:[/red] SBOM generation requires a source repository.")
        raise typer.Exit(2)
    try:
        if diff_ref:
            if not git_ops.is_git_repo(resolved.project.root):
                err_console.print("[red]Error:[/red] --diff requires a local git repository.")
                raise typer.Exit(2)
            changes = _diff_or_exit(diff_components, resolved.project.root, diff_ref)
            doc = diff_to_dict(changes, ref_spec=diff_ref)
            text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
            if output:
                output.write_text(text, encoding="utf-8")
            else:
                write_stdout(text)
            s = doc["summary"]
            # The summary goes to stderr when the JSON is on stdout, so the
            # stream stays parseable.
            (console if output else err_console).print(
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
            console.print(
                f"[green]SBOM uploaded[/green] ({count} components): {resp.get('url', 'dashboard')}"
            )
        elif output:
            output.write_text(text, encoding="utf-8")
            console.print(f"[green]SBOM written:[/green] {output} ({count} components)")
        else:
            write_stdout(text)
    finally:
        resolved.cleanup()


def dependencies(
    target: str = typer.Argument(".", help="Local git repository path."),
    diff_ref: str | None = typer.Option(
        None,
        "--diff",
        help="Git ref range (e.g. origin/main...HEAD) to compare dependency changes.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write JSON report here (table to stdout if omitted).",
    ),
    behavior: bool = typer.Option(
        True,
        "--behavior/--no-behavior",
        help="Fetch npm registry metadata for version-change anomalies (network).",
    ),
) -> None:
    """List dependency changes between git refs (for pull-request review)."""
    import json

    from argus.core.config import Config
    from argus.core.engine import ScanEngine
    from argus.inventory.dependency_diff import diff_packages
    from argus.remediation import git_ops

    if not diff_ref:
        err_console.print("[red]Error:[/red] --diff is required (e.g. origin/main...HEAD).")
        raise typer.Exit(2)

    resolved = resolve_target(target)
    if resolved.project is None or not git_ops.is_git_repo(resolved.project.root):
        err_console.print("[red]Error:[/red] requires a local git repository.")
        raise typer.Exit(2)

    try:
        changes = _diff_or_exit(diff_packages, resolved.project.root, diff_ref)
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


def supply_chain_cmd(
    target: str = typer.Argument(".", help="Local git repository path."),
    diff_ref: str | None = typer.Option(
        None,
        "--diff",
        help="Git ref range for dependency/version analysis (e.g. origin/main...HEAD).",
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON report."),
    behavior: bool = typer.Option(
        True, "--behavior/--no-behavior", help="npm metadata anomaly checks."
    ),
    sandbox: str = typer.Option(
        "auto",
        "--sandbox",
        help="Behavioral fetch isolation: auto | host | docker (never installs packages).",
    ),
    auth_map: bool = typer.Option(False, "--auth-map", help="Include endpoint authorization map."),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit non-zero on findings at/above severity."
    ),
    fail_on_error: bool | None = typer.Option(
        None,
        "--fail-on-error/--no-fail-on-error",
        help="Exit non-zero if any scanner crashes (default: on when --fail-on is set).",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Run supply-chain scanners: malicious packages, typosquats, dependency diffs, provenance."""
    import json

    from argus.analysis.auth_map import build_auth_map
    from argus.core.config import Config
    from argus.core.engine import ScanEngine
    from argus.inventory.dependency_diff import diff_packages
    from argus.remediation import git_ops

    threshold = cli_severity(fail_on, "--fail-on") if fail_on else None
    resolved, project = resolve_project(target, "supply-chain requires a source repository.")

    try:
        cfg = Config()
        cfg.trust_project_config = project.origin == "local"
        cfg.fail_on_error = fail_on_error
        cfg.ai.enabled = False
        cfg.scanners = [
            "supply-chain",
            "dependency-diff",
            "dependencies",
            "provenance",
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
        elif git_ops.is_git_repo(project.root):
            base = git_ops.default_branch(project.root)
            cfg.scanner_options["dependency-diff"] = {
                "ref": f"{base}...HEAD",
                "behavior": behavior,
                "sandbox": sandbox,
            }

        # Compute the dependency changes before the (slower) scan so a bad
        # --diff ref fails fast. An automatically chosen base that git cannot
        # resolve (e.g. a repository without commits) only skips this section.
        changes = []
        if diff_ref:
            changes = _diff_or_exit(diff_packages, project.root, diff_ref)
        elif git_ops.is_git_repo(project.root):
            auto_ref = f"{git_ops.default_branch(project.root)}...HEAD"
            try:
                changes = diff_packages(project.root, auto_ref)
            except ValueError as exc:
                if not quiet:
                    err_console.print(
                        f"[dim]· Dependency changes skipped: {escape(str(exc))}[/dim]"
                    )

        result = ScanEngine(cfg, progress=progress_printer(quiet)).scan(project)

        payload: dict = {
            "errors": result.errors,
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
        payload["dependency_changes"] = [
            {
                "ecosystem": c.ecosystem,
                "package": c.package,
                "change": c.change,
                "old_version": c.old_version,
                "new_version": c.new_version,
            }
            for c in changes
        ]
        if auth_map:
            payload["auth_map"] = [e.to_dict() for e in build_auth_map(project)]

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

        fail_on_scanner_errors(result, cfg, gating=threshold is not None)
        if threshold is not None and result.highest_severity() >= threshold:
            raise typer.Exit(1)
    finally:
        resolved.cleanup()
