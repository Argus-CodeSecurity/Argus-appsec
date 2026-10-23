"""``nephilex audit``: verify, list and export the fix and suppression audit log."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import typer
from rich.markup import escape

from nephilex.cli._console import console, err_console
from nephilex.cli.output import write_stdout

audit_app = typer.Typer(
    help="Tamper-evident audit log of applied fixes and suppressions (.nephilex/audit.log)."
)

_TARGET_HELP = "Project directory (uses its .nephilex/audit.log) or the path of a log file."


def _log_path(target: Path) -> Path:
    from nephilex.audit import AUDIT_PATH

    return target if target.is_file() else target / AUDIT_PATH


def _parse_date(value: str | None, option: str) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise typer.BadParameter("expected a YYYY-MM-DD date", param_hint=option) from exc


def _filter(
    action: list[str] | None,
    kind: list[str] | None,
    rule: str | None,
    path: str | None,
    actor: str | None,
    fingerprint: str | None,
    since: str | None,
    until: str | None,
):
    from nephilex.audit import ACTIONS, SUPPRESSION_KINDS
    from nephilex.audit.export import RecordFilter

    for value in action or []:
        if value not in ACTIONS:
            raise typer.BadParameter(
                f"unknown action {value!r} (choose from: {', '.join(ACTIONS)})",
                param_hint="--action",
            )
    for value in kind or []:
        if value not in SUPPRESSION_KINDS:
            raise typer.BadParameter(
                f"unknown kind {value!r} (choose from: {', '.join(SUPPRESSION_KINDS)})",
                param_hint="--kind",
            )
    return RecordFilter(
        actions=tuple(action or ()),
        kinds=tuple(kind or ()),
        rule=rule,
        path=path,
        actor=actor,
        fingerprint=fingerprint,
        since=_parse_date(since, "--since"),
        until=_parse_date(until, "--until"),
    )


@audit_app.command("verify")
def audit_verify(
    target: Path = typer.Argument(Path("."), help=_TARGET_HELP),
    anchor: str | None = typer.Option(
        None,
        "--anchor",
        metavar="HASH",
        help="A record hash saved earlier outside the repository (e.g. a CI artifact). "
        "It must still be in the chain, which also catches records removed from the end.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Print the result as JSON."),
) -> None:
    """Check the hash chain. Exit 1 at the first edited, deleted or reordered record."""
    from nephilex.audit import verify_log

    log = _log_path(target)
    if not log.is_file() and anchor is None:
        if as_json:
            write_stdout(json.dumps({"ok": True, "records": 0, "log": str(log)}) + "\n")
        else:
            console.print(
                f"[yellow]No audit log at {escape(str(log))}; nothing to verify.[/yellow]"
            )
        return
    result = verify_log(log, anchor=anchor)
    if as_json:
        write_stdout(
            json.dumps(
                {
                    "ok": result.ok,
                    "log": str(log),
                    "records": result.records,
                    "head": result.head,
                    "line": result.line,
                    "seq": result.seq,
                    "problem": result.reason,
                }
            )
            + "\n"
        )
    elif result.ok:
        console.print(
            f"[green]OK[/green]: {result.records} record(s), chain intact. Head hash: {result.head}"
        )
    else:
        where = f"line {result.line}" if result.line else escape(str(log))
        if result.seq is not None:
            where += f" (seq {result.seq})"
        err_console.print(f"[red]Audit log broken[/red] at {where}: {escape(result.reason or '')}")
        err_console.print(
            f"[dim]{result.records} record(s) before it verified; last good hash {result.head}[/dim]"
        )
    if not result.ok:
        raise typer.Exit(1)


@audit_app.command("show")
def audit_show(
    target: Path = typer.Argument(Path("."), help=_TARGET_HELP),
    action: list[str] | None = typer.Option(
        None, "--action", "-a", help="Only this action (repeatable), e.g. fix.applied."
    ),
    kind: list[str] | None = typer.Option(
        None,
        "--kind",
        "-k",
        help="Only this suppression kind (repeatable): allowlist, exception, inline, baseline.",
    ),
    rule: str | None = typer.Option(None, "--rule", help="Only this rule id (full or short)."),
    path: str | None = typer.Option(None, "--path", help="Only paths matching this glob."),
    actor: str | None = typer.Option(None, "--actor", help="Only actors containing this text."),
    fingerprint: str | None = typer.Option(None, "--fingerprint", help="Only this fingerprint."),
    since: str | None = typer.Option(None, "--since", help="On or after this date (YYYY-MM-DD)."),
    until: str | None = typer.Option(None, "--until", help="On or before this date (YYYY-MM-DD)."),
    limit: int = typer.Option(0, "--limit", "-n", min=0, help="Show only the last N matches."),
    as_json: bool = typer.Option(False, "--json", help="Print matching records as JSON Lines."),
) -> None:
    """List audit records, newest last, with optional filters."""
    from nephilex.audit.export import load_records

    log = _log_path(target)
    flt = _filter(action, kind, rule, path, actor, fingerprint, since, until)
    if not log.is_file():
        if not as_json:
            console.print(f"[yellow]No audit log at {escape(str(log))}.[/yellow]")
        return
    records, unparsed = load_records(log, flt)
    if limit:
        records = records[-limit:]
    if unparsed:
        err_console.print(
            f"[yellow]{len(unparsed)} line(s) are not valid records (first: line "
            f"{unparsed[0]}); run `nephilex audit verify`.[/yellow]"
        )
    if as_json:
        write_stdout("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
        return
    from rich.table import Table

    table = Table(show_lines=False)
    for col in ("seq", "time (UTC)", "actor", "action", "kind", "rule", "path", "reason"):
        table.add_column(col, overflow="fold")
    for r in records:
        table.add_row(
            str(r.get("seq", "")),
            escape(str(r.get("ts", ""))[:19].replace("T", " ")),
            escape(str(r.get("actor") or "")),
            escape(str(r.get("action") or "")),
            escape(str(r.get("kind") or "")),
            escape(str(r.get("rule") or "")),
            escape(str(r.get("path") or "")),
            escape(str(r.get("reason") or "")),
        )
    console.print(table)
    console.print(f"[dim]{len(records)} record(s)[/dim]")


@audit_app.command("export")
def audit_export(
    target: Path = typer.Argument(Path("."), help=_TARGET_HELP),
    fmt: str = typer.Option("json", "--format", "-f", help="csv or json."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write to this file instead of stdout."
    ),
    action: list[str] | None = typer.Option(None, "--action", "-a", help="Only this action."),
    kind: list[str] | None = typer.Option(None, "--kind", "-k", help="Only this kind."),
    since: str | None = typer.Option(None, "--since", help="On or after this date."),
    until: str | None = typer.Option(None, "--until", help="On or before this date."),
) -> None:
    """Export records for auditors. JSON includes the chain verification result."""
    from nephilex.audit.export import load_records, to_csv, to_json
    from nephilex.audit.log import verify_log

    fmt = fmt.strip().lower()
    if fmt not in ("csv", "json"):
        raise typer.BadParameter("choose csv or json", param_hint="--format")
    flt = _filter(action, kind, None, None, None, None, since, until)
    log = _log_path(target)
    if not log.is_file():
        err_console.print(f"[red]Error:[/red] no audit log at {escape(str(log))}")
        raise typer.Exit(2)
    records, _unparsed = load_records(log, flt)
    text = to_csv(records) if fmt == "csv" else to_json(log, records)
    check = verify_log(log)
    if not check.ok:
        err_console.print(
            f"[yellow]Warning:[/yellow] the chain does not verify "
            f"(line {check.line}: {escape(check.reason or '')})."
        )
    if output is None:
        write_stdout(text)
        return
    output.write_text(text, encoding="utf-8", newline="")
    err_console.print(f"[green]Exported[/green] {len(records)} record(s) to {escape(str(output))}")
