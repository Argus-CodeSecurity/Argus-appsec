"""Audit log (.nephilex/audit.log): hash chain, tamper detection, concurrency, redaction."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from typer.testing import CliRunner

import nephilex
from nephilex.audit import (
    AUDIT_PATH,
    GENESIS_HASH,
    AuditEvent,
    append_events,
    record_baseline,
    record_hash,
    verify_log,
)
from nephilex.cli.main import app
from nephilex.core.config import Config, load_project_config
from nephilex.core.engine import ScanEngine
from nephilex.core.models import Finding, Location, Severity
from nephilex.core.project import Project
from nephilex.remediation import git_ops
from nephilex.remediation.applier import apply_fixes

runner = CliRunner()
ACTOR = "Test User <test@example.com>"


def _events(n: int, prefix: str = "r") -> list[AuditEvent]:
    return [
        AuditEvent(
            action="fix.applied",
            fingerprint=f"{prefix}.rule|a.py|{i:012d}",
            rule=f"{prefix}.rule",
            path="a.py",
            reason="verified deterministic fix",
            details={"line": i},
        )
        for i in range(n)
    ]


def _lines(root: Path) -> list[str]:
    return (root / AUDIT_PATH).read_text(encoding="ascii").splitlines()


def _records(root: Path) -> list[dict]:
    return [json.loads(line) for line in _lines(root)]


def _rewrite(root: Path, lines: list[str]) -> None:
    (root / AUDIT_PATH).write_text("\n".join(lines) + "\n", encoding="ascii")


# --- the chain ------------------------------------------------------------------
def test_records_are_chained_and_verify(tmp_path: Path) -> None:
    res = append_events(tmp_path, _events(3), actor=ACTOR)
    assert res.written == 3 and res.warning is None
    recs = _records(tmp_path)
    assert [r["seq"] for r in recs] == [1, 2, 3]
    assert recs[0]["prev_hash"] == GENESIS_HASH
    assert recs[1]["prev_hash"] == recs[0]["hash"]
    assert all(record_hash(r) == r["hash"] for r in recs)
    assert recs[0]["actor"] == ACTOR and recs[0]["ts"].endswith("Z")
    assert set(recs[0]) >= {"action", "fingerprint", "rule", "path", "reason", "kind"}

    append_events(tmp_path, _events(2, "s"), actor=ACTOR)  # a second writer continues
    result = verify_log(tmp_path / AUDIT_PATH)
    assert result.ok and result.records == 5 and result.head == _records(tmp_path)[-1]["hash"]


def test_edited_record_is_detected(tmp_path: Path) -> None:
    append_events(tmp_path, _events(4), actor=ACTOR)
    lines = _lines(tmp_path)
    lines[1] = lines[1].replace("verified deterministic fix", "nothing to see here")
    _rewrite(tmp_path, lines)
    result = verify_log(tmp_path / AUDIT_PATH)
    assert not result.ok and result.line == 2 and result.seq == 2
    assert "edited" in (result.reason or "")
    assert result.records == 1


def test_edited_and_rehashed_record_breaks_the_next_link(tmp_path: Path) -> None:
    append_events(tmp_path, _events(4), actor=ACTOR)
    recs = _records(tmp_path)
    recs[1]["reason"] = "approved by nobody"
    recs[1]["hash"] = record_hash(recs[1])
    _rewrite(tmp_path, [json.dumps(r) for r in recs])
    result = verify_log(tmp_path / AUDIT_PATH)
    assert not result.ok and result.line == 3


def test_deleted_record_is_detected(tmp_path: Path) -> None:
    append_events(tmp_path, _events(4), actor=ACTOR)
    lines = _lines(tmp_path)
    del lines[1]
    _rewrite(tmp_path, lines)
    result = verify_log(tmp_path / AUDIT_PATH)
    assert not result.ok and result.line == 2 and "deleted" in (result.reason or "")


def test_deleted_first_record_is_detected(tmp_path: Path) -> None:
    append_events(tmp_path, _events(3), actor=ACTOR)
    _rewrite(tmp_path, _lines(tmp_path)[1:])
    result = verify_log(tmp_path / AUDIT_PATH)
    assert not result.ok and result.line == 1


def test_reordered_records_are_detected(tmp_path: Path) -> None:
    append_events(tmp_path, _events(4), actor=ACTOR)
    lines = _lines(tmp_path)
    lines[1], lines[2] = lines[2], lines[1]
    _rewrite(tmp_path, lines)
    result = verify_log(tmp_path / AUDIT_PATH)
    assert not result.ok and result.line == 2


def test_truncation_is_only_caught_with_an_anchor(tmp_path: Path) -> None:
    append_events(tmp_path, _events(4), actor=ACTOR)
    head = verify_log(tmp_path / AUDIT_PATH).head
    _rewrite(tmp_path, _lines(tmp_path)[:2])
    assert verify_log(tmp_path / AUDIT_PATH).ok  # the documented limit
    result = verify_log(tmp_path / AUDIT_PATH, anchor=head[:16])
    assert not result.ok and "anchor" in (result.reason or "")


def test_damaged_tail_is_appended_after_but_still_flagged(tmp_path: Path) -> None:
    append_events(tmp_path, _events(2), actor=ACTOR)
    with open(tmp_path / AUDIT_PATH, "ab") as fh:
        fh.write(b'{"v": 1, "seq": 3, "trunc')  # a crash mid-write
    res = append_events(tmp_path, _events(1, "late"), actor=ACTOR)
    assert res.written == 1 and res.warning and "malformed" in res.warning
    assert len(_lines(tmp_path)) == 4  # the new record is on its own line
    result = verify_log(tmp_path / AUDIT_PATH)
    assert not result.ok and result.line == 3


# --- concurrency ------------------------------------------------------------------
def test_concurrent_threads_do_not_fork_the_chain(tmp_path: Path) -> None:
    def work(i: int) -> None:
        for j in range(10):
            append_events(tmp_path, _events(2, f"t{i}-{j}"), actor=ACTOR)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = verify_log(tmp_path / AUDIT_PATH)
    assert result.ok, result.reason
    assert result.records == 8 * 10 * 2


_WRITER = """
import sys
from nephilex.audit import AuditEvent, append_events
root, tag = sys.argv[1], sys.argv[2]
for j in range(15):
    res = append_events(root, [AuditEvent(action="fix.applied", rule=f"{tag}.{j}", path="a.py")],
                        actor="proc")
    assert res.written == 1, res.warning
"""


def test_concurrent_processes_do_not_fork_the_chain(tmp_path: Path) -> None:
    env = dict(os.environ)
    src = str(Path(nephilex.__file__).resolve().parents[1])
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _WRITER, str(tmp_path), f"p{i}"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for i in range(4)
    ]
    for p in procs:
        _out, err = p.communicate(timeout=120)
        assert p.returncode == 0, err.decode(errors="replace")
    result = verify_log(tmp_path / AUDIT_PATH)
    assert result.ok, result.reason
    assert result.records == 4 * 15


# --- redaction and robustness -------------------------------------------------------
GH_TOKEN = "ghp_" + "A1b2C3d4E5" * 4
URL_TOKEN = "x-access-token:" + "s3cr3tvalue"


def test_secret_values_never_reach_the_log(tmp_path: Path) -> None:
    event = AuditEvent(
        action="suppression.matched",
        kind="inline",
        rule="secrets.github-token",
        path="settings.py",
        reason=f"rotated, old value {GH_TOKEN}",
        details={"pr_url": f"https://{URL_TOKEN}@github.com/o/r/pull/1", "note": "x\ny"},
    )
    append_events(tmp_path, [event], actor=ACTOR)
    text = (tmp_path / AUDIT_PATH).read_text(encoding="ascii")
    assert GH_TOKEN not in text and "s3cr3tvalue" not in text
    assert verify_log(tmp_path / AUDIT_PATH).ok


def test_fix_records_do_not_contain_source_lines(tmp_path: Path) -> None:
    secret_line = 'x = yaml.load(s)  # password = "hunter2hunter2"\n'
    (tmp_path / "a.py").write_text("import yaml\n" + secret_line, encoding="utf-8")
    finding = Finding(
        id="f1",
        rule_id="patterns.python-yaml-load",
        scanner="patterns",
        title="yaml.load",
        description="",
        location=Location(path="a.py", start_line=2, snippet=secret_line.strip()),
        severity=Severity.HIGH,
    )
    report = apply_fixes(Project.from_path(tmp_path), [finding])
    assert report.fixes and report.audit_records == 1
    rec = _records(tmp_path)[0]
    assert rec["action"] == "fix.applied" and rec["fingerprint"] == finding.fingerprint()
    assert rec["details"]["line"] == 2
    assert "hunter2" not in (tmp_path / AUDIT_PATH).read_text(encoding="ascii")


def test_dry_run_and_disabled_log_record_nothing(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "a.py").write_text("import yaml\nx = yaml.load(s)\n", encoding="utf-8")
    finding = Finding(
        id="f1",
        rule_id="patterns.python-yaml-load",
        scanner="patterns",
        title="t",
        description="",
        location=Location(path="a.py", start_line=2),
    )
    apply_fixes(Project.from_path(tmp_path), [finding], dry_run=True)
    assert not (tmp_path / AUDIT_PATH).exists()
    monkeypatch.setenv("NEPHILEX_AUDIT_LOG", "off")
    apply_fixes(Project.from_path(tmp_path), [finding])
    assert not (tmp_path / AUDIT_PATH).exists()


def test_unwritable_log_is_a_warning(tmp_path: Path) -> None:
    (tmp_path / ".nephilex").write_text("not a directory", encoding="utf-8")
    res = append_events(tmp_path, _events(1), actor=ACTOR)
    assert res.written == 0 and res.warning and "not written" in res.warning


def test_symlinked_log_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("precious\n", encoding="utf-8")
    root = tmp_path / "repo"
    (root / ".nephilex").mkdir(parents=True)
    try:
        (root / AUDIT_PATH).symlink_to(outside)
    except OSError:
        pytest.skip("cannot create symlinks here")
    res = append_events(root, _events(1), actor=ACTOR)
    assert res.written == 0 and res.warning and "symlink" in res.warning
    assert outside.read_text(encoding="utf-8") == "precious\n"


# --- suppression events from scans ---------------------------------------------------
_IGNORED = (
    "import subprocess\n"
    'subprocess.run(cmd, shell=True)  # nephilex-ignore: python-shell-true reason="{reason}"\n'
)


def _scan(root: Path, origin: str = "local", **cfg_kw) -> None:
    project = Project.from_path(root, origin=origin)
    cfg = load_project_config(project, trust_remote=cfg_kw.pop("trust_remote", False))
    cfg.scanners = ["patterns"]
    cfg.ai.enabled = False
    cfg.cache = False
    for key, value in cfg_kw.items():
        setattr(cfg, key, value)
    ScanEngine(cfg).scan(project)


def test_inline_suppression_is_recorded_once_per_content(tmp_path: Path) -> None:
    (tmp_path / "run.py").write_text(_IGNORED.format(reason="trusted input"), encoding="utf-8")
    _scan(tmp_path)
    first = _records(tmp_path)
    assert [r["action"] for r in first] == ["suppression.added", "suppression.matched"]
    matched = first[1]
    assert matched["kind"] == "inline" and matched["reason"] == "trusted input"
    assert matched["rule"].endswith("python-shell-true") and matched["path"] == "run.py"

    _scan(tmp_path)
    _scan(tmp_path)
    assert len(_records(tmp_path)) == 2  # no flood on repeated scans

    (tmp_path / "run.py").write_text(_IGNORED.format(reason="reviewed by sec"), encoding="utf-8")
    _scan(tmp_path)
    assert len(_records(tmp_path)) == 4  # a changed reason is a new suppression
    assert verify_log(tmp_path / AUDIT_PATH).ok


def test_allowlist_and_exceptions_are_recorded(tmp_path: Path) -> None:
    (tmp_path / "loader.py").write_text(
        "import yaml\ndef f(raw):\n    return yaml.load(raw)\n", encoding="utf-8"
    )
    (tmp_path / "h.py").write_text(
        "import hashlib\ndef h(p):\n    return hashlib.md5(p).hexdigest()\n", encoding="utf-8"
    )
    (tmp_path / ".nephilex.yml").write_text(
        "allow:\n  - {rule: python-yaml-load, path: loader.py, reason: input is our own file}\n",
        encoding="utf-8",
    )
    project = Project.from_path(tmp_path)
    cfg = load_project_config(project)
    cfg.scanners = ["patterns"]
    cfg.ai.enabled = False
    result = ScanEngine(cfg).scan(project)
    md5 = next(f for f in result.findings if f.location.path == "h.py")
    (tmp_path / ".nephilex" / "exceptions.yml").write_text(
        "exceptions:\n"
        f"  - {{fingerprint: '{md5.fingerprint()}', status: accept, reason: legacy checksum,"
        " owner: sec@example.com}\n",
        encoding="utf-8",
    )
    ScanEngine(cfg).scan(project)
    recs = _records(tmp_path)
    kinds = {(r["action"], r["kind"]) for r in recs}
    assert ("suppression.added", "allowlist") in kinds
    assert ("suppression.matched", "allowlist") in kinds
    assert ("suppression.added", "exception") in kinds
    assert ("suppression.matched", "exception") in kinds
    exc = next(r for r in recs if r["action"] == "suppression.matched" and r["kind"] == "exception")
    assert exc["fingerprint"] == md5.fingerprint() and exc["details"]["status"] == "accept"
    assert result.project_summary["audit"]["path"] == AUDIT_PATH


def test_untrusted_or_disabled_scans_do_not_write(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".nephilex.yml").write_text(
        "allow:\n  - {rule: python-shell-true, reason: ok}\n", encoding="utf-8"
    )
    (tmp_path / "run.py").write_text(_IGNORED.format(reason="x"), encoding="utf-8")
    _scan(tmp_path, origin="github")  # cloned remote: never written
    assert not (tmp_path / AUDIT_PATH).exists()
    _scan(tmp_path, audit_log=False)
    assert not (tmp_path / AUDIT_PATH).exists()
    monkeypatch.setenv("NEPHILEX_AUDIT_LOG", "0")
    _scan(tmp_path)
    assert not (tmp_path / AUDIT_PATH).exists()


def test_audit_log_config_key_is_validated() -> None:
    assert Config.from_dict({"audit_log": False}).audit_log is False
    with pytest.raises(ValueError, match="audit_log"):
        Config.from_dict({"audit_log": "no"})


def test_unwritable_log_never_fails_a_scan(tmp_path: Path) -> None:
    (tmp_path / "run.py").write_text(_IGNORED.format(reason="x"), encoding="utf-8")
    (tmp_path / ".nephilex").write_text("a file, not a folder", encoding="utf-8")
    project = Project.from_path(tmp_path)
    cfg = load_project_config(project)
    cfg.scanners = ["patterns"]
    cfg.ai.enabled = False
    result = ScanEngine(cfg).scan(project)
    assert not result.errors
    assert "warning" in result.project_summary["audit"]


def test_postprocess_applies_suppressions_and_context_to_external_findings(
    tmp_path: Path,
) -> None:
    from datetime import datetime, timezone

    from nephilex.core.models import ScanResult

    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".nephilex").mkdir()
    (tmp_path / ".nephilex" / "context.yml").write_text(
        "internal_paths: ['scripts/**']\n", encoding="utf-8"
    )
    (tmp_path / ".nephilex.yml").write_text(
        "allow:\n  - {rule: ext.noisy, reason: tool is wrong here}\n", encoding="utf-8"
    )

    def ext(rule: str) -> Finding:
        return Finding(
            id=rule,
            rule_id=rule,
            scanner="sarif-import",
            title="t",
            description="d",
            location=Location(path="scripts/a.py", start_line=1, snippet="x = 1"),
            severity=Severity.HIGH,
        )

    project = Project.from_path(tmp_path)
    cfg = load_project_config(project)
    cfg.ai.enabled = False
    result = ScanResult(target=str(tmp_path), started_at=datetime.now(timezone.utc))
    result.findings = [ext("ext.real"), ext("ext.noisy")]
    out = ScanEngine(cfg).postprocess(result, project)
    assert [f.rule_id for f in out.findings] == ["ext.real"]
    assert out.findings[0].severity == Severity.MEDIUM and "internal" in out.findings[0].tags
    matched = [r for r in _records(tmp_path) if r["action"] == "suppression.matched"]
    assert [(r["kind"], r["rule"]) for r in matched] == [("allowlist", "ext.noisy")]


def test_baseline_helper_records_hidden_findings(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}", encoding="utf-8")
    f = Finding(
        id="x",
        rule_id="patterns.python-yaml-load",
        scanner="patterns",
        title="t",
        description="",
        location=Location(path="a.py", start_line=3, snippet="yaml.load(x)"),
    )
    record_baseline(tmp_path, baseline, [f])
    record_baseline(tmp_path, baseline, [f])
    recs = _records(tmp_path)
    assert [(r["action"], r["kind"]) for r in recs] == [
        ("suppression.added", "baseline"),
        ("suppression.matched", "baseline"),
    ]


# --- CLI ------------------------------------------------------------------------------
def test_cli_verify_show_export(tmp_path: Path) -> None:
    append_events(tmp_path, _events(3), actor=ACTOR)
    append_events(
        tmp_path,
        [
            AuditEvent(
                action="suppression.matched",
                kind="inline",
                rule="patterns.python-shell-true",
                path="run.py",
                reason="=HYPERLINK(evil)",
                once=True,
            )
        ],
        actor=ACTOR,
    )
    res = runner.invoke(app, ["audit", "verify", str(tmp_path)])
    assert res.exit_code == 0 and "4 record(s)" in res.output

    res = runner.invoke(app, ["audit", "show", str(tmp_path), "--kind", "inline", "--json"])
    assert res.exit_code == 0
    shown = [json.loads(line) for line in res.output.splitlines() if line.strip()]
    assert [r["seq"] for r in shown] == [4]

    res = runner.invoke(app, ["audit", "show", str(tmp_path), "--action", "fix.applied", "-n", "2"])
    assert res.exit_code == 0 and "2 record(s)" in res.output

    out = tmp_path / "audit.csv"
    res = runner.invoke(app, ["audit", "export", str(tmp_path), "-f", "csv", "-o", str(out)])
    assert res.exit_code == 0
    csv_text = out.read_text(encoding="utf-8")
    assert csv_text.splitlines()[0].startswith("seq,ts,actor,action")
    assert "'=HYPERLINK(evil)" in csv_text  # neutralised for spreadsheets

    res = runner.invoke(app, ["audit", "export", str(tmp_path), "-f", "json"])
    doc = json.loads(res.output)
    assert doc["verified"] is True and len(doc["records"]) == 4

    res = runner.invoke(app, ["audit", "export", str(tmp_path), "-f", "xml"])
    assert res.exit_code == 2


def test_cli_verify_fails_on_tampering(tmp_path: Path) -> None:
    append_events(tmp_path, _events(3), actor=ACTOR)
    lines = _lines(tmp_path)
    _rewrite(tmp_path, [lines[0], lines[2]])
    res = runner.invoke(app, ["audit", "verify", str(tmp_path)])
    assert res.exit_code == 1
    assert "line 2" in res.output


def test_cli_verify_without_log(tmp_path: Path) -> None:
    assert runner.invoke(app, ["audit", "verify", str(tmp_path)]).exit_code == 0
    res = runner.invoke(app, ["audit", "verify", str(tmp_path), "--anchor", "ab" * 32])
    assert res.exit_code == 1


# --- fix workflow --------------------------------------------------------------------
ID = ("-c", "user.name=Setup", "-c", "user.email=setup@example.com", "-c", "commit.gpgsign=false")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.mark.skipif(not git_ops.git_available(), reason="git not installed")
def test_fix_workflow_commits_the_audit_log_with_the_fix(tmp_path: Path, monkeypatch) -> None:
    from nephilex.remediation.pullrequest import FixOptions, run_fix_workflow

    empty = tmp_path / "empty.gitconfig"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("import yaml\nx = yaml.load(s)\n", encoding="utf-8")
    _git(root, "init", "-q", "-b", "main")
    _git(root, *ID, "add", "-A")
    _git(root, *ID, "commit", "-qm", "init")
    # A scan just recorded a suppression: the log is new and untracked. That
    # alone must not make `nephilex fix` refuse the "dirty" tree.
    append_events(root, _events(1, "scan"), actor=ACTOR)

    finding = Finding(
        id="f1",
        rule_id="patterns.python-yaml-load",
        scanner="patterns",
        title="t",
        description="",
        location=Location(path="a.py", start_line=2),
        severity=Severity.HIGH,
    )
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Dev")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "dev@example.com")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Dev")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "dev@example.com")
    outcome = run_fix_workflow(Project.from_path(root), [finding], FixOptions())
    assert outcome.committed, outcome.error
    committed = _git(root, "show", "--name-only", "--format=", "HEAD").splitlines()
    assert sorted(committed) == [AUDIT_PATH, "a.py"]
    assert _git(root, "status", "--porcelain") == ""
    recs = _records(root)
    assert [r["action"] for r in recs] == ["fix.applied", "fix.applied"]
    assert recs[1]["rule"] == "patterns.python-yaml-load"
    assert verify_log(root / AUDIT_PATH).ok
