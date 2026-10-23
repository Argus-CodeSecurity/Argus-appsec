"""Tests for the fix/PR workflow: rewrites, applier, git ops, and remote parsing."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from nephilex.core.config import Config
from nephilex.core.engine import ScanEngine
from nephilex.core.models import Finding, Location, Severity
from nephilex.remediation import git_ops
from nephilex.remediation.applier import apply_fixes
from nephilex.remediation.hosting import parse_remote
from nephilex.remediation.pullrequest import FixOptions, run_fix_workflow
from nephilex.remediation.rewrites import fix_line, verify_line_fixed

git_missing = shutil.which("git") is None


# --- rewrites --------------------------------------------------------------
def test_fix_line_transforms_known_rules():
    assert (
        fix_line("patterns.python-yaml-load", "x = yaml.load(data)") == "x = yaml.safe_load(data)"
    )
    assert "sha256" in fix_line("patterns.weak-hash-md5-sha1", "hashlib.md5(x)")
    assert "shell=True" not in fix_line(
        "patterns.python-shell-true", "subprocess.run(cmd, shell=True)"
    )


def test_fix_line_unknown_rule_returns_none():
    assert fix_line("patterns.nonexistent", "whatever") is None


def test_fix_line_llm_rules():
    # trust_remote_code=True -> False, and the detection then clears.
    fixed = fix_line(
        "llm.trust-remote-code", "m = AutoModel.from_pretrained('x', trust_remote_code=True)"
    )
    assert "trust_remote_code=False" in fixed
    assert verify_line_fixed("llm.trust-remote-code", fixed) is True

    # torch.load gains weights_only=True, clearing the pickle detection.
    fixed = fix_line("llm.torch-load-pickle", "w = torch.load('model.bin')")
    assert "weights_only=True" in fixed
    assert verify_line_fixed("llm.torch-load-pickle", fixed) is True

    # Already-safe torch.load is left alone.
    assert fix_line("llm.torch-load-pickle", "w = torch.load('m', weights_only=True)") is None


def test_verify_line_fixed():
    fixed = fix_line("patterns.python-yaml-load", "yaml.load(x)")
    assert verify_line_fixed("patterns.python-yaml-load", fixed) is True
    # The original still trips the detection.
    assert verify_line_fixed("patterns.python-yaml-load", "yaml.load(x)") is False


# --- patch agent tiers -----------------------------------------------------
def _agent_ctx(ai, tmp_path):
    from nephilex.core.project import Project

    return __import__("nephilex.agents.base", fromlist=["AgentContext"]).AgentContext(
        project=Project.from_path(tmp_path), config=Config(), ai=ai
    )


def test_patch_deterministic_tier_labeled(tmp_path):
    from nephilex.agents.patch import PatchAgent
    from nephilex.ai.heuristic import HeuristicProvider

    f = Finding(
        id="x",
        rule_id="patterns.python-yaml-load",
        scanner="patterns",
        title="t",
        description="d",
        location=Location(path="a.py", start_line=1, snippet="data = yaml.load(raw)"),
        severity=Severity.HIGH,
    )
    PatchAgent().process(f, _agent_ctx(HeuristicProvider(), tmp_path))
    assert f.remediation.patch and "safe_load" in f.remediation.patch
    assert f.remediation.verified is True
    assert f.metadata["patch_source"] == "deterministic"


def test_patch_ai_tier_labeled_for_review(tmp_path):
    from nephilex.agents.patch import PatchAgent
    from nephilex.ai.base import AIProvider

    class _FakeModel(AIProvider):
        name = "fake-model"
        is_remote = False

        def complete(self, system, user):
            # Return a fixed snippet the deterministic tier would not produce.
            return "cursor.execute('SELECT * FROM t WHERE id = ?', (uid,))"

    f = Finding(
        id="x",
        rule_id="patterns.python-sql-format",
        scanner="patterns",
        title="SQLi",
        description="d",
        location=Location(
            path="a.py",
            start_line=1,
            snippet="cursor.execute('SELECT * FROM t WHERE id = %s' % uid)",
        ),
        severity=Severity.HIGH,
        cwe=["CWE-89"],
    )
    PatchAgent().process(f, _agent_ctx(_FakeModel(), tmp_path))
    assert f.remediation.patch
    assert f.metadata["patch_source"] == "ai-proposed"
    assert f.metadata["patch_review"] == "human-review-required"
    assert "review before merging" in f.remediation.guidance.lower()


# --- applier ---------------------------------------------------------------
def _finding(rule_id: str, path: str, line: int) -> Finding:
    return Finding(
        id=f"{rule_id}:{line}",
        rule_id=rule_id,
        scanner="patterns",
        title="t",
        description="d",
        location=Location(path=path, start_line=line),
        severity=Severity.HIGH,
    )


def test_apply_fixes_preserves_indentation(tmp_path: Path):
    src = tmp_path / "m.py"
    src.write_text("def f():\n    return yaml.load(data)\n", encoding="utf-8")
    from nephilex.core.project import Project

    project = Project.from_path(tmp_path)
    findings = [_finding("patterns.python-yaml-load", "m.py", 2)]
    report = apply_fixes(project, findings)

    assert report.any_changes
    assert src.read_text(encoding="utf-8") == "def f():\n    return yaml.safe_load(data)\n"
    # Indentation kept.
    assert report.fixes[0].after.startswith("    ")


def test_apply_fixes_dry_run_writes_nothing(tmp_path: Path):
    src = tmp_path / "m.py"
    original = "yaml.load(x)\n"
    src.write_text(original, encoding="utf-8")
    from nephilex.core.project import Project

    project = Project.from_path(tmp_path)
    report = apply_fixes(project, [_finding("patterns.python-yaml-load", "m.py", 1)], dry_run=True)
    assert report.any_changes  # it reports what it would do
    assert src.read_text(encoding="utf-8") == original  # but changes nothing


def test_apply_fixes_skips_unverifiable_without_flag(tmp_path: Path):
    """A line that doesn't actually contain the pattern won't verify -> skipped."""
    src = tmp_path / "m.py"
    src.write_text("a = 1\n", encoding="utf-8")
    from nephilex.core.project import Project

    project = Project.from_path(tmp_path)
    report = apply_fixes(project, [_finding("patterns.python-yaml-load", "m.py", 1)])
    assert not report.any_changes
    assert report.skipped


def test_syntax_error_helper():
    from nephilex.remediation.applier import _syntax_error

    assert _syntax_error("m.py", "x = 1\n") is None
    assert _syntax_error("m.py", "def (:\n") is not None
    # Non-Python files are trusted (no cheap parser).
    assert _syntax_error("m.js", "def (:\n") is None


def test_apply_fixes_reverts_syntax_breaking_change(tmp_path: Path, monkeypatch):
    """A rewrite that clears the detection but breaks the file must be reverted."""
    import nephilex.remediation.rewrites as rw

    src = tmp_path / "m.py"
    original = "x = yaml.load(data)\n"
    src.write_text(original, encoding="utf-8")
    from nephilex.core.project import Project

    # Emit code that no longer trips the detector but is not valid Python.
    monkeypatch.setitem(rw.REWRITES, "patterns.python-yaml-load", lambda ln: "x = (")
    project = Project.from_path(tmp_path)
    report = apply_fixes(project, [_finding("patterns.python-yaml-load", "m.py", 1)])

    assert not report.any_changes
    assert any("syntax error" in s for s in report.skipped)
    assert src.read_text(encoding="utf-8") == original  # left untouched


# --- remote parsing --------------------------------------------------------
@pytest.mark.parametrize(
    "url,host,owner,repo",
    [
        ("https://github.com/octo/repo.git", "github", "octo", "repo"),
        ("https://github.com/octo/repo", "github", "octo", "repo"),
        ("git@github.com:octo/repo.git", "github", "octo", "repo"),
        ("https://gitlab.com/group/sub/proj.git", "gitlab", "group/sub", "proj"),
        ("git@bitbucket.org:team/repo.git", "bitbucket", "team", "repo"),
    ],
)
def test_parse_remote(url, host, owner, repo):
    ref = parse_remote(url)
    assert ref is not None
    assert (ref.host, ref.owner, ref.repo) == (host, owner, repo)


def test_parse_remote_unknown_host():
    assert parse_remote("https://example.com/x/y.git") is None


# --- end-to-end workflow (git-backed) --------------------------------------
def _git_repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "import yaml\ndef load(x):\n    return yaml.load(x)\n",
        encoding="utf-8",
    )
    run = lambda *a: subprocess.run(  # noqa: E731
        ["git", "-C", str(tmp_path), *a], check=True, capture_output=True
    )
    run("init", "-q")
    run("-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
    run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    return tmp_path


@pytest.mark.skipif(git_missing, reason="git not available")
def test_fix_workflow_creates_branch_and_commits(tmp_path: Path):
    from nephilex.core.project import Project

    repo = _git_repo(tmp_path)
    project = Project.from_path(repo)
    result = ScanEngine(Config(ai=Config().ai)).scan(project)
    # Disable AI to keep it deterministic (already offline heuristic anyway).

    outcome = run_fix_workflow(
        project,
        result.findings,
        FixOptions(branch="nephilex/test-fixes", open_pr=False),
    )
    assert outcome.committed
    assert outcome.applied.any_changes
    assert git_ops.branch_exists(repo, "nephilex/test-fixes")
    # The file on the branch is fixed.
    assert "safe_load" in (repo / "app.py").read_text(encoding="utf-8")


@pytest.mark.skipif(git_missing, reason="git not available")
def test_fix_workflow_dry_run_no_git_needed(tmp_path: Path):
    from nephilex.core.project import Project

    (tmp_path / "app.py").write_text("import yaml\nyaml.load(x)\n", encoding="utf-8")
    project = Project.from_path(tmp_path)
    result = ScanEngine(Config()).scan(project)
    outcome = run_fix_workflow(project, result.findings, FixOptions(dry_run=True))
    assert outcome.applied.any_changes
    assert not outcome.committed
    # Dry run must not modify the file.
    assert "safe_load" not in (tmp_path / "app.py").read_text(encoding="utf-8")


@pytest.mark.skipif(git_missing, reason="git not available")
def test_fix_workflow_errors_on_non_repo(tmp_path: Path):
    from nephilex.core.project import Project

    (tmp_path / "app.py").write_text("yaml.load(x)\n", encoding="utf-8")
    project = Project.from_path(tmp_path)
    outcome = run_fix_workflow(
        project, [_finding("patterns.python-yaml-load", "app.py", 1)], FixOptions(open_pr=False)
    )
    assert outcome.error and "not a git repository" in outcome.error
