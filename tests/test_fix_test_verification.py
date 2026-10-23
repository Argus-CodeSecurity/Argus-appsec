"""`nephilex fix --verify-with-tests`: fixes verified by the project's own tests."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nephilex.audit import AUDIT_PATH
from nephilex.cli.main import app
from nephilex.core.config import Config, ConfigError, load_project_config
from nephilex.core.models import Finding, Location, Severity
from nephilex.core.project import Project
from nephilex.remediation import git_ops, testverify
from nephilex.remediation.applier import AppliedFix
from nephilex.remediation.pullrequest import FixOptions, run_fix_workflow
from nephilex.remediation.testverify import (
    TESTS_FAILED,
    TESTS_NOT_VERIFIED,
    TESTS_PASSED,
    TestCommand,
    TestCommandError,
    TestVerification,
    resolve_executable,
    resolve_test_command,
    run_test_command,
    scrub_environment,
    split_command,
)

pytestmark = pytest.mark.skipif(not git_ops.git_available(), reason="git not installed")

ID = ("-c", "user.name=Setup", "-c", "user.email=setup@example.com", "-c", "commit.gpgsign=false")

# The tiny project's own test: passes while a.py still calls yaml.load, so a
# fix to that line "breaks" it. The text is split so the scanner does not
# flag (and fix) this script too.
NEEDS_YAML_LOAD = (
    "import sys\n"
    "wanted = 'yaml.' + 'load(s)'\n"
    "sys.exit(0 if wanted in open('a.py', encoding='utf-8').read() else 1)\n"
)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def temp_root(tmp_path, monkeypatch) -> Path:
    """A private temp directory, so leftover worktrees are easy to spot."""
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp))
    return tmp


@pytest.fixture
def repo(tmp_path, monkeypatch, temp_root) -> Path:
    empty = tmp_path / "empty.gitconfig"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for var in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{var}_NAME", "Dev")
        monkeypatch.setenv(f"GIT_{var}_EMAIL", "dev@example.com")
    monkeypatch.delenv("NEPHILEX_AUDIT_LOG", raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("import yaml\nx = yaml.load(s)\n", encoding="utf-8")
    (root / "check_tests.py").write_text(NEEDS_YAML_LOAD, encoding="utf-8")
    _git(root, "init", "-q", "-b", "main")
    _git(root, *ID, "add", "-A")
    _git(root, *ID, "commit", "-qm", "init")
    return root


def _finding() -> Finding:
    return Finding(
        id="f1",
        rule_id="patterns.python-yaml-load",
        scanner="patterns",
        title="yaml.load",
        description="",
        location=Location(path="a.py", start_line=2),
        severity=Severity.HIGH,
    )


def _python(code: str, timeout: float = 120) -> TestCommand:
    return TestCommand(argv=(sys.executable, "-c", code), timeout=timeout)


def _options(command: TestCommand) -> FixOptions:
    return FixOptions(verify_tests=TestVerification(command, Config(scanners=["patterns"])))


def _worktrees(root: Path) -> list[str]:
    out = _git(root, "worktree", "list", "--porcelain")
    return [ln for ln in out.splitlines() if ln.startswith("worktree ")]


def _assert_cleaned_up(root: Path, temp_root: Path) -> None:
    assert len(_worktrees(root)) == 1, _worktrees(root)
    assert list(temp_root.iterdir()) == []


# --- the workflow ----------------------------------------------------------
def test_fix_committed_when_tests_pass(repo, temp_root, tmp_path):
    seen = tmp_path / "seen.json"
    code = (
        "import json, os, sys\n"
        f"json.dump({{'cwd': os.getcwd()}}, open({str(seen)!r}, 'w'))\n"
        "sys.exit(0)\n"
    )
    finding = _finding()
    outcome = run_fix_workflow(Project.from_path(repo), [finding], _options(_python(code)))

    assert outcome.committed, outcome.error
    assert "yaml.safe_load" in (repo / "a.py").read_text(encoding="utf-8")
    assert [f.tests for f in outcome.applied.fixes] == [TESTS_PASSED]
    assert outcome.verification is not None
    assert outcome.verification.baseline and outcome.verification.baseline.passed
    assert outcome.verification.after and outcome.verification.after.passed
    # The tests ran in a separate worktree, never in the operator's checkout.
    cwd = Path(json.loads(seen.read_text(encoding="utf-8"))["cwd"]).resolve()
    assert not cwd.is_relative_to(repo.resolve())
    assert "tests passed" in _git(repo, "log", "-1", "--format=%B")
    record = json.loads((repo / AUDIT_PATH).read_text(encoding="utf-8").splitlines()[-1])
    assert record["action"] == "fix.applied"
    assert record["details"]["tests"] == TESTS_PASSED
    assert "tests passed" in record["reason"]
    assert "remediation_applied" in finding.metadata
    _assert_cleaned_up(repo, temp_root)


def test_fix_not_committed_when_tests_fail(repo, temp_root):
    command = TestCommand(argv=(sys.executable, "check_tests.py"), timeout=120)
    finding = _finding()
    outcome = run_fix_workflow(Project.from_path(repo), [finding], _options(command))

    assert outcome.error is None
    assert not outcome.committed
    assert outcome.verification is not None
    assert outcome.verification.baseline and outcome.verification.baseline.passed
    assert outcome.verification.after and outcome.verification.after.status == "failed"
    assert [f.tests for f in outcome.verification.fixes] == [TESTS_FAILED]
    assert any("No fix passed test verification" in m for m in outcome.messages)
    # The operator's checkout is untouched: same branch, same file, no branch.
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert "yaml.load(s)" in (repo / "a.py").read_text(encoding="utf-8")
    assert _git(repo, "status", "--porcelain") == ""
    assert not git_ops.branch_exists(repo, "nephilex/security-fixes")
    assert "remediation_applied" not in finding.metadata
    _assert_cleaned_up(repo, temp_root)


def test_failing_baseline_means_nothing_is_verified(repo, temp_root):
    outcome = run_fix_workflow(
        Project.from_path(repo), [_finding()], _options(_python("import sys; sys.exit(3)"))
    )
    assert outcome.error and "before any fix was applied" in outcome.error
    assert "exit code 3" in outcome.error
    assert not outcome.committed
    assert outcome.verification is not None
    assert outcome.verification.after is None
    assert [f.tests for f in outcome.verification.fixes] == [TESTS_NOT_VERIFIED]
    assert not git_ops.branch_exists(repo, "nephilex/security-fixes")
    _assert_cleaned_up(repo, temp_root)


def test_timeout_stops_the_tests_and_cleans_up(repo, temp_root):
    command = _python("import time; time.sleep(60)", timeout=1)
    outcome = run_fix_workflow(Project.from_path(repo), [_finding()], _options(command))
    assert outcome.error and "timed out after 1s" in outcome.error
    assert not outcome.committed
    baseline = outcome.verification.baseline if outcome.verification else None
    assert baseline is not None and baseline.status == "timeout"
    assert baseline.duration < 30
    _assert_cleaned_up(repo, temp_root)


def test_worktree_removed_after_an_error(repo, temp_root, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("simulated crash in the test runner")

    monkeypatch.setattr(testverify, "run_test_command", boom)
    outcome = run_fix_workflow(Project.from_path(repo), [_finding()], _options(_python("pass")))
    assert outcome.error and "simulated crash" in outcome.error
    assert not outcome.committed
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    _assert_cleaned_up(repo, temp_root)


def test_test_output_is_capped(tmp_path):
    code = "import sys; sys.stdout.write('x' * 3_000_000); sys.stdout.flush()"
    run = run_test_command(_python(code), tmp_path)
    assert run.passed
    assert run.truncated
    assert len(run.output) <= testverify.MAX_TEST_OUTPUT


def test_secrets_are_stripped_from_the_test_environment(repo, temp_root, tmp_path, monkeypatch):
    secrets = {
        "GITHUB_TOKEN": "ghp_" + "a" * 36,
        "NEPHILEX_GITLAB_TOKEN": "glpat-" + "b" * 20,
        "AWS_SECRET_ACCESS_KEY": "c" * 40,
        "MY_SERVICE_API_KEY": "d" * 24,
        "DATABASE_URL": "postgres://app:hunter2@db.internal/app",
        "INNOCENT_NAME": "sk-" + "e" * 40,
    }
    for name, value in secrets.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("KEEP_ME", "1")
    dump = tmp_path / "env.json"
    code = f"import json, os; json.dump(dict(os.environ), open({str(dump)!r}, 'w'))"
    outcome = run_fix_workflow(Project.from_path(repo), [_finding()], _options(_python(code)))
    assert outcome.committed, outcome.error

    seen = json.loads(dump.read_text(encoding="utf-8"))
    upper = {k.upper() for k in seen}
    for name in secrets:
        assert name not in upper, name
    assert "KEEP_ME" in upper
    assert "PATH" in upper
    assert outcome.verification is not None
    assert set(secrets) <= {n.upper() for n in outcome.verification.removed_env}
    # Names are reported to the operator; values never are.
    assert not any("hunter2" in m for m in outcome.messages)


def test_rescan_failure_keeps_the_fix_out(repo, temp_root, monkeypatch):
    still_there = _finding()

    def fake_rescan(root, name, config):
        return [still_there], []

    monkeypatch.setattr(testverify, "_rescan", fake_rescan)
    outcome = run_fix_workflow(Project.from_path(repo), [_finding()], _options(_python("pass")))
    assert not outcome.committed
    assert outcome.verification is not None
    assert outcome.verification.after is None  # nothing left to test
    [fix] = outcome.verification.fixes
    assert fix.tests == TESTS_FAILED and "still reports" in fix.tests_reason
    _assert_cleaned_up(repo, temp_root)


def test_rescan_flags_a_new_high_finding():
    fix = AppliedFix(
        path="a.py", rule_id="r.one", line=2, before="", after="", finding_id="f1", verified=True
    )
    original = [_finding()]
    new = Finding(
        id="n1",
        rule_id="r.other",
        scanner="patterns",
        title="t",
        description="",
        location=Location(path="a.py", start_line=5),
        severity=Severity.CRITICAL,
    )
    low = new.model_copy(update={"id": "n2", "severity": Severity.LOW})
    assert testverify._rescan_failures([fix], original, [low]) == {}
    failures = testverify._rescan_failures([fix], original, [new])
    assert "new" in failures["f1"] and "r.other" in failures["f1"]


def test_branch_content_must_match_what_was_tested(repo, temp_root, monkeypatch):
    from nephilex.remediation import pullrequest

    real = pullrequest.content_digest
    monkeypatch.setattr(pullrequest, "content_digest", lambda data: "x" + real(data))
    outcome = run_fix_workflow(Project.from_path(repo), [_finding()], _options(_python("pass")))
    assert outcome.error and "differs from the version the tests ran against" in outcome.error
    assert not outcome.committed
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert not git_ops.branch_exists(repo, "nephilex/security-fixes")
    assert "yaml.load(s)" in (repo / "a.py").read_text(encoding="utf-8")
    assert not (repo / AUDIT_PATH).exists()


def test_pr_body_shows_test_results(repo, temp_root, monkeypatch):
    from nephilex.remediation import pullrequest

    outcome = run_fix_workflow(Project.from_path(repo), [_finding()], _options(_python("pass")))
    assert outcome.committed, outcome.error
    body = pullrequest._pr_body(outcome.applied, outcome.verification)
    assert "| Tests |" in body
    assert "### Test verification" in body
    assert "| passed |" in body


# --- choosing the command --------------------------------------------------
def test_untrusted_config_cannot_choose_the_command(tmp_path):
    root = tmp_path / "cloned"
    root.mkdir()
    (root / ".nephilex.yml").write_text(
        "autofix:\n  test_command: ['evil', '--steal']\n  test_timeout: 5\n", encoding="utf-8"
    )
    project = Project.from_path(root, origin="github")
    cfg = load_project_config(project)
    assert not cfg.trust_project_config
    with pytest.raises(TestCommandError):
        resolve_test_command(None, None, cfg)

    # Even a config object that carries the key is ignored when untrusted.
    cfg = Config(autofix={"test_command": "evil --steal"})
    cfg.trust_project_config = False
    with pytest.raises(TestCommandError):
        resolve_test_command(None, None, cfg)
    # The operator's own --test-command still works, with the default timeout.
    cmd = resolve_test_command("pytest -q", None, cfg)
    assert cmd.argv == ("pytest", "-q") and cmd.timeout == testverify.DEFAULT_TEST_TIMEOUT


def test_trusted_config_supplies_the_command(tmp_path):
    root = tmp_path / "local"
    root.mkdir()
    (root / ".nephilex.yml").write_text(
        "autofix:\n  test_command: ['python', '-m', 'pytest']\n  test_timeout: 90\n",
        encoding="utf-8",
    )
    cfg = load_project_config(Project.from_path(root))
    cmd = resolve_test_command(None, None, cfg)
    assert cmd.argv == ("python", "-m", "pytest")
    assert cmd.timeout == 90
    assert cmd.source == "autofix.test_command"
    # The CLI wins over the config.
    assert resolve_test_command("tox", 5, cfg).argv == ("tox",)


def test_config_rejects_bad_test_settings():
    with pytest.raises(ConfigError, match="test_command"):
        Config.from_dict({"autofix": {"test_command": 5}})
    with pytest.raises(ConfigError, match="test_timeout"):
        Config.from_dict({"autofix": {"test_timeout": -1}})


def test_cli_requires_a_command(repo):
    res = CliRunner().invoke(app, ["fix", str(repo), "-s", "patterns", "-q", "--verify-with-tests"])
    assert res.exit_code == 2, res.output
    assert "needs a test command" in res.output
    assert "yaml.load(s)" in (repo / "a.py").read_text(encoding="utf-8")


def test_cli_rejects_dry_run_with_tests(repo):
    res = CliRunner().invoke(app, ["fix", str(repo), "-q", "--dry-run", "--test-command", "pytest"])
    assert res.exit_code == 2, res.output


def test_cli_verifies_and_reports(repo, temp_root):
    command = subprocess.list2cmdline([sys.executable, "check_tests.py"])
    if sys.platform != "win32":
        import shlex

        command = shlex.join([sys.executable, "check_tests.py"])
    res = CliRunner().invoke(
        app, ["fix", str(repo), "-s", "patterns", "-q", "--test-command", command]
    )
    assert res.exit_code == 0, res.output
    assert "verified with tests" in res.output
    assert "failed" in res.output
    assert "yaml.load(s)" in (repo / "a.py").read_text(encoding="utf-8"), res.output
    _assert_cleaned_up(repo, temp_root)


# --- the pieces ------------------------------------------------------------
def test_scrub_environment_keeps_what_runtimes_need():
    env = {
        "PATH": "/usr/bin",
        "HOME": "/home/dev",
        "SYSTEMROOT": r"C:\Windows",
        "VIRTUAL_ENV": "/venv",
        "NODE_OPTIONS": "--max-old-space-size=4096",
        "PYTHONPATH": "src",
        "LANG": "C.UTF-8",
        "GIT_AUTHOR_NAME": "Dev",
        "GIT_CONFIG_GLOBAL": "/home/dev/.gitconfig",
        "GH_TOKEN": "x",
        "GITLAB_TOKEN": "x",
        "NPM_TOKEN": "x",
        "ANTHROPIC_API_KEY": "x",
        "OPENAI_API_KEY": "x",
        "GOOGLE_APPLICATION_CREDENTIALS": "/creds.json",
        "AZURE_CLIENT_SECRET": "x",
        "SSH_AUTH_SOCK": "/tmp/agent",
        "DB_PASSWORD": "x",
        "GIT_CONFIG_VALUE_0": "AUTHORIZATION: basic xyz",
        "GIT_DIR": "/elsewhere/.git",
        "REDIS_URL": "redis://:pw@cache:6379",
        "PROXY": "http://user:pw@proxy:3128",
    }
    kept, removed = scrub_environment(env)
    assert set(kept) == {
        "PATH",
        "HOME",
        "SYSTEMROOT",
        "VIRTUAL_ENV",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "LANG",
        "GIT_AUTHOR_NAME",
        "GIT_CONFIG_GLOBAL",
    }
    assert set(removed) == set(env) - set(kept)


@pytest.mark.parametrize(
    ("text", "posix", "windows"),
    [
        ("pytest -q", ["pytest", "-q"], ["pytest", "-q"]),
        ('npm run "unit tests"', ["npm", "run", "unit tests"], ["npm", "run", "unit tests"]),
        (r"C:\tools\run.exe -x", [r"C:toolsrun.exe", "-x"], [r"C:\tools\run.exe", "-x"]),
        (r'a "b\"c" d', ["a", 'b"c', "d"], ["a", 'b"c', "d"]),
        (r'a \\"b c"', ["a", "\\b c"], ["a", "\\b c"]),
    ],
)
def test_split_command(text, posix, windows, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert split_command(text) == posix
    monkeypatch.setattr(sys, "platform", "win32")
    assert split_command(text) == windows


def test_split_command_rejects_empty_and_unterminated(monkeypatch):
    for platform in ("linux", "win32"):
        monkeypatch.setattr(sys, "platform", platform)
        with pytest.raises(ValueError):
            split_command("   ")
        with pytest.raises(ValueError):
            split_command('pytest "-k foo')


def test_bare_program_names_never_resolve_from_the_working_directory(tmp_path):
    planted = tmp_path / ("tool.exe" if sys.platform == "win32" else "tool")
    planted.write_text("", encoding="utf-8")
    planted.chmod(0o755)
    # Not on PATH, only in the directory the tests would run in.
    assert resolve_executable("tool", tmp_path, "") is None
    assert resolve_executable("tool", tmp_path, f".{__import__('os').pathsep}") is None
    # An explicit relative path is resolved against that directory.
    assert resolve_executable(f"./{planted.name}", tmp_path, "") is not None
    # And a PATH entry finds it.
    assert resolve_executable("tool", tmp_path, str(tmp_path)) is not None


def test_missing_program_is_reported(tmp_path):
    run = run_test_command(TestCommand(argv=("nephilex-no-such-program-xyz",), timeout=5), tmp_path)
    assert run.status == "error" and "not found" in (run.error or "")
