"""Regression tests for the Phase-0 trust/robustness hardening.

Covers the fixes that continuous, unattended running would otherwise amplify:

* the ``FileRef.text()`` data race under parallel scanning,
* the ``git add -A`` hazard in ``argus fix`` (dirty tree + scoped staging),
* untrusted-repo rule injection / ReDoS via the ``.argus/rules`` convention dir,
* the ``torch.load`` / ``yaml.load`` rewrites that used to "verify" while broken.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from argus.core.config import Config
from argus.core.plugin import ScannerContext
from argus.core.project import FileRef, Project
from argus.remediation.pullrequest import FixOptions, run_fix_workflow
from argus.remediation.rewrites import fix_line, verify_line_fixed
from argus.scanners.custom_rules import _is_catastrophic, load_custom_rules
from argus.scanners.patterns import RULES as BUILTIN_RULES
from argus.scanners.patterns import PatternScanner

git_missing = shutil.which("git") is None


# --- FileRef.text() thread safety ------------------------------------------
def test_fileref_text_is_threadsafe(tmp_path: Path):
    """Many threads reading one fresh FileRef must all see the full content.

    Before the fix, a racing reader could observe the in-progress read as "".
    """
    content = "payload-line\n" * 5000  # big enough to widen the read window
    p = tmp_path / "big.py"
    p.write_text(content, encoding="utf-8")

    def read(ref: FileRef, out: list[str], gate: threading.Barrier) -> None:
        gate.wait()  # release all threads at once to contend on the read
        out.append(ref.text())

    for _ in range(50):  # repeat to make the race likely if it exists
        ref = FileRef(path=p, rel_path="big.py", size=len(content))
        results: list[str] = []
        gate = threading.Barrier(8)
        threads = [threading.Thread(target=read, args=(ref, results, gate)) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(r == content for r in results), "a thread saw partial/empty content"


# --- ReDoS guard on custom rules -------------------------------------------
def test_catastrophic_pattern_detector():
    assert _is_catastrophic("(a+)+$") is True
    assert _is_catastrophic("([a-z]*)+") is True
    assert _is_catastrophic(r"\bAKIA[0-9A-Z]{16}\b") is False
    assert _is_catastrophic(r"password\s*=\s*['\"].+['\"]") is False


def test_redos_rule_is_rejected(tmp_path: Path):
    rules = tmp_path / ".argus" / "rules"
    rules.mkdir(parents=True)
    (rules / "r.yml").write_text(
        "rules:\n"
        "  - id: ok\n    pattern: 'TODO'\n    severity: low\n"
        "  - id: bad\n    pattern: '(a+)+$'\n    severity: low\n",
        encoding="utf-8",
    )
    loaded = load_custom_rules(tmp_path, None, include_convention_dir=True)
    assert [r.id for r in loaded] == ["ok"]  # the ReDoS rule is dropped


# --- untrusted-repo rule injection gate ------------------------------------
def test_untrusted_repo_ignores_convention_rules(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    rules = tmp_path / ".argus" / "rules"
    rules.mkdir(parents=True)
    (rules / "r.yml").write_text(
        "rules:\n  - id: benign\n    pattern: 'TODO'\n    severity: low\n",
        encoding="utf-8",
    )

    # Trusted: the in-repo rule loads; untrusted: it must not.
    assert [r.id for r in load_custom_rules(tmp_path, None, True)] == ["benign"]
    assert load_custom_rules(tmp_path, None, False) == []

    # And through the scanner, driven by config.trust_project_config.
    scanner = PatternScanner()
    project = Project.from_path(tmp_path)
    trusted = Config()
    trusted.trust_project_config = True
    untrusted = Config()
    untrusted.trust_project_config = False
    n_trusted = len(scanner._effective_rules(ScannerContext(project=project, config=trusted)))
    n_untrusted = len(scanner._effective_rules(ScannerContext(project=project, config=untrusted)))
    assert n_trusted == len(BUILTIN_RULES) + 1
    assert n_untrusted == len(BUILTIN_RULES)


# --- torch.load / yaml.load rewrite correctness ----------------------------
def test_torch_load_nested_paren_fix_is_correct_and_verified():
    src = 'w = torch.load(f, map_location=torch.device("cpu"))'
    fixed = fix_line("llm.torch-load-pickle", src)
    # The keyword lands on the torch.load call, NOT the inner torch.device call.
    assert fixed == 'w = torch.load(f, map_location=torch.device("cpu"), weights_only=True)'
    assert verify_line_fixed("llm.torch-load-pickle", fixed) is True


def test_torch_load_unbalanced_line_is_left_alone():
    # Call that doesn't close on this line -> no risky single-line rewrite.
    assert fix_line("llm.torch-load-pickle", "w = torch.load(f,") is None


def test_yaml_load_with_loader_is_not_autofixed():
    # safe_load takes no Loader= kwarg; rewriting would raise TypeError at runtime.
    assert (
        fix_line("patterns.python-yaml-load", "cfg = yaml.load(raw, Loader=yaml.FullLoader)")
        is None
    )


def test_yaml_load_plain_is_fixed_and_verified():
    fixed = fix_line("patterns.python-yaml-load", "cfg = yaml.load(raw)")
    assert fixed == "cfg = yaml.safe_load(raw)"
    assert verify_line_fixed("patterns.python-yaml-load", fixed) is True


# --- git dirty-tree guard + scoped staging ---------------------------------
def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _init_repo(tmp_path: Path) -> Path:
    (tmp_path / "a.py").write_text(
        "import yaml\nx = yaml.load(open('c').read())\n", encoding="utf-8"
    )
    (tmp_path / "unrelated.py").write_text("WIP = 1\n", encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    return tmp_path


def _yaml_finding():
    from argus.core.models import Finding, Location, Severity

    return Finding(
        id="patterns:python-yaml-load:1",
        rule_id="patterns.python-yaml-load",
        scanner="patterns",
        title="yaml.load",
        description="",
        location=Location(path="a.py", start_line=2),
        severity=Severity.HIGH,
    )


@pytest.mark.skipif(git_missing, reason="git not available")
def test_fix_workflow_refuses_dirty_tree(tmp_path: Path):
    repo = _init_repo(tmp_path)
    (repo / "unrelated.py").write_text("WIP = 2  # uncommitted\n", encoding="utf-8")
    outcome = run_fix_workflow(
        Project.from_path(repo), [_yaml_finding()], FixOptions(open_pr=False)
    )
    assert outcome.error and "uncommitted" in outcome.error
    assert not outcome.committed


@pytest.mark.skipif(git_missing, reason="git not available")
def test_fix_workflow_stages_only_changed_files(tmp_path: Path):
    repo = _init_repo(tmp_path)  # clean tree
    outcome = run_fix_workflow(
        Project.from_path(repo), [_yaml_finding()], FixOptions(open_pr=False)
    )
    assert outcome.committed
    committed = subprocess.run(
        ["git", "-C", str(repo), "show", "--name-only", "--pretty=format:", "HEAD"],
        capture_output=True,
        text=True,
    ).stdout.split()
    # unrelated.py is never swept in; the audit log of the fix is committed with it
    assert [p for p in committed if p != ".argus/audit.log"] == ["a.py"]
