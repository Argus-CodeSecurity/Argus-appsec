"""Tests for the built-in scanners."""

from __future__ import annotations

from nephilex.core.config import Config
from nephilex.core.models import Severity
from nephilex.core.plugin import ScannerContext, registry
from nephilex.scanners.dependencies import _matches_range, _parse_requirements
from nephilex.scanners.secrets import _shannon_entropy


def _run(scanner_name: str, project, config: Config | None = None) -> list:
    from nephilex.analysis.repository import RepositoryAnalyzer

    RepositoryAnalyzer().analyze(project)
    cls = registry.get_scanner(scanner_name)
    ctx = ScannerContext(project=project, config=config or Config(), ai=None)
    return list(cls().scan(ctx))


def _offline_config() -> Config:
    """Force the dependency scanner to use the bundled seed (deterministic tests)."""
    return Config(scanner_options={"dependencies": {"online": False}})


def test_secrets_finds_aws_key(vulnerable_project):
    findings = _run("secrets", vulnerable_project)
    rules = {f.rule_id for f in findings}
    assert "secrets.aws-access-key-id" in rules
    # The credential value must be redacted in the snippet.
    aws = next(f for f in findings if f.rule_id == "secrets.aws-access-key-id")
    assert "AKIAIOSFODNN7EXAMPLE" not in (aws.location.snippet or "")


def test_secrets_clean_project_no_findings(clean_project):
    assert _run("secrets", clean_project) == []


def test_patterns_finds_injection_classes(vulnerable_project):
    findings = _run("patterns", vulnerable_project)
    rules = {f.rule_id for f in findings}
    # SQL injection is detected via either the f-string or the format rule.
    assert rules & {"patterns.python-sql-fstring", "patterns.python-sql-format"}
    assert "patterns.python-shell-true" in rules
    assert "patterns.python-yaml-load" in rules
    assert "patterns.weak-hash-md5-sha1" in rules


def test_patterns_carry_cwe_and_reasoning(vulnerable_project):
    findings = _run("patterns", vulnerable_project)
    sqli = next(f for f in findings if "CWE-89" in f.cwe)
    assert sqli.cwe == ["CWE-89"]
    assert sqli.why_vulnerable and sqli.attacker_perspective and sqli.business_impact


def test_sql_injection_caught_when_query_assigned_then_executed(tmp_path):
    """Regression: an f-string SQL query built into a variable, executed later.

    This is the cross-line case line-anchored, execute()-only patterns miss.
    """
    findings = _run_patterns(
        tmp_path,
        "app.py",
        "def q(username):\n"
        "    query = f\"SELECT * FROM users WHERE name = '{username}'\"\n"
        "    cursor.execute(query)\n",
    )
    sqli = [f for f in findings if "CWE-89" in f.cwe]
    assert len(sqli) == 1  # detected exactly once, no double report
    assert sqli[0].rule_id == "patterns.python-sql-fstring"


def test_inline_execute_fstring_not_double_reported(tmp_path):
    findings = _run_patterns(
        tmp_path,
        "app.py",
        "cursor.execute(f\"SELECT * FROM t WHERE id = '{x}'\")\n",
    )
    assert len([f for f in findings if "CWE-89" in f.cwe]) == 1


# --- path traversal via lightweight taint tracking (cross-line) -------------
def test_path_traversal_tainted_var_across_lines(tmp_path):
    """The case line-anchored rules miss: request input -> variable -> open()."""
    findings = _run_patterns(
        tmp_path,
        "app.py",
        "def read():\n"
        '    filename = request.args.get("file")\n'
        '    with open(filename, "r") as f:\n'
        "        return f.read()\n",
    )
    pt = [f for f in findings if "CWE-22" in f.cwe]
    assert len(pt) == 1
    assert pt[0].rule_id == "patterns.path-traversal-taint"


def test_path_traversal_not_flagged_when_source_is_constant(tmp_path):
    findings = _run_patterns(
        tmp_path,
        "app.py",
        'filename = "config.yml"\nopen(filename)\n',
    )
    assert not [f for f in findings if "CWE-22" in f.cwe]


def test_path_traversal_not_flagged_when_sanitized(tmp_path):
    findings = _run_patterns(
        tmp_path,
        "app.py",
        "from werkzeug.utils import secure_filename\n"
        'filename = secure_filename(request.args.get("file"))\n'
        "open(filename)\n",
    )
    assert not [f for f in findings if "CWE-22" in f.cwe]


def test_dependencies_flags_known_cve(vulnerable_project):
    # Offline mode uses the deterministic bundled advisory seed.
    findings = _run("dependencies", vulnerable_project, _offline_config())
    pkgs = {f.metadata.get("cve") for f in findings}
    assert "CVE-2020-14343" in pkgs  # pyyaml 5.3.1


def test_dependencies_uses_osv_when_online(monkeypatch, vulnerable_project):
    """When online, findings come from OSV; failures fall back to the seed."""
    from nephilex.scanners import osv

    fake = {
        ("flask", "2.0.1"): [
            osv.OSVAdvisory(
                id="GHSA-fake-flask",
                summary="Fake Flask issue",
                severity=Severity.HIGH,
                cve="CVE-9999-0001",
                fixed="2.3.0",
                cwe=["CWE-79"],
                references=["https://example.com/adv"],
            )
        ],
    }
    monkeypatch.setattr(osv, "query", lambda eco, deps, **kw: fake)

    findings = _run("dependencies", vulnerable_project)  # online default
    cves = {f.metadata.get("cve") for f in findings}
    assert "CVE-9999-0001" in cves
    flask_finding = next(f for f in findings if f.metadata.get("cve") == "CVE-9999-0001")
    assert flask_finding.severity == Severity.HIGH
    assert flask_finding.metadata["fixed_version"] == "2.3.0"


def test_dependencies_falls_back_when_osv_errors(monkeypatch, vulnerable_project):
    from nephilex.scanners import osv

    def boom(*a, **k):
        raise osv.OSVError("network down")

    monkeypatch.setattr(osv, "query", boom)
    findings = _run("dependencies", vulnerable_project)  # online, but OSV fails
    # Falls back to the bundled seed, so the known pyyaml CVE still appears.
    assert "CVE-2020-14343" in {f.metadata.get("cve") for f in findings}


def test_iac_flags_root_container(vulnerable_project):
    findings = _run("iac", vulnerable_project)
    rules = {f.rule_id for f in findings}
    assert "iac.docker-user-root" in rules
    assert "iac.docker-latest-tag" in rules


def test_dependency_version_range():
    assert _matches_range("2.0.1", "<2.2.5")
    assert not _matches_range("2.2.5", "<2.2.5")
    assert _matches_range("5.3.1", "<5.4")


def test_requirements_parser():
    deps = _parse_requirements("flask==2.0.1\n# comment\nrequests==2.25.0\n-e .\n")
    assert dict(deps) == {"flask": "2.0.1", "requests": "2.25.0"}


def test_entropy_distinguishes_random_from_words():
    assert _shannon_entropy("password") < _shannon_entropy("aB3$xZ9!qW2#mK7&")


# --- false-positive suppression (validated against real-world scans) ---------
def _run_patterns(tmp_path, rel_path: str, content: str):
    from nephilex.analysis.repository import RepositoryAnalyzer
    from nephilex.core.project import Project

    target = tmp_path / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    cls = registry.get_scanner("patterns")
    return list(cls().scan(ScannerContext(project=project, config=Config(), ai=None)))


def test_weak_hash_suppressed_when_usedforsecurity_false(tmp_path):
    findings = _run_patterns(
        tmp_path, "auth.py", "h = hashlib.md5(x, usedforsecurity=False).hexdigest()\n"
    )
    assert not [f for f in findings if f.rule_id == "patterns.weak-hash-md5-sha1"]
    # But a plain md5 IS still flagged.
    findings2 = _run_patterns(tmp_path, "auth2.py", "h = hashlib.md5(x).hexdigest()\n")
    assert [f for f in findings2 if f.rule_id == "patterns.weak-hash-md5-sha1"]


def test_pickle_roundtrip_suppressed(tmp_path):
    findings = _run_patterns(tmp_path, "m.py", "y = pickle.loads(pickle.dumps(obj))\n")
    assert not [f for f in findings if f.rule_id == "patterns.python-pickle-loads"]


def test_eval_exec_flags_builtins_not_method_calls(tmp_path):
    # The bare builtins are still flagged.
    for code in ("r = eval(user_input)\n", "exec(compile(src, 'x', 'exec'))\n"):
        findings = _run_patterns(tmp_path, "a.py", code)
        assert [f for f in findings if f.rule_id == "patterns.python-eval-exec"], code

    # Method calls named exec/eval are NOT the builtins and must not be flagged:
    # SQLModel's session.exec() and a DB cursor.exec() are safe APIs.
    safe = (
        "rows = session.exec(select(Project).where(Project.id == pid)).all()\n"
        "cur.exec('noop')\n"
        "self.eval(model_output)\n"
    )
    findings = _run_patterns(tmp_path, "store.py", safe)
    # (_run_patterns scans the whole tmp dir, so scope the check to store.py.)
    assert not [
        f
        for f in findings
        if f.rule_id == "patterns.python-eval-exec" and f.location.path == "store.py"
    ]


def test_test_file_findings_are_downgraded(tmp_path):
    from nephilex.core.models import Confidence, Severity

    findings = _run_patterns(tmp_path, "tests/test_x.py", "r = requests.get(url, verify=False)\n")
    tls = [f for f in findings if f.rule_id == "patterns.tls-verify-disabled"]
    assert tls, "should still report, just downgraded"
    assert tls[0].severity < Severity.HIGH  # downgraded from HIGH
    assert tls[0].confidence == Confidence.LOW
    assert "test-context" in tls[0].tags


def test_private_key_in_tests_dir_downgraded(clean_project, tmp_path):
    from nephilex.core.models import Severity

    # A private key committed under a top-level tests/ dir is test material.
    key = tmp_path / "tests" / "certs" / "server.key"
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text(
        "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\n", encoding="utf-8"
    )
    from nephilex.core.project import Project

    project = Project.from_path(tmp_path)
    cls = registry.get_scanner("secrets")
    findings = list(cls().scan(ScannerContext(project=project, config=Config(), ai=None)))
    pk = [f for f in findings if f.rule_id == "secrets.private-key-block"]
    assert pk, "still detected"
    assert pk[0].severity <= Severity.LOW  # downgraded, not Critical
