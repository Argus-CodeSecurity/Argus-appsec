"""SARIF import: parsing untrusted input, mapping to findings, de-duplication."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from nephilex.core.models import Confidence, Finding, Location, Severity
from nephilex.core.project import Project
from nephilex.importers import (
    SarifImportError,
    import_sarif,
    load_sarif,
    merge_findings,
    parse_sarif,
)

FIXTURES = Path(__file__).parent / "fixtures" / "sarif"


def _fixture(name: str) -> Path:
    return FIXTURES / f"{name}.sarif"


def _import(project: Project, *names: str):
    return import_sarif([_fixture(n) for n in names], project_root=project.root)


def _by_rule(findings: list[Finding], suffix: str) -> Finding:
    matches = [f for f in findings if f.rule_id.endswith(suffix)]
    assert len(matches) == 1, [f.rule_id for f in findings]
    return matches[0]


def _doc(results: list, rules: list | None = None, **run) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "T", "rules": rules or []}}, "results": results, **run}
        ],
    }


def _result(uri: str = "app.py", line: int | None = 1, **extra) -> dict:
    region = {"startLine": line} if line is not None else {}
    loc = {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}
    return {"ruleId": "R1", "message": {"text": "m"}, "locations": [loc], **extra}


# --- per-tool fixtures ------------------------------------------------------------
@pytest.mark.parametrize(
    ("name", "scanner", "count"),
    [
        ("semgrep", "sarif:semgrep-oss", 2),
        ("codeql", "sarif:codeql", 3),
        ("gitleaks", "sarif:gitleaks", 2),
        ("trivy", "sarif:trivy", 2),
        ("bandit", "sarif:bandit", 3),
    ],
)
def test_tool_fixtures_import(vulnerable_project, name, scanner, count):
    out = _import(vulnerable_project, name)
    assert out.tools == [scanner]
    assert len(out.findings) == count
    for f in out.findings:
        assert f.scanner == scanner
        assert f.rule_id.startswith(scanner.split(":", 1)[1] + ".")
        assert "sarif" in f.tags and scanner.split(":", 1)[1] in f.tags
        assert f.metadata["imported"] is True
        assert f.metadata["sarif"]["rule_id"] in f.rule_id


def test_semgrep_mapping(vulnerable_project):
    out = _import(vulnerable_project, "semgrep")
    assert out.stats["suppressed"] == 1  # the nosemgrep result
    sql = _by_rule(out.findings, "formatted-sql-query")
    assert sql.cwe == ["CWE-89"]
    assert "A03:2021-Injection" in sql.owasp
    assert sql.severity is Severity.MEDIUM  # level "warning"
    assert sql.location.path == "app.py" and sql.location.start_line == 8
    # Semgrep's shortDescription only repeats the id; the message is the title.
    assert sql.title.startswith("Detected possible formatted SQL query")
    shell = _by_rule(out.findings, "subprocess-shell-true")
    assert shell.severity is Severity.HIGH  # security-severity 7.3
    assert shell.remediation and shell.remediation.references[0].startswith("https://semgrep.dev/")


def test_codeql_mapping(vulnerable_project):
    out = _import(vulnerable_project, "codeql")
    sql = _by_rule(out.findings, "py/sql-injection")
    assert sql.title == "SQL query built from user-controlled sources"  # from the extension
    assert sql.cwe == ["CWE-89"]  # external/cwe/cwe-089
    assert sql.severity is Severity.HIGH  # security-severity 8.8
    assert sql.confidence is Confidence.MEDIUM  # precision high, one step down
    assert sql.metadata["sarif"]["fingerprints"]["primaryLocationLineHash"]
    # No snippet in the SARIF: it is read from the project file.
    assert sql.location.snippet == "cursor.execute(\"SELECT * FROM users WHERE id = '%s'\" % uid)"
    hashing = _by_rule(out.findings, "weak-sensitive-data-hashing")
    assert hashing.cwe == ["CWE-327", "CWE-328", "CWE-916"]
    unused = _by_rule(out.findings, "py/unused-import")
    assert unused.severity is Severity.LOW  # problem.severity recommendation
    assert unused.location.path == "app.py"  # resolved through run.artifacts[0]
    # %SRCROOT% names the CI checkout; paths were re-anchored on our root.
    assert any("uriBaseId points outside" in w for w in out.warnings)


def test_trivy_mapping(vulnerable_project):
    out = _import(vulnerable_project, "trivy")
    cve = _by_rule(out.findings, "CVE-2020-14343")
    assert cve.severity is Severity.CRITICAL  # 9.8
    assert cve.location.path == "requirements.txt"  # ROOTPATH file:/// is the root
    assert cve.location.snippet == "pyyaml==5.3.1"
    assert cve.metadata["cve"] == "CVE-2020-14343"
    assert cve.remediation and cve.remediation.summary == "Vulnerability CVE-2020-14343"
    assert _by_rule(out.findings, "DS001").severity is Severity.MEDIUM


def test_bandit_mapping(vulnerable_project):
    out = _import(vulnerable_project, "bandit")
    shell = _by_rule(out.findings, "B602")
    assert shell.severity is Severity.HIGH  # issue_severity
    assert shell.cwe == ["CWE-78"]
    assert shell.confidence is Confidence.MEDIUM
    assert shell.title.startswith("subprocess call with shell=True")
    assert _by_rule(out.findings, "B506").severity is Severity.MEDIUM


# --- secrets ------------------------------------------------------------------------
def test_gitleaks_secrets_never_stored(vulnerable_project):
    out = _import(vulnerable_project, "gitleaks")
    dumped = json.dumps([f.model_dump(mode="json") for f in out.findings])
    assert "AKIAIOSFODNN7EXAMPLE" not in dumped
    assert "f3c9a1e7b2d84a60c5e19b7d3a2f8e41" not in dumped
    aws = _by_rule(out.findings, "aws-access-token")
    assert aws.cwe == ["CWE-798"]
    assert aws.severity is Severity.HIGH  # no level at all: secrets default high
    assert aws.title == "AWS Access Token"
    # Same redacted line as Nephilex's own secrets scanner records.
    assert aws.location.snippet == 'AWS_ACCESS_KEY_ID = "AKI\u2026 [redacted, 20 chars]"'
    # The file does not exist: the bare value from the SARIF is masked whole.
    generic = _by_rule(out.findings, "generic-api-key")
    assert generic.location.snippet == "f3c\u2026 [redacted, 32 chars]"


def test_secret_reported_by_column_span_is_masked(tmp_path):
    # "hint" is not a secret-looking name, so only the reported span finds it.
    (tmp_path / "conf.py").write_text('hint = "q8Zr2LmN0pXv7Tk"\n', encoding="utf-8")
    doc = _doc(
        [
            _result(
                "conf.py",
                1,
                message={"text": "found q8Zr2LmN0pXv7Tk"},
            )
        ],
        rules=[{"id": "R1", "properties": {"tags": ["secret"]}}],
    )
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"].update(
        {"startColumn": 9, "endColumn": 24}
    )
    (f,) = parse_sarif(doc, project_root=tmp_path).findings
    dumped = f.model_dump_json()
    assert "q8Zr2LmN0pXv7Tk" not in dumped
    assert f.location.snippet == 'hint = "q8Z\u2026 [redacted, 15 chars]"'


def test_edge_case_secret_scrubbed_from_message(tmp_path):
    out = import_sarif([_fixture("edge-cases")], project_root=tmp_path)
    dumped = json.dumps([f.model_dump(mode="json") for f in out.findings])
    assert "Tr0ub4dor-3xampleP4ss" not in dumped
    pw = _by_rule(out.findings, "EC002")
    assert pw.severity is Severity.CRITICAL  # security-severity 9.1
    assert pw.cwe == ["CWE-259"]
    assert "[redacted" in pw.description


# --- untrusted input ------------------------------------------------------------------
def test_edge_cases(tmp_path):
    out = import_sarif([_fixture("edge-cases")], project_root=tmp_path)
    stats = out.stats
    assert stats["results"] == 13
    assert stats["unsafe_path"] == 4  # /etc/passwd, C:/Windows, ../, %2e%2e
    assert stats["not_a_problem"] == 1 and stats["absent"] == 1 and stats["invalid"] == 1
    assert sum("dropped" in w for w in out.warnings) == 4
    paths = {f.location.path for f in out.findings}
    assert paths == {
        "app.py",
        "src/my file.py",
        "src/win/path.py",
        "db.py",
        "(com.example.Billing.charge)",
        "(Edge Case Scanner)",
    }
    dumped = json.dumps([f.model_dump(mode="json") for f in out.findings])
    assert "passwd" not in dumped and "shadow" not in dumped
    assert "\\u001b" not in dumped and "[31m" not in dumped  # ANSI escapes stripped
    traversal = [f for f in out.findings if f.location.path == "app.py"][0]
    assert traversal.cwe == ["CWE-22"]  # from rule.relationships
    assert traversal.location.start_line is None  # no region: file-level
    assert traversal.remediation is None  # javascript: helpUri is not kept
    logical = _by_rule(out.findings, "EC003")
    assert logical.cwe == ["CWE-862"]  # result.taxa by index
    assert logical.severity is Severity.MEDIUM  # nested problem.severity; level 5 ignored
    assert logical.title == "Missing authorization check RED"
    # startLine "3" (a string) is not a line number.
    assert [f for f in out.findings if f.location.path == "src/win/path.py"][
        0
    ].location.start_line is None


def test_deeply_nested_input_is_rejected(tmp_path):
    with pytest.raises(SarifImportError, match="nests deeper"):
        load_sarif(_fixture("deep-nesting"))
    hostile = tmp_path / "bomb.sarif"
    hostile.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    with pytest.raises(SarifImportError, match="nested too deeply|nests deeper"):
        load_sarif(hostile)


def test_oversized_input_is_rejected():
    with pytest.raises(SarifImportError, match="import limit"):
        load_sarif(_fixture("semgrep"), max_bytes=1_000)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{not json", "not valid JSON"),
        ('{"version": "2.1.0", "runs": [{"x": NaN}]}', "non-standard JSON constant"),
        ("[]", "expected a JSON object"),
        ('{"version": "2.1.0"}', "no 'runs' array"),
        ('{"version": "2.0.0", "runs": []}', "only 2.1.0"),
    ],
)
def test_malformed_files_are_rejected(tmp_path, content, message):
    bad = tmp_path / "bad.sarif"
    bad.write_text(content, encoding="utf-8")
    with pytest.raises(SarifImportError, match=message):
        import_sarif([bad], project_root=tmp_path)


def test_non_utf8_and_missing_files_are_rejected(tmp_path):
    bad = tmp_path / "latin1.sarif"
    bad.write_bytes(b'{"runs": [], "x": "\xe9"}')
    with pytest.raises(SarifImportError, match="UTF-8"):
        load_sarif(bad)
    with pytest.raises(SarifImportError, match="cannot read"):
        load_sarif(tmp_path / "missing.sarif")


def test_result_cap(tmp_path):
    doc = _doc([_result(line=i) for i in range(1, 6)])
    with pytest.raises(SarifImportError, match="more than 3 results"):
        parse_sarif(doc, project_root=tmp_path, max_results=3)


def test_absolute_uri_inside_root_is_made_relative(tmp_path):
    (tmp_path / "pkg").mkdir()
    target = tmp_path / "pkg" / "mod.py"
    target.write_text("x = 1\n", encoding="utf-8")
    doc = _doc([_result(target.as_uri(), 1), _result(str(target), 1)])
    out = parse_sarif(doc, project_root=tmp_path)
    assert [f.location.path for f in out.findings] == ["pkg/mod.py", "pkg/mod.py"]
    assert out.findings[0].location.snippet == "x = 1"


def test_base_id_inside_root_and_relative_bases(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("a = 1\n", encoding="utf-8")
    bases = {
        "SRC": {"uri": (tmp_path / "src").as_uri() + "/"},
        "REL": {"uri": "src/"},
        "UP": {"uri": "../"},
    }
    results = [
        {**_result("a.py"), "locations": [_loc("a.py", "SRC")]},
        {**_result("a.py"), "locations": [_loc("a.py", "REL")]},
        {**_result("a.py"), "locations": [_loc("a.py", "UP")]},
    ]
    out = parse_sarif(_doc(results, originalUriBaseIds=bases), project_root=tmp_path)
    assert [f.location.path for f in out.findings] == ["src/a.py", "src/a.py"]
    assert out.stats["unsafe_path"] == 1


def _loc(uri: str, base: str) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": base},
            "region": {"startLine": 1},
        }
    }


def test_symlink_outside_root_is_never_read(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("TOP-SECRET-CONTENT\n", encoding="utf-8")
    try:
        os.symlink(outside, root / "link.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")
    out = parse_sarif(_doc([_result("link.py", 1)]), project_root=root)
    assert out.findings[0].location.snippet is None


def test_unsupported_schemes_and_unc_paths_are_dropped(tmp_path):
    results = [
        _result("ftp://host/a.py"),
        _result("//server/share/a.py"),
        _result("file://otherhost/a.py"),
        _result("C:/outside/a.py"),
        _result("src/C:evil.py"),  # drive-relative segment
        _result("javascript:alert(1)"),
    ]
    out = parse_sarif(_doc(results), project_root=tmp_path)
    assert out.findings == []
    assert out.stats["unsafe_path"] == 6


def test_https_location_is_kept_as_external(tmp_path):
    out = parse_sarif(_doc([_result("https://app.example/login", None)]), project_root=tmp_path)
    assert out.findings[0].location.path == "https://app.example/login"


def test_message_arguments_and_message_strings(tmp_path):
    rules = [{"id": "R1", "messageStrings": {"default": {"text": "Value {0} reaches {1}."}}}]
    results = [_result(message={"id": "default", "arguments": ["x", "sink"]})]
    (f,) = parse_sarif(_doc(results, rules), project_root=tmp_path).findings
    assert f.description == "Value x reaches sink."


# --- identity --------------------------------------------------------------------------
def test_ids_and_fingerprints_survive_line_shifts(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    fp = {"primaryLocationLineHash": "abc:1"}
    before = parse_sarif(
        _doc([_result("app.py", 2, partialFingerprints=fp)]), project_root=tmp_path
    ).findings[0]
    src.write_text("import os\n\n\nos.system(cmd)\n", encoding="utf-8")
    after = parse_sarif(
        _doc([_result("app.py", 4, partialFingerprints=fp)]), project_root=tmp_path
    ).findings[0]
    assert before.id == after.id
    assert before.fingerprint() == after.fingerprint()  # what baselines match on


def test_fallback_id_uses_location_and_snippet(tmp_path):
    (tmp_path / "app.py").write_text("a()\nb()\n", encoding="utf-8")
    out = parse_sarif(_doc([_result("app.py", 1), _result("app.py", 2)]), project_root=tmp_path)
    assert len({f.id for f in out.findings}) == 2


def test_identical_results_collapse(tmp_path):
    sarif = tmp_path / "dup.sarif"
    sarif.write_text(json.dumps(_doc([_result(), _result()])), encoding="utf-8")
    out = import_sarif([sarif, sarif], project_root=tmp_path)
    assert len(out.findings) == 1
    assert out.stats["duplicate"] == 3


def test_tool_suppressions_and_kinds(tmp_path):
    results = [
        _result(suppressions=[{"kind": "external", "status": "accepted"}]),
        _result(suppressions=[{"kind": "external", "status": "rejected"}]),
        _result(suppressions=[{"kind": "external", "status": "underReview"}]),
        _result(kind="notApplicable"),
        _result(kind="review"),
    ]
    out = parse_sarif(_doc(results), project_root=tmp_path)
    assert out.stats["suppressed"] == 1 and out.stats["not_a_problem"] == 1
    assert out.stats["imported"] == 3


@pytest.mark.parametrize(
    ("props", "level", "expected"),
    [
        ({"security-severity": "9.0"}, None, Severity.CRITICAL),
        ({"security-severity": 6.1}, "error", Severity.MEDIUM),
        ({"security-severity": "0.0"}, None, Severity.INFO),
        ({"security-severity": "11"}, "note", Severity.LOW),  # out of range: ignored
        ({"security-severity": True}, "none", Severity.INFO),
        ({"problem.severity": "error"}, None, Severity.HIGH),
        ({"severity": "critical"}, None, Severity.CRITICAL),
        ({}, None, Severity.MEDIUM),
    ],
)
def test_severity_sources(tmp_path, props, level, expected):
    result = _result(properties=props)
    if level:
        result["level"] = level
    (f,) = parse_sarif(_doc([result]), project_root=tmp_path).findings
    assert f.severity is expected


def test_inline_suppression_applies_to_trusted_projects_only(tmp_path):
    from nephilex.core.config import Config
    from nephilex.importers import process_imported

    (tmp_path / "app.py").write_text(
        'os.system(cmd)  # nephilex-ignore reason="reviewed"\nos.system(other)\n', encoding="utf-8"
    )
    doc = _doc([_result("app.py", 1), _result("app.py", 2)])
    project = Project.from_path(tmp_path)
    cfg = Config()
    cfg.ai.enabled = False
    cfg.trust_project_config = True
    kept, _ = process_imported(parse_sarif(doc, project_root=tmp_path).findings, project, cfg)
    assert [f.location.start_line for f in kept] == [2]
    cfg.trust_project_config = False
    kept, _ = process_imported(parse_sarif(doc, project_root=tmp_path).findings, project, cfg)
    assert len(kept) == 2


# --- de-duplication ----------------------------------------------------------------------
def _f(scanner: str, line: int | None, cwe: list[str], sev=Severity.MEDIUM, **kw) -> Finding:
    return Finding(
        id=f"{scanner}:{line}",
        rule_id=kw.pop("rule_id", f"{scanner}.r"),
        scanner=scanner,
        title="t",
        description="d",
        location=Location(path=kw.pop("path", "app.py"), start_line=line),
        severity=sev,
        cwe=cwe,
        **kw,
    )


def test_merge_keeps_native_and_records_imported():
    native = _f("ast-python", 8, ["CWE-89"], Severity.MEDIUM)
    dup = _f("sarif:codeql", 9, ["CWE-89"], Severity.HIGH)
    kept, merged = merge_findings([native], [dup])
    assert kept == [native] and merged == 1
    assert native.metadata["also_reported_by"][0]["scanner"] == "sarif:codeql"
    assert native.severity is Severity.HIGH  # never lower a gate by merging
    assert native.metadata["severity_raised_by"] == "sarif:codeql"


def test_merge_keeps_distinct_issues():
    native = _f("ast-python", 8, ["CWE-89"])
    others = [
        _f("sarif:a", 8, ["CWE-78"]),  # different CWE
        _f("sarif:b", 20, ["CWE-89"]),  # far away
        _f("sarif:c", 8, ["CWE-89"], path="other.py"),  # other file
        _f("sarif:d", None, ["CWE-89"]),  # no line
        _f("ast-python", 8, ["CWE-89"], rule_id="ast-python.other"),  # same scanner
    ]
    kept, merged = merge_findings([native], others)
    assert merged == 0 and len(kept) == 6


def test_merge_between_imported_keeps_the_stronger():
    weak = _f("sarif:semgrep", 8, ["CWE-89"], Severity.MEDIUM)
    strong = _f("sarif:codeql", 8, ["CWE-89", "CWE-943"], Severity.HIGH)
    kept, merged = merge_findings([], [weak, strong])
    assert kept == [strong] and merged == 1
    assert strong.metadata["also_reported_by"][0]["scanner"] == "sarif:semgrep"


def test_merge_by_advisory():
    native = _f(
        "dependencies",
        None,
        ["CWE-20"],
        path="requirements.txt",
        rule_id="dependencies.GHSA-8q59-q68h-6hv4",
        metadata={"cve": "CVE-2020-14343"},
    )
    trivy = _f("sarif:trivy", 2, [], path="requirements.txt", rule_id="trivy.CVE-2020-14343")
    kept, merged = merge_findings([native], [trivy])
    assert kept == [native] and merged == 1
