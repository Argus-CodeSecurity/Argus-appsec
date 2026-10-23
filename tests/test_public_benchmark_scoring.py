"""Unit tests for the public-benchmark scoring code (benchmarks/public).

The scoring code decides every published precision/recall number, so its edge
cases are pinned here: CWE parsing, OWASP case mapping, strict vs mapped CWE
matching, undefined metrics, and the tool-output parsers.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from benchmarks.public import datasets, mapping, tools
from benchmarks.public.scoring import (
    Finding,
    LabeledSample,
    OwaspCase,
    confusion_metrics,
    finding_matches,
    owasp_case_id,
    parse_cwe,
    score_labeled_recall,
    score_owasp,
)


def _f(file: str, *cwes: int, rule: str = "r") -> Finding:
    return Finding(file=file, line=1, rule_id=rule, cwes=frozenset(cwes))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (78, 78),
        ("78", 78),
        ("CWE-78", 78),
        ("CWE-078", 78),
        ("cwe-89: Improper Neutralization of Special Elements", 89),
        ("CWE-1204", 1204),
        ("", None),
        ("n/a", None),
        (None, None),
        (True, None),
        (0, None),
    ],
)
def test_parse_cwe(raw: object, expected: int | None) -> None:
    assert parse_cwe(raw) == expected


def test_owasp_case_id_only_matches_test_case_sources() -> None:
    assert owasp_case_id("testcode/BenchmarkTest00042.py") == "BenchmarkTest00042"
    assert owasp_case_id("testcode\\BenchmarkTest00042.py") == "BenchmarkTest00042"
    # The matching HTML template and helper modules are not test cases.
    assert owasp_case_id("templates/web/x/BenchmarkTest00042.html") is None
    assert owasp_case_id("helpers/utils.py") is None


def test_strict_needs_exact_cwe_and_mapped_uses_groups() -> None:
    weak_hash = _f("a.py", 327)
    assert not finding_matches("nephilex", weak_hash, 328, "strict")
    assert finding_matches("nephilex", weak_hash, 328, "mapped")
    # Unrelated CWEs never match in either mode.
    assert not finding_matches("nephilex", _f("a.py", 79), 89, "mapped")
    with pytest.raises(ValueError):
        finding_matches("nephilex", weak_hash, 328, "fuzzy")


def test_rule_override_applies_only_in_mapped_mode_and_only_to_its_tool() -> None:
    xml = _f("a.py", 20, rule="B317")
    assert ("bandit", "B317") in mapping.RULE_OVERRIDES
    assert finding_matches("bandit", xml, 611, "mapped")
    assert not finding_matches("bandit", xml, 611, "strict")
    assert not finding_matches("semgrep", xml, 611, "mapped")


def test_accepted_cwes_is_label_plus_groups() -> None:
    assert mapping.accepted_cwes(22) >= {22, 23, 36}
    assert mapping.accepted_cwes(501) == {501}


def test_confusion_metrics_values_and_undefined() -> None:
    m = confusion_metrics(tp=3, fp=1, tn=3, fn=1)
    assert m["tpr"] == 0.75
    assert m["fpr"] == 0.25
    assert m["precision"] == 0.75
    assert m["f1"] == 0.75
    assert m["score"] == 0.5
    empty = confusion_metrics(tp=0, fp=0, tn=5, fn=0)
    # No vulnerable cases and no flags: TPR and precision are undefined, not 100%.
    assert empty["tpr"] is None
    assert empty["precision"] is None
    assert empty["f1"] is None
    assert empty["score"] is None
    assert empty["fpr"] == 0.0
    missed_all = confusion_metrics(tp=0, fp=0, tn=1, fn=2)
    assert missed_all["precision"] is None
    assert missed_all["tpr"] == 0.0


def test_score_owasp_counts_and_ignores_other_cwes_in_file() -> None:
    cases = [
        OwaspCase("BenchmarkTest00001", "sqli", 89, True),
        OwaspCase("BenchmarkTest00002", "sqli", 89, False),
        OwaspCase("BenchmarkTest00003", "sqli", 89, True),
        OwaspCase("BenchmarkTest00004", "xss", 79, False),
    ]
    findings = [
        _f("testcode/BenchmarkTest00001.py", 89),  # TP
        _f("testcode/BenchmarkTest00002.py", 89),  # FP
        _f("testcode/BenchmarkTest00003.py", 79),  # wrong CWE: still FN
        _f("testcode/BenchmarkTest00004.py", 89),  # wrong CWE: still TN
        _f("helpers/db.py", 89),  # not a test case
    ]
    out = score_owasp(cases, findings, "nephilex", "strict")
    sqli = out["per_category"]["sqli"]
    assert (sqli["tp"], sqli["fp"], sqli["tn"], sqli["fn"]) == (1, 1, 0, 1)
    assert sqli["fn_cases"] == ["BenchmarkTest00003"]
    assert sqli["fp_cases"] == ["BenchmarkTest00002"]
    xss = out["per_category"]["xss"]
    assert (xss["tp"], xss["fp"], xss["tn"], xss["fn"]) == (0, 0, 1, 0)
    overall = out["overall"]
    assert (overall["tp"], overall["fp"], overall["tn"], overall["fn"]) == (1, 1, 1, 1)
    # Category average skips the undefined xss score rather than counting it as 0.
    assert overall["category_average"]["score"] == pytest.approx(0.5 - 1.0)


def test_score_labeled_recall_modes() -> None:
    samples = [
        LabeledSample("CWE-089_a.py", 89),
        LabeledSample("CWE-089_b.py", 89),
        LabeledSample("CWE-327_a.py", 327),
    ]
    findings = [
        _f("samples/CWE-089_a.py", 89),
        _f("samples/CWE-089_b.py", 798),  # some finding, wrong CWE
        _f("samples/CWE-327_a.py", 328),  # related CWE
    ]
    strict = score_labeled_recall(samples, findings, "nephilex", "strict")["overall"]
    mapped = score_labeled_recall(samples, findings, "nephilex", "mapped")["overall"]
    anyf = score_labeled_recall(samples, findings, "nephilex", "any")["overall"]
    assert (strict["detected"], mapped["detected"], anyf["detected"]) == (1, 2, 3)
    assert strict["samples"] == 3
    assert mapped["cwe_average_recall"] == pytest.approx((0.5 + 1.0) / 2)
    per = score_labeled_recall(samples, findings, "nephilex", "strict")["per_cwe"]
    assert per["CWE-89"]["missed"] == ["CWE-089_b.py"]


def test_parse_owasp_expected_and_securityeval_ids() -> None:
    text = (
        "# test name, category, real vulnerability, cwe, Benchmark version: 0.1\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00002,hash,false,328\n"
    )
    cases = datasets.parse_owasp_expected(text)
    assert cases == [
        OwaspCase("BenchmarkTest00001", "pathtraver", 22, True),
        OwaspCase("BenchmarkTest00002", "hash", 328, False),
    ]
    with pytest.raises(ValueError):
        datasets.parse_owasp_expected("BenchmarkTest00003,sqli,maybe,89\n")
    samples = datasets.parse_securityeval_ids(["CWE-020_author_1.py", "CWE-1204_sonar_1.py"])
    assert [s.cwe for s in samples] == [20, 1204]


def test_tool_parsers_normalize_paths_and_cwes(tmp_path: Path) -> None:
    root = tmp_path / "ds"
    target = root / "testcode" / "BenchmarkTest00001.py"
    nephilex = {
        "findings": [
            {
                "rule_id": "ast-python.ast-sql-injection",
                "cwe": ["CWE-89"],
                "location": {"path": "testcode/BenchmarkTest00001.py", "start_line": 7},
            }
        ]
    }
    bandit = {
        "results": [
            {
                "filename": str(target),
                "line_number": 3,
                "test_id": "B608",
                "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"},
            }
        ]
    }
    semgrep = {
        "results": [
            {
                "path": str(target),
                "start": {"line": 5},
                "check_id": "python.lang.security.x",
                "extra": {"metadata": {"cwe": "CWE-89: Improper Neutralization"}},
            }
        ]
    }
    parsed = [
        tools.parse_nephilex(nephilex, root)[0],
        tools.parse_bandit(bandit, root)[0],
        tools.parse_semgrep(semgrep, root)[0],
    ]
    assert {p.file for p in parsed} == {"testcode/BenchmarkTest00001.py"}
    assert all(p.cwes == frozenset({89}) for p in parsed)
    assert [p.rule_id for p in parsed] == [
        "ast-python.ast-sql-injection",
        "B608",
        "python.lang.security.x",
    ]


def test_safe_extract_rejects_path_traversal(tmp_path: Path) -> None:
    import zipfile

    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("repo-abc/ok.txt", "fine")
        zf.writestr("repo-abc/../../escape.txt", "nope")
    with pytest.raises(ValueError):
        datasets._safe_extract(archive, tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()
