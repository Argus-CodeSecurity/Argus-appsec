"""Attack-chain correlation: connect findings into breach paths."""

from __future__ import annotations

from argus.analysis.attack_chains import find_chains
from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.models import Finding, Location, Severity
from argus.core.project import Project


def _f(rule_id, *, path="a.py", cwe=None, scanner="x", line=1) -> Finding:
    return Finding(
        id=rule_id,
        rule_id=rule_id,
        scanner=scanner,
        title="t",
        description="d",
        location=Location(path=path, start_line=line),
        severity=Severity.MEDIUM,
        cwe=cwe or [],
    )


def test_llm_injection_to_execution_chain():
    chains = find_chains(
        [
            _f("llm.prompt-injection", scanner="llm"),
            _f("llm.insecure-output-handling", scanner="llm"),
        ]
    )
    assert any(c.id == "llm-injection-to-execution" for c in chains)
    assert chains[0].severity == Severity.CRITICAL


def test_llm_chain_cites_owasp_llm_2025_ids():
    import re

    (chain,) = find_chains(
        [
            _f("llm.prompt-injection", scanner="llm"),
            _f("llm.insecure-output-handling", scanner="llm"),
        ]
    )
    # 2025 list: LLM05 Improper Output Handling, LLM06 Excessive Agency. The
    # 2023 ids (LLM02 output handling, LLM08 agency) must not come back.
    assert "LLM05" in chain.narrative and "LLM06" in chain.narrative
    assert not re.search(r"LLM0[28]\b", chain.narrative)


def test_secret_plus_injection_chain():
    chains = find_chains(
        [
            _f("secrets.aws-access-key-id", scanner="secrets"),
            _f("patterns.python-shell-true", cwe=["CWE-78"], scanner="patterns"),
        ]
    )
    assert any(c.id == "secret-plus-injection" for c in chains)


def test_no_chain_for_unrelated_findings():
    assert find_chains([_f("patterns.weak-hash", cwe=["CWE-327"])]) == []


def test_chain_requires_same_component():
    assert (
        find_chains(
            [
                _f("llm.prompt-injection", path="a.py", scanner="llm"),
                _f("llm.insecure-output-handling", path="b.py", scanner="llm"),
            ]
        )
        == []
    )


def test_history_secret_does_not_form_injection_chain():
    # A secret found only in history is not co-located with the injection.
    assert (
        find_chains(
            [
                _f("secrets.history.aws-access-key-id", scanner="secrets"),
                _f("patterns.python-shell-true", cwe=["CWE-78"], scanner="patterns"),
            ]
        )
        == []
    )


def test_chain_finding_shape():
    finding = find_chains(
        [
            _f("llm.prompt-injection", scanner="llm"),
            _f("llm.insecure-output-handling", scanner="llm"),
        ]
    )[0].to_finding()
    assert finding.rule_id == "chains.llm-injection-to-execution"
    assert finding.scanner == "chains"
    assert "attack-chain" in finding.tags
    assert finding.metadata["chain_members"]


def test_engine_emits_llm_chain(tmp_path):
    (tmp_path / "agent.py").write_text(
        "import openai\n"
        "def run(request):\n"
        '    prompt = "Q: " + request.args.get("q")\n'
        '    resp = openai.ChatCompletion.create(model="gpt-4", messages=[{"role": "user", "content": prompt}])\n'
        "    out = resp.choices[0].message.content\n"
        "    eval(out)\n",
        encoding="utf-8",
    )
    cfg = Config(scanner_options={"dependencies": {"online": False}})
    result = ScanEngine(cfg).scan(Project.from_path(tmp_path))
    assert any(f.rule_id == "chains.llm-injection-to-execution" for f in result.findings)
