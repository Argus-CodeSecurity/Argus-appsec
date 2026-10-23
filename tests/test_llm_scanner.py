"""Tests for the LLM / AI-application security scanner (OWASP LLM Top 10)."""

from __future__ import annotations

from pathlib import Path

from nephilex.analysis.repository import RepositoryAnalyzer
from nephilex.core.config import Config
from nephilex.core.plugin import ScannerContext, registry
from nephilex.core.project import Project


def _scan_llm(tmp_path: Path) -> list:
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    cls = registry.get_scanner("llm")
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return list(cls().scan(ctx))


def _rules(findings) -> set[str]:
    return {f.rule_id for f in findings}


def test_scanner_is_registered():
    assert "llm" in registry.scanners()


def test_only_runs_on_llm_files(tmp_path):
    (tmp_path / "plain.py").write_text(
        "import os\n"
        "def f(x):\n"
        "    return eval(x)\n",  # eval present, but no LLM stack -> not our scope
        encoding="utf-8",
    )
    assert _scan_llm(tmp_path) == []


def test_insecure_output_handling_eval(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def run(q):\n"
        "    resp = client.chat.completions.create(model='gpt-4o', messages=q)\n"
        "    answer = resp.choices[0].message.content\n"
        "    return eval(answer)\n",
        encoding="utf-8",
    )
    findings = _scan_llm(tmp_path)
    out = [f for f in findings if f.rule_id == "llm.insecure-output-handling"]
    assert out, "expected an insecure-output-handling finding"
    assert out[0].owasp == ["LLM05:2025-Improper Output Handling"]
    assert "CWE-95" in out[0].cwe


def test_insecure_output_handling_suppressed_when_parsed(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def run(q):\n"
        "    resp = client.chat.completions.create(model='gpt-4o', messages=q)\n"
        "    answer = resp.choices[0].message.content\n"
        "    data = json.loads(answer)\n"  # sanitized -> not flagged
        "    return data\n",
        encoding="utf-8",
    )
    out = [f for f in _scan_llm(tmp_path) if f.rule_id == "llm.insecure-output-handling"]
    assert out == []


def test_trust_remote_code(tmp_path):
    (tmp_path / "load.py").write_text(
        "from transformers import AutoModel\n"
        "m = AutoModel.from_pretrained('x/y', trust_remote_code=True)\n",
        encoding="utf-8",
    )
    findings = _scan_llm(tmp_path)
    assert "llm.trust-remote-code" in _rules(findings)
    f = next(f for f in findings if f.rule_id == "llm.trust-remote-code")
    assert f.metadata["owasp_llm"] == "LLM03:2025-Supply Chain"


def test_torch_load_pickle_flagged_without_weights_only(tmp_path):
    (tmp_path / "m.py").write_text(
        "import torch\n"
        "from transformers import AutoModel  # marks this an LLM file\n"
        "w = torch.load('model.bin')\n",
        encoding="utf-8",
    )
    assert "llm.torch-load-pickle" in _rules(_scan_llm(tmp_path))


def test_torch_load_safe_with_weights_only(tmp_path):
    (tmp_path / "m.py").write_text(
        "import torch\n"
        "from transformers import AutoModel\n"
        "w = torch.load('model.bin', weights_only=True)\n",
        encoding="utf-8",
    )
    assert "llm.torch-load-pickle" not in _rules(_scan_llm(tmp_path))


def test_secret_in_prompt(tmp_path):
    # A user-role prompt: the line rule (LLM02) reports it, with the key masked.
    (tmp_path / "p.py").write_text(
        "import anthropic\n"
        "prompt = 'Summarize this. Use api_key=\"sk-abc123ABC456def789ghiJKL\"'\n",
        encoding="utf-8",
    )
    findings = _scan_llm(tmp_path)
    f = next(f for f in findings if f.rule_id == "llm.secret-in-prompt")
    assert f.owasp == ["LLM02:2025-Sensitive Information Disclosure"]
    assert "sk-abc123ABC456def789ghiJKL" not in f.location.snippet


def test_secret_in_system_prompt_is_reported_once_as_llm07(tmp_path):
    # In a system prompt the data-flow tier's LLM07 rule replaces the line rule.
    (tmp_path / "p.py").write_text(
        "import anthropic\n"
        "system_prompt = 'You are a bot. Use api_key=\"sk-abc123ABC456def789ghiJKL\"'\n",
        encoding="utf-8",
    )
    findings = _scan_llm(tmp_path)
    assert _rules(findings) == {"llm.secret-in-system-prompt"}
    assert findings[0].owasp == ["LLM07:2025-System Prompt Leakage"]
    assert "sk-abc123ABC456def789ghiJKL" not in findings[0].location.snippet


def test_agent_shell_tool(tmp_path):
    (tmp_path / "a.py").write_text(
        "from langchain.agents import initialize_agent\n"
        "from langchain_experimental.tools import PythonREPLTool\n"
        "tools = [PythonREPLTool()]\n",
        encoding="utf-8",
    )
    findings = _scan_llm(tmp_path)
    assert "llm.agent-shell-tool" in _rules(findings)
    f = next(f for f in findings if f.rule_id == "llm.agent-shell-tool")
    assert f.metadata["owasp_llm"] == "LLM06:2025-Excessive Agency"


def test_prompt_injection_from_request(tmp_path):
    (tmp_path / "p.py").write_text(
        "from openai import OpenAI\n"
        "from flask import request\n"
        "def h():\n"
        "    prompt = 'Answer this: ' + request.args.get('q')\n"
        "    return prompt\n",
        encoding="utf-8",
    )
    assert "llm.prompt-injection" in _rules(_scan_llm(tmp_path))


def test_model_download_over_http(tmp_path):
    (tmp_path / "d.py").write_text(
        "from huggingface_hub import hf_hub_download\n"
        "import requests\n"
        "requests.get('http://example.com/model.bin')\n",
        encoding="utf-8",
    )
    assert "llm.model-download-http" in _rules(_scan_llm(tmp_path))


def test_findings_carry_llm_taxonomy_and_remediation(tmp_path):
    (tmp_path / "load.py").write_text(
        "from transformers import AutoModel\n"
        "m = AutoModel.from_pretrained('x', trust_remote_code=True)\n",
        encoding="utf-8",
    )
    for f in _scan_llm(tmp_path):
        assert f.owasp and f.owasp[0].startswith("LLM")
        assert f.remediation is not None and f.remediation.summary
        assert "ai-security" in f.tags
