"""LLM / AI-application security scanner (mapped to the OWASP Top 10 for LLMs).

Codebases now embed LLM calls, agent frameworks, and model loading everywhere,
and that surface has its own vulnerability classes that generic SAST does not
cover. This scanner is Argus's first-class support for them. It runs only on
files that actually touch an LLM/agent stack (so it stays fast and quiet), and
each finding maps to an OWASP LLM Top-10 category.

Coverage:

* **LLM01 Prompt Injection**, untrusted input concatenated straight into a
  prompt / system message.
* **LLM02 Insecure Output Handling**, a model response flowing into a
  dangerous sink (``eval``/``exec``, ``os.system``, ``subprocess(..., shell=
  True)``, a SQL string, or unescaped HTML). Detected with a light single-file
  taint pass, since this is the highest-value novel case.
* **LLM05 Supply Chain / LLM03 Poisoning**, ``trust_remote_code=True``,
  ``torch.load`` without ``weights_only=True`` (pickle code execution), and
  fetching models/weights over plaintext HTTP.
* **LLM06 Sensitive Information Disclosure**, API keys/credentials interpolated
  into prompt or system-message strings.
* **LLM08 Excessive Agency**, agent tool wiring that grants shell / filesystem
  / arbitrary-HTTP capability (e.g. LangChain ``ShellTool``,
  ``PythonREPLTool``, an MCP server exposing a shell) without evident guarding.

Like the ``patterns`` tier this is regex-plus-light-taint, not full data-flow:
it favors precise, well-known signatures and marks lower-confidence heuristics
as such. It is ``file_local`` so results are cached per file.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from argus.core.plugin import Scanner, ScannerContext, scanner

# Files worth scanning: those that import or reference a known LLM/agent stack.
# Keeps the scanner quiet on non-AI code and cheap on large repos.
_LLM_STACK = re.compile(
    r"(?i)\b("
    r"openai|anthropic|langchain|langgraph|llama_index|llamaindex|litellm|"
    r"cohere|google\.generativeai|google\.genai|vertexai|transformers|"
    r"huggingface_hub|sentence_transformers|ollama|mistralai|"
    r"chat\s*completions?|messages\.create|\.invoke\(|system_prompt|"
    r"model_dump|trust_remote_code|torch\.load"
    r")\b"
)


@dataclass
class LLMRule:
    id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    llm_category: str  # e.g. "LLM01:2025-Prompt Injection"
    cwe: list[str]
    why: str
    attack: str
    impact: str
    fix: str
    confidence: Confidence = Confidence.MEDIUM
    languages: set[str] = field(default_factory=set)
    suppress: re.Pattern[str] | None = None
    references: list[str] = field(default_factory=list)


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p)


_OWASP_LLM_URL = "https://genai.owasp.org/llm-top-10/"

# --- line-level rules ------------------------------------------------------
RULES: list[LLMRule] = [
    # LLM06, secrets baked into prompts / system messages.
    LLMRule(
        id="secret-in-prompt",
        title="API key or credential embedded in a prompt string",
        # A key-ish literal appearing inside a string that also reads like a
        # prompt/system message. Distinct from the secrets scanner: here the
        # risk is the secret being *sent to the model provider*, not just stored.
        pattern=_rx(
            r"(?i)(system_prompt|prompt|messages|content|instruction)\b[^\n]{0,80}"
            r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|api[_\-]?key\s*[:=]\s*['\"][^'\"]{12,})"
        ),
        severity=Severity.HIGH,
        llm_category="LLM06:2025-Sensitive Information Disclosure",
        cwe=["CWE-522", "CWE-200"],
        confidence=Confidence.MEDIUM,
        why="A credential is interpolated into prompt text, so it is transmitted to "
        "the model provider and may be logged, cached, or echoed back in a "
        "completion.",
        attack="A prompt-injection or a provider-side log leak exposes the embedded "
        "key; the model may also be induced to repeat it in its output.",
        impact="Credential compromise for whatever the key protects, plus exposure "
        "to the model vendor's infrastructure.",
        fix="Never place secrets in prompts. Authenticate to downstream services in "
        "your own code and pass the model only the minimum non-secret context.",
        references=[_OWASP_LLM_URL],
    ),
    # LLM05, trusting remote code from a model repo.
    LLMRule(
        id="trust-remote-code",
        title="Model loaded with trust_remote_code=True",
        pattern=_rx(r"trust_remote_code\s*=\s*True"),
        severity=Severity.HIGH,
        llm_category="LLM05:2025-Supply Chain",
        cwe=["CWE-494", "CWE-829"],
        confidence=Confidence.HIGH,
        why="trust_remote_code=True executes arbitrary Python shipped alongside the "
        "model on the Hugging Face Hub at load time.",
        attack="A malicious or compromised model repository runs code in your process "
        "the moment the model is loaded.",
        impact="Remote code execution with the privileges of the loading process.",
        fix="Leave trust_remote_code at its default (False). If custom code is truly "
        "required, vendor and review it, and pin the model revision by commit "
        "hash.",
        references=[_OWASP_LLM_URL],
    ),
    # LLM05 / LLM03, pickle code execution via torch.load.
    LLMRule(
        id="torch-load-pickle",
        title="torch.load without weights_only=True (pickle code execution)",
        # Fire on any torch.load( call and clear it via the suppress idiom when
        # weights_only=True is present. A lookahead bounded by the first ) would
        # miss nested calls like torch.load(f, map_location=torch.device("cpu")).
        pattern=_rx(r"torch\.load\s*\("),
        suppress=_rx(r"weights_only\s*=\s*True"),
        severity=Severity.HIGH,
        llm_category="LLM05:2025-Supply Chain",
        cwe=["CWE-502"],
        confidence=Confidence.MEDIUM,
        languages={"Python"},
        why="torch.load uses pickle by default, which executes arbitrary code while "
        "deserializing an untrusted checkpoint.",
        attack="A crafted .pt/.bin checkpoint runs attacker code during loading.",
        impact="Remote code execution from a poisoned or man-in-the-middled model file.",
        fix="Pass weights_only=True (PyTorch 2.0+), or load weights from a safetensors "
        "file, which cannot carry executable payloads.",
        references=["https://cwe.mitre.org/data/definitions/502.html", _OWASP_LLM_URL],
    ),
    # LLM05, fetching model weights over plaintext HTTP.
    LLMRule(
        id="model-download-http",
        title="Model or weights downloaded over plaintext HTTP",
        pattern=_rx(
            r"(?i)(from_pretrained|hf_hub_download|load_model|get_file|"
            r"urlretrieve|requests\.get)\s*\(\s*['\"]http://[^'\"]+"
        ),
        severity=Severity.MEDIUM,
        llm_category="LLM05:2025-Supply Chain",
        cwe=["CWE-319", "CWE-494"],
        confidence=Confidence.MEDIUM,
        why="Model artifacts fetched over HTTP can be tampered with in transit.",
        attack="A network attacker swaps the weights/config for a poisoned or backdoored artifact.",
        impact="Loading attacker-controlled model data, up to code execution when "
        "combined with pickle-based formats.",
        fix="Use HTTPS, and pin artifacts by revision/hash so a swapped file is detected.",
        references=[_OWASP_LLM_URL],
    ),
    # LLM08, over-privileged agent tools.
    LLMRule(
        id="agent-shell-tool",
        title="Agent granted shell / code-execution capability",
        pattern=_rx(
            r"(?i)\b(ShellTool|PythonREPLTool|PythonAstREPLTool|"
            r"BashProcess|TerminalTool|ComputerTool|exec_tool)\b"
        ),
        severity=Severity.HIGH,
        llm_category="LLM08:2025-Excessive Agency",
        cwe=["CWE-250", "CWE-732"],
        confidence=Confidence.MEDIUM,
        why="An LLM-driven agent is wired to a tool that runs shell commands or "
        "arbitrary code, so a prompt injection can turn model output into "
        "execution.",
        attack="An attacker who can influence the model's input (a webpage, a "
        "document, a user message) makes the agent run commands on your host.",
        impact="Remote code execution / full host compromise driven by untrusted content.",
        fix="Remove shell/code tools from agents exposed to untrusted input, or gate "
        "them behind an allowlist, a sandbox, and human approval for each call.",
        references=[_OWASP_LLM_URL],
    ),
    # LLM08, MCP / tool server exposing dangerous capability broadly.
    LLMRule(
        id="unrestricted-tool-registration",
        title="Tool/function exposed to the model without evident restriction",
        pattern=_rx(
            r"(?i)(allow_dangerous|dangerous_tools?\s*=\s*True|"
            r"allow_code_execution\s*=\s*True)"
        ),
        severity=Severity.HIGH,
        llm_category="LLM08:2025-Excessive Agency",
        cwe=["CWE-732"],
        confidence=Confidence.MEDIUM,
        why="A flag explicitly enables dangerous / code-executing tools for the model.",
        attack="Prompt injection escalates into whatever the enabled tools can do.",
        impact="Excessive agency: the model can take high-impact actions on attacker instruction.",
        fix="Disable dangerous tool flags; expose only least-privilege, allowlisted "
        "tools and require confirmation for irreversible actions.",
        references=[_OWASP_LLM_URL],
    ),
]

# --- taint pass for insecure output handling (LLM02) -----------------------
# Variables assigned from something that looks like a model response.
_LLM_OUTPUT_ASSIGN = re.compile(
    r"""(?x)
    ^\s*(?P<var>[A-Za-z_]\w*)\s*=\s*[^\n]*?
    (?:
        \.chat\.completions\.create | \.completions\.create | \.messages\.create |
        \.responses\.create | \.generate_content | \.generate\b | \.invoke\b |
        \.predict\b | \.run\b | \.chat\b | \.complete\b | ollama\.\w+ |
        choices\s*\[\s*0\s*\]\s*\.message\.content | \.message\.content |
        \.content\b | \.text\b | \.output_text\b
    )
    """
)
# Sinks that must never receive raw model output.
_OUTPUT_SINKS: list[tuple[str, re.Pattern[str], list[str], str]] = [
    ("code-exec", re.compile(r"\b(eval|exec)\s*\("), ["CWE-95"], "passed to eval()/exec()"),
    ("os-system", re.compile(r"\bos\.system\s*\("), ["CWE-78"], "passed to os.system()"),
    (
        "shell-true",
        re.compile(r"subprocess\.(?:run|call|Popen|check_output)\s*\([^\n]*shell\s*=\s*True"),
        ["CWE-78"],
        "run in a shell via subprocess(..., shell=True)",
    ),
    ("sql", re.compile(r"(?i)(execute|executemany)\s*\("), ["CWE-89"], "used to build a SQL query"),
    (
        "html-unescaped",
        re.compile(
            r"(?i)(render_template_string|Markup|\|\s*safe|dangerouslySetInnerHTML|innerHTML\s*=)"
        ),
        ["CWE-79"],
        "rendered as unescaped HTML",
    ),
]
_OUTPUT_SANITIZER = re.compile(
    r"(?i)(json\.loads|ast\.literal_eval|shlex\.quote|escape\(|bleach\.|"
    r"pydantic|validate|allowlist|whitelist|int\(|float\()"
)


@scanner
class LLMScanner(Scanner):
    name = "llm"
    category = "llm"
    file_local = True
    description = "Security checks for LLM/agent code (OWASP Top 10 for LLM Apps)."

    _CODE_LANGS = {"Python", "JavaScript", "TypeScript"}

    def applies_to(self, project) -> bool:
        return any(
            f.language in self._CODE_LANGS and _LLM_STACK.search(f.text()) for f in project.files()
        )

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if f.language not in self._CODE_LANGS or f.is_probably_binary():
                continue
            text = f.text()
            if not _LLM_STACK.search(text):
                continue  # not an LLM file, skip entirely
            lines = f.lines()

            for rule in RULES:
                if rule.languages and f.language not in rule.languages:
                    continue
                for lineno, line in enumerate(lines, start=1):
                    if len(line) > 2000 or not rule.pattern.search(line):
                        continue
                    if rule.suppress and rule.suppress.search(line):
                        continue
                    counter += 1
                    yield self._rule_finding(rule, counter, f.rel_path, lineno, line)

            counter = yield from self._scan_output_handling(f, lines, counter)
            counter = yield from self._scan_prompt_injection(f, lines, counter)

    # LLM02: model output -> dangerous sink (single-file light taint).
    def _scan_output_handling(self, f, lines, counter):
        tainted: set[str] = set()
        for line in lines:
            m = _LLM_OUTPUT_ASSIGN.match(line)
            if m:
                tainted.add(m.group("var"))
        if not tainted:
            return counter
        for lineno, line in enumerate(lines, start=1):
            if len(line) > 2000 or _OUTPUT_SANITIZER.search(line):
                continue
            uses_tainted = any(re.search(rf"\b{re.escape(v)}\b", line) for v in tainted)
            if not uses_tainted:
                continue
            for sink_id, sink_re, cwe, phrase in _OUTPUT_SINKS:
                if sink_re.search(line) and not _LLM_OUTPUT_ASSIGN.match(line):
                    counter += 1
                    yield self._output_finding(
                        f.rel_path, lineno, line, sink_id, cwe, phrase, counter
                    )
                    break
        return counter

    # LLM01: untrusted input concatenated into a prompt.
    _INPUT_SRC = re.compile(
        r"(?i)(request\.|flask\.request|input\(|argv|\.get_json|\.form\[|\.args|"
        r"req\.(body|query|params)|event\[|message\.content|user_input|user_message)"
    )
    _PROMPT_CTX = re.compile(
        r"(?i)(prompt|system_prompt|messages|instruction|template)\s*(=|\+=|\.append|:)"
    )

    def _scan_prompt_injection(self, f, lines, counter):
        for lineno, line in enumerate(lines, start=1):
            if len(line) > 2000:
                continue
            if (
                self._PROMPT_CTX.search(line)
                and self._INPUT_SRC.search(line)
                and (
                    "+" in line or "f'" in line or 'f"' in line or ".format" in line or "${" in line
                )
            ):
                counter += 1
                yield self._prompt_injection_finding(f.rel_path, lineno, line, counter)
        return counter

    # --- finding builders --------------------------------------------------
    def _rule_finding(
        self, rule: LLMRule, index: int, path: str, lineno: int, line: str
    ) -> Finding:
        return Finding(
            id=f"{self.name}:{rule.id}:{index}",
            rule_id=f"{self.name}.{rule.id}",
            scanner=self.name,
            title=rule.title,
            description=rule.why,
            location=Location(path=path, start_line=lineno, snippet=line.strip()[:240]),
            severity=rule.severity,
            confidence=rule.confidence,
            likelihood=Likelihood.POSSIBLE,
            cwe=rule.cwe,
            owasp=[rule.llm_category],
            why_vulnerable=rule.why,
            attacker_perspective=rule.attack,
            business_impact=rule.impact,
            remediation=Remediation(
                summary=rule.fix, guidance=rule.fix, references=rule.references
            ),
            tags=["llm", "ai-security", rule.llm_category.split(":")[0]],
            metadata={"owasp_llm": rule.llm_category},
        )

    def _output_finding(self, path, lineno, line, sink_id, cwe, phrase, index) -> Finding:
        return Finding(
            id=f"{self.name}:insecure-output-{sink_id}:{path}:{lineno}",
            rule_id=f"{self.name}.insecure-output-handling",
            scanner=self.name,
            title="Insecure handling of LLM output",
            description=f"A model response is {phrase} without validation.",
            location=Location(path=path, start_line=lineno, snippet=line.strip()[:240]),
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            likelihood=Likelihood.POSSIBLE,
            cwe=cwe,
            owasp=["LLM02:2025-Insecure Output Handling"],
            why_vulnerable=(
                f"Output from a language model is treated as trusted and {phrase}. "
                "Model output is attacker-influenceable (via prompt injection) and "
                "must be handled like any other untrusted input."
            ),
            attacker_perspective=(
                "Craft input (directly or via injected content the model reads) so "
                "the completion contains a payload that executes in the sink."
            ),
            business_impact="Code execution, command injection, SQL injection, or XSS "
            "driven by model output.",
            remediation=Remediation(
                summary="Validate, parse, or escape model output before it reaches a "
                "sensitive sink.",
                guidance="Treat completions as untrusted: parse structured output "
                "with a strict schema (e.g. Pydantic/JSON), escape before "
                "HTML, parameterize SQL, and never eval/exec or shell-run a "
                "raw completion.",
                references=[_OWASP_LLM_URL],
            ),
            tags=["llm", "ai-security", "LLM02"],
            metadata={"owasp_llm": "LLM02:2025-Insecure Output Handling"},
        )

    def _prompt_injection_finding(self, path, lineno, line, index) -> Finding:
        return Finding(
            id=f"{self.name}:prompt-injection:{path}:{lineno}",
            rule_id=f"{self.name}.prompt-injection",
            scanner=self.name,
            title="Untrusted input concatenated into a prompt",
            description="User-controlled input is interpolated directly into a prompt "
            "or system message.",
            location=Location(path=path, start_line=lineno, snippet=line.strip()[:240]),
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            likelihood=Likelihood.POSSIBLE,
            cwe=["CWE-74"],
            owasp=["LLM01:2025-Prompt Injection"],
            why_vulnerable=(
                "Untrusted input is placed into the prompt without delimiting or "
                "sanitization, so it can override instructions, especially "
                "dangerous when the model also has tool access."
            ),
            attacker_perspective=(
                "Supply input like 'ignore previous instructions and …' to hijack the "
                "model's behavior or exfiltrate the system prompt."
            ),
            business_impact="Instruction hijacking, data exfiltration, or misuse of any "
            "tools the model can call.",
            remediation=Remediation(
                summary="Separate untrusted input from instructions and constrain the "
                "model's authority.",
                guidance="Keep user content in a distinct user-role message (never the "
                "system prompt), delimit and label it, apply input/output "
                "guardrails, and give the model only least-privilege tools.",
                references=[_OWASP_LLM_URL],
            ),
            tags=["llm", "ai-security", "LLM01"],
            metadata={"owasp_llm": "LLM01:2025-Prompt Injection"},
        )
