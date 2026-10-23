"""LLM / AI-application security scanner (OWASP Top 10 for LLM Applications 2025).

Codebases now embed LLM calls, agent frameworks, and model loading everywhere,
and that surface has its own vulnerability classes that generic SAST does not
cover. This scanner runs only on files that actually touch an LLM/agent stack
(so it stays fast and quiet), and each finding maps to an OWASP LLM 2025 id.

Two tiers:

* **Data flow (tree-sitter, the ``[ast]`` extra).** Python and JS/TS files are
  parsed and analyzed by :mod:`nephilex.scanners.llm_taint` (model output into a
  dangerous sink, LLM05; tool arguments into a shell or ``eval``, LLM06;
  untrusted input into a system prompt, LLM01; secrets and internal URLs in
  system prompts, LLM07), :mod:`nephilex.scanners.llm_taint_js` (the same flows
  for JS/TS) and :mod:`nephilex.scanners.llm_agency` (excessive agent tools,
  LLM06). Both taint passes also report the agent trust-boundary rules in
  :mod:`nephilex.scanners.llm_agent`: indirect prompt injection, tool arguments
  reaching sinks, caller-controlled message roles and tool selection, and
  secrets sent to the model.
* **Line signatures (always on).** Well-known, high-precision signatures:
  ``trust_remote_code=True`` and ``torch.load`` without ``weights_only`` and
  plaintext model downloads (LLM03 Supply Chain), credentials in prompt strings
  (LLM02), dangerous-tool opt-in flags (LLM06), and prompt concatenation of
  request input (LLM01). Without tree-sitter, a light regex taint pass stands
  in for the data-flow output-handling rule, and the line rule for shell tools
  stands in for the agent-tool analysis.

Where both tiers cover the same line, the data-flow finding wins. MCP and agent
configuration files are handled by the separate ``agent-config`` scanner
(:mod:`nephilex.scanners.agent_config`). The scanner is ``file_local`` so results
are cached per file.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from nephilex.core.plugin import Scanner, ScannerContext, scanner
from nephilex.scanners import llm_ast
from nephilex.scanners._text import iter_scan_lines, iter_scan_windows, match_columns, snippet_line
from nephilex.scanners.llm_ast import LLM01, LLM02, LLM03, LLM05, LLM06

# Files worth scanning: those that import or reference a known LLM/agent stack.
# Keeps the scanner quiet on non-AI code and cheap on large repos.
_LLM_STACK = re.compile(
    r"(?i)\b(?:"
    r"openai|anthropic|langchain\w*|langgraph|llama_index|llamaindex|litellm|"
    r"cohere|google\.generativeai|google\.genai|google\s+import\s+genai|vertexai|"
    r"transformers|huggingface_hub|sentence_transformers|ollama|mistralai|groq|"
    r"crewai\w*|autogen\w*|smolagents|fastmcp|mcp\.server|"
    r"chat\s*completions?|messages\.create|system_prompt|"
    r"model_dump|trust_remote_code|torch\.load"
    r")\b"
    r"|\.invoke\(|@ai-sdk/|@anthropic-ai/|@langchain/|@modelcontextprotocol/|@openai/agents|@google/genai|@google/generative-ai|"
    r"\bfrom\s+['\"]ai['\"]"
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
    #: Replaced by the data-flow tier for Python when tree-sitter is available.
    ast_superseded: bool = False
    #: Mask secret-looking values in the snippet (never print a credential).
    redact: bool = False
    tags: list[str] = field(default_factory=list)


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p)


_OWASP_LLM_URL = "https://genai.owasp.org/llm-top-10/"

# --- line-level rules ------------------------------------------------------
RULES: list[LLMRule] = [
    # LLM02, secrets baked into prompts / system messages.
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
        llm_category=LLM02,
        cwe=["CWE-522", "CWE-200"],
        confidence=Confidence.MEDIUM,
        redact=True,
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
    # LLM03, trusting remote code from a model repo.
    LLMRule(
        id="trust-remote-code",
        title="Model loaded with trust_remote_code=True",
        pattern=_rx(r"trust_remote_code\s*=\s*True"),
        severity=Severity.HIGH,
        llm_category=LLM03,
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
    # LLM03, pickle code execution via torch.load.
    LLMRule(
        id="torch-load-pickle",
        title="torch.load without weights_only=True (pickle code execution)",
        # Fire on any torch.load( call and clear it via the suppress idiom when
        # weights_only=True is present. A lookahead bounded by the first ) would
        # miss nested calls like torch.load(f, map_location=torch.device("cpu")).
        pattern=_rx(r"torch\.load\s*\("),
        suppress=_rx(r"weights_only\s*=\s*True"),
        severity=Severity.HIGH,
        llm_category=LLM03,
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
    # LLM03, fetching model weights over plaintext HTTP.
    LLMRule(
        id="model-download-http",
        title="Model or weights downloaded over plaintext HTTP",
        pattern=_rx(
            r"(?i)(from_pretrained|hf_hub_download|load_model|get_file|"
            r"urlretrieve|requests\.get)\s*\(\s*['\"]http://[^'\"]+"
        ),
        severity=Severity.MEDIUM,
        llm_category=LLM03,
        cwe=["CWE-319", "CWE-494"],
        confidence=Confidence.MEDIUM,
        why="Model artifacts fetched over HTTP can be tampered with in transit.",
        attack="A network attacker swaps the weights/config for a poisoned or backdoored artifact.",
        impact="Loading attacker-controlled model data, up to code execution when "
        "combined with pickle-based formats.",
        fix="Use HTTPS, and pin artifacts by revision/hash so a swapped file is detected.",
        references=[_OWASP_LLM_URL],
    ),
    # LLM06, over-privileged agent tools (line fallback without tree-sitter).
    LLMRule(
        id="agent-shell-tool",
        title="Agent granted shell / code-execution capability",
        pattern=_rx(
            r"(?i)\b(ShellTool|PythonREPLTool|PythonAstREPLTool|"
            r"BashProcess|TerminalTool|ComputerTool|exec_tool)\b"
        ),
        severity=Severity.HIGH,
        llm_category=LLM06,
        cwe=["CWE-250", "CWE-732"],
        confidence=Confidence.MEDIUM,
        ast_superseded=True,
        tags=["agent"],
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
    # LLM06, explicit opt-in flags for dangerous tools. CrewAI's
    # allow_code_execution is judged by the data-flow tier instead: its default
    # "safe" mode runs code in Docker, so the flag alone is not excessive.
    LLMRule(
        id="unrestricted-tool-registration",
        title="Tool/function exposed to the model without evident restriction",
        pattern=_rx(r"(?i)(allow_dangerous\w{0,40}\s*=\s*True|dangerous_tools?\s*=\s*True)"),
        severity=Severity.HIGH,
        llm_category=LLM06,
        cwe=["CWE-732"],
        confidence=Confidence.MEDIUM,
        tags=["agent"],
        why="A flag explicitly enables dangerous / code-executing tools for the model.",
        attack="Prompt injection escalates into whatever the enabled tools can do.",
        impact="Excessive agency: the model can take high-impact actions on attacker instruction.",
        fix="Disable dangerous tool flags; expose only least-privilege, allowlisted "
        "tools and require confirmation for irreversible actions.",
        references=[_OWASP_LLM_URL],
    ),
]

# --- regex fallback for improper output handling (LLM05) ---------------------
# Used only when tree-sitter is not installed; the data-flow tier in
# llm_taint / llm_taint_js replaces it otherwise.
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


#: Regex-tier rule ids that a data-flow finding on the same line replaces.
_OVERLAPPING_RULES = {
    "llm.secret-in-prompt",
    "llm.prompt-injection",
    "llm.unrestricted-tool-registration",
    "llm.agent-shell-tool",
}
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")


@scanner
class LLMScanner(Scanner):
    name = "llm"
    category = "llm"
    file_local = True
    description = (
        "Security checks for LLM/agent code (OWASP Top 10 for LLM Apps 2025); "
        "data-flow rules need the [ast] extra."
    )

    _CODE_LANGS = {"Python", "JavaScript", "TypeScript"}

    def applies_to(self, project) -> bool:
        return any(
            f.language in self._CODE_LANGS and _LLM_STACK.search(f.text()) for f in project.files()
        )

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        from nephilex.scanners.patterns import _is_test_file

        counter = 0
        for f in ctx.project.files():
            if f.language not in self._CODE_LANGS or f.is_probably_binary():
                continue
            text = f.text()
            if not _LLM_STACK.search(text):
                continue  # not an LLM file, skip entirely
            lines = f.lines()
            in_test = _is_test_file(f.rel_path)

            ast_findings, analyzed = self._ast_tier(f, text, in_test)
            regex: list[Finding] = []
            for rule in RULES:
                if rule.languages and f.language not in rule.languages:
                    continue
                if rule.ast_superseded and analyzed and f.language == "Python":
                    continue
                reported: set[int] = set()
                for lineno, offset, segment in iter_scan_windows(lines):
                    if lineno in reported:
                        continue
                    m = rule.pattern.search(segment)
                    if not m or (rule.suppress and rule.suppress.search(segment)):
                        continue
                    reported.add(lineno)
                    counter += 1
                    regex.append(
                        self._rule_finding(
                            rule,
                            counter,
                            f.rel_path,
                            lineno,
                            lines[lineno - 1],
                            match_columns(m, offset),
                        )
                    )
            if not analyzed:
                regex.extend(self._scan_output_handling(f, lines))
            regex.extend(self._scan_prompt_injection(f, lines))

            # Lines a data-flow finding covers (a multi-line call counts whole).
            ast_lines: set[int | None] = set()
            for x in ast_findings:
                start = x.location.start_line or 0
                end = int(x.metadata.get("end_line") or start)
                ast_lines.update(range(start, end + 1))
            yield from ast_findings
            for finding in regex:
                if (
                    finding.rule_id in _OVERLAPPING_RULES
                    and finding.location.start_line in ast_lines
                ):
                    continue  # the data-flow tier reported this line more precisely
                yield finding

    def _ast_tier(self, f, text: str, in_test: bool) -> tuple[list[Finding], bool]:
        """Data-flow findings for one file, and whether the file was analyzed."""
        if f.language == "Python":
            parser = llm_ast.python_parser()
        elif f.suffix in _JS_SUFFIXES:
            parser = llm_ast.js_parser(f.suffix)
        else:
            parser = None
        if parser is None:
            return [], False
        data = text.encode("utf-8", "replace")
        # A hostile or pathological file must not sink the scan: analyze it in
        # isolation and keep the gap visible.
        try:
            root = parser.parse(data).root_node
            if f.language == "Python":
                from nephilex.scanners.llm_agency import analyze_agency
                from nephilex.scanners.llm_taint import analyze_python

                found = list(analyze_python(data, root, f.rel_path, in_test))
                found += analyze_agency(data, root, f.rel_path, in_test)
            else:
                from nephilex.scanners.llm_taint_js import analyze_js

                found = analyze_js(data, root, f.rel_path, in_test)
        except Exception as exc:
            from nephilex.scanners.ast_python import analysis_skipped_finding

            return [analysis_skipped_finding(self.name, f.rel_path, exc)], False
        return found, True

    # LLM05 fallback: model output -> dangerous sink (single-file regex taint).
    def _scan_output_handling(self, f, lines) -> list[Finding]:
        tainted: set[str] = set()
        for _lineno, segment in iter_scan_lines(lines):
            m = _LLM_OUTPUT_ASSIGN.match(segment)
            if m:
                tainted.add(m.group("var"))
        if not tainted:
            return []
        uses = re.compile(r"\b(?:" + "|".join(re.escape(v) for v in sorted(tainted)) + r")\b")
        out: list[Finding] = []
        reported: set[int] = set()
        for lineno, offset, segment in iter_scan_windows(lines):
            if lineno in reported or _OUTPUT_SANITIZER.search(segment):
                continue
            if not uses.search(segment) or _LLM_OUTPUT_ASSIGN.match(segment):
                continue
            for sink_id, sink_re, cwe, phrase in _OUTPUT_SINKS:
                m = sink_re.search(segment)
                if m:
                    reported.add(lineno)
                    out.append(
                        self._output_finding(
                            f.rel_path,
                            lineno,
                            lines[lineno - 1],
                            sink_id,
                            cwe,
                            phrase,
                            match_columns(m, offset),
                        )
                    )
                    break
        return out

    # LLM01: untrusted input concatenated into a prompt.
    _INPUT_SRC = re.compile(
        r"(?i)(request\.|flask\.request|input\(|argv|\.get_json|\.form\[|\.args|"
        r"req\.(body|query|params)|event\[|message\.content|user_input|user_message)"
    )
    _PROMPT_CTX = re.compile(
        r"(?i)(prompt|system_prompt|messages|instruction|template)\s*(=|\+=|\.append|:)"
    )

    def _scan_prompt_injection(self, f, lines) -> list[Finding]:
        out: list[Finding] = []
        reported: set[int] = set()
        for lineno, offset, segment in iter_scan_windows(lines):
            if lineno in reported:
                continue
            src = self._INPUT_SRC.search(segment)
            if (
                src
                and self._PROMPT_CTX.search(segment)
                and (
                    "+" in segment
                    or "f'" in segment
                    or 'f"' in segment
                    or ".format" in segment
                    or "${" in segment
                )
            ):
                reported.add(lineno)
                out.append(
                    self._prompt_injection_finding(
                        f.rel_path, lineno, lines[lineno - 1], match_columns(src, offset)
                    )
                )
        return out

    # --- finding builders --------------------------------------------------
    def _rule_finding(
        self,
        rule: LLMRule,
        index: int,
        path: str,
        lineno: int,
        line: str,
        cols: tuple[int, int],
    ) -> Finding:
        snippet = line.rstrip("\r\n")
        if rule.redact:
            from nephilex.scanners.llm_prompt import _secret_spans, mask

            spans = [(m.start(2), m.end(2), "credential") for m in rule.pattern.finditer(line)]
            snippet = mask(line, spans + _secret_spans(line)).rstrip("\r\n")
        return Finding(
            id=f"{self.name}:{rule.id}:{index}",
            rule_id=f"{self.name}.{rule.id}",
            scanner=self.name,
            title=rule.title,
            description=rule.why,
            location=_location(path, lineno, cols, snippet[:240]),
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
            tags=["llm", "ai-security", *rule.tags, rule.llm_category.split(":")[0]],
            metadata={"owasp_llm": rule.llm_category},
        )

    def _output_finding(self, path, lineno, line, sink_id, cwe, phrase, cols) -> Finding:
        return Finding(
            id=f"{self.name}:insecure-output-{sink_id}:{path}:{lineno}",
            rule_id=f"{self.name}.insecure-output-handling",
            scanner=self.name,
            title="Insecure handling of LLM output",
            description=f"A model response is {phrase} without validation.",
            location=_location(path, lineno, cols, snippet_line(line)),
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            likelihood=Likelihood.POSSIBLE,
            cwe=cwe,
            owasp=[LLM05],
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
                references=[llm_ast.OWASP_URLS[LLM05]],
            ),
            tags=["llm", "ai-security", "LLM05"],
            metadata={"owasp_llm": LLM05, "analysis": "regex-fallback"},
        )

    def _prompt_injection_finding(self, path, lineno, line, cols) -> Finding:
        return Finding(
            id=f"{self.name}:prompt-injection:{path}:{lineno}",
            rule_id=f"{self.name}.prompt-injection",
            scanner=self.name,
            title="Untrusted input concatenated into a prompt",
            description="User-controlled input is interpolated directly into a prompt "
            "or system message.",
            location=_location(path, lineno, cols, snippet_line(line)),
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            likelihood=Likelihood.POSSIBLE,
            cwe=["CWE-74"],
            owasp=[LLM01],
            why_vulnerable=(
                "Untrusted input is placed into the prompt without delimiting or "
                "sanitization, so it can override instructions, especially "
                "dangerous when the model also has tool access."
            ),
            attacker_perspective=(
                "Supply input like 'ignore previous instructions and ...' to hijack the "
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
                references=[llm_ast.OWASP_URLS[LLM01]],
            ),
            tags=["llm", "ai-security", "prompt", "LLM01"],
            metadata={"owasp_llm": LLM01},
        )


def _location(path: str, lineno: int, cols: tuple[int, int], snippet: str) -> Location:
    return Location(
        path=path,
        start_line=lineno,
        end_line=lineno,
        start_column=cols[0],
        end_column=cols[1],
        snippet=snippet,
    )
