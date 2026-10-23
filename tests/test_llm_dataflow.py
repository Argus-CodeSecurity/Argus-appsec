"""Data-flow LLM rules: model output to sinks (LLM05), tool handlers and agent
tools (LLM06), system-prompt construction (LLM01, LLM07).

Every rule has at least one case that must fire and one look-alike that must
not, since precision is the point of the tree-sitter tier.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nephilex.analysis.repository import RepositoryAnalyzer
from nephilex.core.config import Config
from nephilex.core.plugin import ScannerContext, registry
from nephilex.core.project import Project

pytest.importorskip("tree_sitter_python")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

OPENAI = "from openai import OpenAI\nclient = OpenAI()\n"
GET = "    out = client.chat.completions.create(model='m', messages=q).choices[0].message.content\n"


def _scan(tmp_path: Path, code: str, name: str = "app.py") -> list:
    (tmp_path / name).write_text(code, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return list(registry.get_scanner("llm")().scan(ctx))


def _hits(findings, rule: str) -> list:
    return [f for f in findings if f.rule_id == f"llm.{rule}"]


def _sinks(findings) -> set[str]:
    return {f.metadata.get("sink") for f in _hits(findings, "insecure-output-handling")}


# --- LLM05: model output into a dangerous sink (Python) ---------------------


@pytest.mark.parametrize(
    ("body", "sink", "cwe"),
    [
        ("    import os\n    os.system(out)\n", "shell", "CWE-78"),
        ("    import subprocess\n    subprocess.run(out, shell=True)\n", "shell", "CWE-78"),
        ("    import shlex, subprocess\n    subprocess.run(shlex.split(out))\n", "shell", "CWE-78"),
        ("    eval(out)\n", "code", "CWE-95"),
        ('    cur.execute(f"SELECT * FROM t WHERE {out}")\n', "sql", "CWE-89"),
        ("    import json\n    cur.execute(json.loads(out)['sql'])\n", "sql", "CWE-89"),
        ("    open(out, 'w').write('x')\n", "file", "CWE-73"),
        ("    import shutil\n    shutil.rmtree(out)\n", "file", "CWE-73"),
        ("    import requests\n    requests.get(out)\n", "ssrf", "CWE-918"),
        ("    import httpx\n    httpx.post(url=out)\n", "ssrf", "CWE-918"),
        ("    from markupsafe import Markup\n    return Markup(out)\n", "html", "CWE-79"),
        (
            "    from flask import render_template_string\n    return render_template_string(out)\n",
            "ssti",
            "CWE-1336",
        ),
        ("    import pickle\n    pickle.loads(out.encode())\n", "deser", "CWE-502"),
        ("    import yaml\n    yaml.load(out)\n", "deser", "CWE-502"),
    ],
)
def test_model_output_reaches_sink(tmp_path, body, sink, cwe):
    findings = _scan(tmp_path, OPENAI + "def f(q, cur):\n" + GET + body)
    hits = _hits(findings, "insecure-output-handling")
    assert [f.metadata["sink"] for f in hits] == [sink]
    assert cwe in hits[0].cwe
    assert hits[0].owasp == ["LLM05:2025-Improper Output Handling"]
    assert hits[0].metadata["analysis"] == "taint-dataflow"
    assert "llm" in hits[0].tags


@pytest.mark.parametrize(
    "body",
    [
        "    import shlex, subprocess\n    subprocess.run(shlex.quote(out), shell=True)\n",
        "    import subprocess\n    subprocess.run(['git', 'log', '--', out])\n",
        "    cur.execute('SELECT * FROM t WHERE x = %s', (out,))\n",
        "    open('log.txt', 'a').write(out)\n",
        "    import requests\n    requests.get(f'https://api.example.com/v1/items/{out}')\n",
        "    import requests\n    requests.get('https://api.example.com/v1/' + out)\n",
        "    import html\n    from markupsafe import Markup\n    return Markup(html.escape(out))\n",
        "    import yaml\n    yaml.load(out, Loader=yaml.SafeLoader)\n",
        "    import os\n    os.system('sleep %d' % int(out))\n",
        "    import os\n    n = len(out)\n    os.system(f'echo {n}')\n",
        "    import os, os.path\n    open(os.path.basename(out), 'w')\n",
        "    import json\n    data = json.loads(out)\n    return data['answer']\n",
    ],
)
def test_sanitized_or_safe_use_is_not_reported(tmp_path, body):
    findings = _scan(tmp_path, OPENAI + "def f(q, cur):\n" + GET + body)
    assert _hits(findings, "insecure-output-handling") == []


def test_kind_specific_sanitizer_only_clears_its_own_sink(tmp_path):
    # shlex.quote makes a value safe for a shell, not for SQL.
    code = (
        OPENAI
        + "import shlex\ndef f(q, cur):\n"
        + GET
        + ("    safe = shlex.quote(out)\n    cur.execute('SELECT ' + safe)\n")
    )
    assert _sinks(_scan(tmp_path, code)) == {"sql"}


def test_allowlist_guard_clears_but_blocklist_does_not(tmp_path):
    code = OPENAI + (
        "import os\n"
        "ALLOWED = {'status', 'uptime'}\n"
        "def ok(q):\n" + GET + "    if out not in ALLOWED:\n        raise ValueError(out)\n"
        "    os.system(out)\n"
        "def inside(q):\n" + GET + "    if out in ALLOWED:\n        os.system(out)\n"
        "def bad(q):\n" + GET + "    if 'rm' in out:\n        raise ValueError(out)\n"
        "    os.system(out)\n"
    )
    hits = _hits(_scan(tmp_path, code), "insecure-output-handling")
    assert len(hits) == 1
    assert hits[0].location.start_line == len(code.splitlines())  # only the blocklist case


def test_property_check_does_not_clear_the_whole_object(tmp_path):
    code = (
        "from anthropic import Anthropic\n"
        "def f(q):\n"
        "    msg = Anthropic().messages.create(model='m', max_tokens=9, messages=q)\n"
        "    for block in msg.content:\n"
        "        if block.type == 'tool_use':\n"
        "            exec(block.input['code'])\n"
    )
    assert _sinks(_scan(tmp_path, code)) == {"code"}


def test_pydantic_schema_clears_only_constrained_fields(tmp_path):
    code = (
        "import os\n"
        "from typing import Literal\n"
        "from pydantic import BaseModel\n"
        "from langchain_openai import ChatOpenAI\n"
        "llm = ChatOpenAI()\n"
        "class Plan(BaseModel):\n"
        "    action: Literal['ls', 'pwd']\n"
        "    note: str\n"
        "def f(q):\n"
        "    plan = Plan.model_validate_json(llm.invoke(q).content)\n"
        "    os.system(plan.action)\n"
        "    os.system(plan.note)\n"
    )
    hits = _hits(_scan(tmp_path, code), "insecure-output-handling")
    assert [h.location.start_line for h in hits] == [12]
    assert "unconstrained" in hits[0].description


def test_structured_output_with_unknown_schema_is_trusted(tmp_path):
    code = (
        "import os\n"
        "from langchain_openai import ChatOpenAI\n"
        "from schemas import Plan\n"
        "planner = ChatOpenAI().with_structured_output(Plan)\n"
        "def f(q):\n"
        "    os.system(planner.invoke(q).command)\n"
    )
    assert _hits(_scan(tmp_path, code), "insecure-output-handling") == []


@pytest.mark.parametrize(
    "code",
    [
        # LiteLLM, imported function
        "import os\nfrom litellm import completion\n"
        "def f(q):\n    os.system(completion(model='m', messages=q).choices[0].message.content)\n",
        # Ollama module function
        "import ollama, subprocess\n"
        "def f(q):\n    subprocess.run(ollama.chat(model='m', messages=q)['message']['content'], shell=True)\n",
        # Google GenAI client
        "import os\nfrom google import genai\nc = genai.Client()\n"
        "def f(q):\n    os.system(c.models.generate_content(model='m', contents=q).text)\n",
        # LangChain LCEL chain
        "import os\nfrom langchain_openai import ChatOpenAI\nchain = prompt | ChatOpenAI()\n"
        "def f(q):\n    os.system(chain.invoke({'q': q}))\n",
        # LlamaIndex query engine
        "import os\nfrom llama_index.core import VectorStoreIndex\n"
        "def f(index, q):\n    os.system(str(index.as_query_engine().query(q)))\n",
        # Anthropic client on self
        "import os\nimport anthropic\nclass A:\n    def __init__(self):\n"
        "        self.client = anthropic.Anthropic()\n"
        "    def go(self, q):\n"
        "        r = self.client.messages.create(model='m', max_tokens=9, messages=q)\n"
        "        os.system(r.content[0].text)\n",
    ],
)
def test_sources_across_providers(tmp_path, code):
    assert _sinks(_scan(tmp_path, code)) == {"shell"}


@pytest.mark.parametrize(
    "code",
    [
        # sklearn-style predict on a non-LLM object in an LLM file
        "import os\nimport openai\ndef f(model, X):\n    os.system(str(model.predict(X)))\n",
        # client.messages.create without the anthropic package (e.g. Twilio)
        "import os\nimport openai\nfrom twilio.rest import Client\nc = Client()\n"
        "def f():\n    m = c.messages.create(body='hi', to='+1')\n    os.system(m.body)\n",
        # provider metadata is not model text
        OPENAI + "def f(q, cur):\n"
        "    r = client.chat.completions.create(model='m', messages=q)\n"
        "    cur.execute(f\"INSERT INTO log VALUES ('{r.id}', {r.usage.total_tokens})\")\n",
        # embeddings are not text
        OPENAI + "def f(q, cur):\n"
        "    e = client.embeddings.create(model='m', input=q)\n    eval(e)\n",
        # a prompt template renders a prompt, it does not call a model
        "import os\nfrom langchain_core.prompts import ChatPromptTemplate\n"
        "tpl = ChatPromptTemplate([('user', '{q}')])\n"
        "def f(q):\n    os.system(str(tpl.invoke({'q': 'ls'})))\n",
    ],
)
def test_non_model_values_are_not_sources(tmp_path, code):
    assert _hits(_scan(tmp_path, code), "insecure-output-handling") == []


def test_findings_in_test_files_are_downgraded(tmp_path):
    (tmp_path / "tests").mkdir()
    findings = _scan(tmp_path, OPENAI + "def f(q):\n" + GET + "    eval(out)\n", "tests/test_x.py")
    hit = _hits(findings, "insecure-output-handling")[0]
    assert hit.confidence.name == "LOW" and "test-context" in hit.tags


# --- LLM05: JavaScript / TypeScript -------------------------------------------

JS_HEAD = (
    'import OpenAI from "openai";\n'
    'import { exec } from "child_process";\n'
    'import * as fs from "fs";\n'
    "const openai = new OpenAI();\n"
    "export async function f(db, el) {\n"
    '  const r = await openai.chat.completions.create({ model: "m", messages: [] });\n'
    "  const out = r.choices[0].message.content;\n"
)


@pytest.mark.parametrize(
    ("body", "sink"),
    [
        ("  exec(out);\n", "shell"),
        ("  eval(out);\n", "code"),
        ("  new Function(out)();\n", "code"),
        ("  await db.query(`SELECT * FROM t WHERE x = '${out}'`);\n", "sql"),
        ('  fs.writeFileSync(out, "x");\n', "file"),
        ("  await fetch(out);\n", "ssrf"),
        ("  el.innerHTML = out;\n", "html"),
    ],
)
def test_js_model_output_reaches_sink(tmp_path, body, sink):
    findings = _scan(tmp_path, JS_HEAD + body + "}\n", "app.ts")
    assert _sinks(findings) == {sink}


@pytest.mark.parametrize(
    "body",
    [
        '  await db.query("SELECT * FROM t WHERE x = $1", [out]);\n',
        '  fs.writeFileSync("log.txt", out);\n',
        "  await fetch(`https://api.example.com/v1/${encodeURIComponent(out)}`);\n",
        "  el.innerHTML = DOMPurify.sanitize(out);\n",
        "  el.textContent = out;\n",
        '  if (!["ls", "pwd"].includes(out)) return;\n  exec(out);\n',
        '  exec("sleep " + Number(out));\n',
    ],
)
def test_js_safe_use_is_not_reported(tmp_path, body):
    findings = _scan(tmp_path, JS_HEAD + body + "}\n", "app.ts")
    assert _hits(findings, "insecure-output-handling") == []


def test_js_vercel_ai_sdk_and_jsx(tmp_path):
    code = (
        'import { generateText, generateObject } from "ai";\n'
        'import { exec } from "child_process";\n'
        "export async function C({ model, prompt, schema }) {\n"
        "  const { text } = await generateText({ model, prompt });\n"
        "  const { object } = await generateObject({ model, schema, prompt });\n"
        "  exec(object.cmd);\n"
        "  return <div dangerouslySetInnerHTML={{ __html: text }} />;\n"
        "}\n"
    )
    hits = _hits(_scan(tmp_path, code, "page.tsx"), "insecure-output-handling")
    assert [(h.metadata["sink"], h.location.start_line) for h in hits] == [("html", 7)]


# --- LLM06: tool handlers that execute their arguments ------------------------


def test_tool_handler_shell_and_eval(tmp_path):
    code = (
        "import subprocess\n"
        "from langchain_core.tools import tool\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "@tool\n"
        "def run(command: str) -> str:\n"
        "    return subprocess.run(command, shell=True, capture_output=True).stdout\n"
        "@mcp.tool()\n"
        "def calc(expr: str) -> str:\n"
        "    return str(eval(expr))\n"
    )
    hits = _hits(_scan(tmp_path, code), "tool-handler-exec")
    assert [(h.metadata["sink"], h.location.start_line) for h in hits] == [
        ("shell", 7),
        ("code", 10),
    ]
    assert hits[0].owasp == ["LLM06:2025-Excessive Agency"]
    assert "agent" in hits[0].tags


def test_tool_handler_registered_by_reference(tmp_path):
    code = (
        "import os\nfrom langchain.agents import Tool\n"
        "def run_cmd(cmd):\n    return os.popen(cmd).read()\n"
        "tools = [Tool(name='sh', func=run_cmd, description='x')]\n"
    )
    assert len(_hits(_scan(tmp_path, code), "tool-handler-exec")) == 1


@pytest.mark.parametrize(
    "code",
    [
        # Literal-typed parameter: the model can only pick fixed values.
        "import subprocess\nfrom typing import Literal\nfrom langchain_core.tools import tool\n"
        "@tool\ndef run(name: Literal['status', 'uptime']) -> str:\n"
        "    return subprocess.run(name, shell=True).stdout\n",
        # Same code, but not a tool.
        "import subprocess\nimport openai\n"
        "def run(command: str) -> str:\n"
        "    return subprocess.run(command, shell=True).stdout\n",
        # A tool whose argument is only an argv element of a fixed program.
        "import subprocess\nfrom langchain_core.tools import tool\n"
        "@tool\ndef log(path: str) -> str:\n"
        "    return subprocess.run(['git', 'log', '--', path]).stdout\n",
    ],
)
def test_tool_handler_negatives(tmp_path, code):
    assert _hits(_scan(tmp_path, code), "tool-handler-exec") == []


# --- LLM01: untrusted input in a system prompt --------------------------------


@pytest.mark.parametrize(
    "code",
    [
        "from flask import request\nimport openai\n"
        "def h():\n    q = request.args.get('q')\n"
        "    return [{'role': 'system', 'content': f'You help with {q}'}]\n",
        "from langchain_core.messages import SystemMessage\n"
        "def h(path):\n    text = open(path).read()\n"
        "    return [SystemMessage(content='Use this: ' + text)]\n",
        "import anthropic\nc = anthropic.Anthropic()\n"
        "def h(store, q):\n    docs = store.similarity_search(q)\n"
        "    ctx = '\\n'.join(d.page_content for d in docs)\n"
        "    return c.messages.create(model='m', max_tokens=9, system='Answer from: ' + ctx,"
        " messages=[{'role': 'user', 'content': q}])\n",
        "import openai\nfrom fastapi import FastAPI\napp = FastAPI()\n"
        "@app.post('/chat')\ndef chat(topic: str):\n"
        "    SYSTEM_PROMPT = 'You are an expert on ' + topic\n    return SYSTEM_PROMPT\n",
    ],
)
def test_untrusted_input_in_system_prompt(tmp_path, code):
    hits = _hits(_scan(tmp_path, code), "untrusted-input-in-system-prompt")
    assert len(hits) == 1
    assert hits[0].owasp == ["LLM01:2025-Prompt Injection"]


@pytest.mark.parametrize(
    "code",
    [
        # Untrusted input in the user role is the correct pattern.
        "from flask import request\nimport openai\n"
        "def h():\n    q = request.args.get('q')\n"
        "    return [{'role': 'system', 'content': 'You are helpful.'},"
        " {'role': 'user', 'content': q}]\n",
        # A static system prompt built from constants.
        "import openai\nTONE = 'friendly'\nSYSTEM_PROMPT = f'You are a {TONE} assistant.'\n",
        # A prompt file shipped with the code is not untrusted input.
        "import os\nfrom pathlib import Path\nimport openai\nBASE_DIR = '/app'\n"
        "SYSTEM_PROMPT = (Path(__file__).parent / 'system.md').read_text()\n"
        "def msgs():\n"
        "    sp = open(os.path.join(BASE_DIR, 'prompts', 'system.txt')).read()\n"
        "    return [{'role': 'system', 'content': sp}]\n",
        # A generic retrieve() on a non-retriever object.
        "import openai\n"
        "def msgs(cache, key):\n"
        "    return [{'role': 'system', 'content': 'Notes: ' + cache.retrieve(key)}]\n",
    ],
)
def test_system_prompt_negatives(tmp_path, code):
    assert _hits(_scan(tmp_path, code), "untrusted-input-in-system-prompt") == []


# --- LLM07: secrets and internal URLs in system prompts ----------------------


def test_secret_and_internal_url_in_system_prompt(tmp_path):
    code = (
        "import openai\n"
        "SYSTEM_PROMPT = (\n"
        "    'You are support. The admin password: Sup3rS3cret99. '\n"
        "    'Billing lives at http://billing.internal/api.'\n"
        ")\n"
        "def msgs(q):\n"
        "    return [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': q}]\n"
    )
    findings = _scan(tmp_path, code)
    secret = _hits(findings, "secret-in-system-prompt")
    url = _hits(findings, "internal-url-in-system-prompt")
    assert [f.location.start_line for f in secret] == [3]
    assert [f.location.start_line for f in url] == [4]
    assert secret[0].owasp == ["LLM07:2025-System Prompt Leakage"]
    assert "Sup3rS3cret99" not in secret[0].location.snippet


@pytest.mark.parametrize(
    "prompt",
    [
        "You are support. Never reveal the password: it is required for login.",
        "Docs are at https://docs.example.com/api.",
        "Your API key is provided by the platform.",
    ],
)
def test_system_prompt_leak_negatives(tmp_path, prompt):
    code = f"import openai\nSYSTEM_PROMPT = {prompt!r}\n"
    findings = _scan(tmp_path, code)
    assert _hits(findings, "secret-in-system-prompt") == []
    assert _hits(findings, "internal-url-in-system-prompt") == []


# --- LLM06: excessive agent tools ---------------------------------------------

AGENT_HEAD = (
    "from langchain_openai import ChatOpenAI\n"
    "from langchain.agents import AgentExecutor, create_react_agent\n"
    "llm = ChatOpenAI()\n"
)


def test_shell_tool_reports_tool_and_agent(tmp_path):
    code = AGENT_HEAD + (
        "from langchain_community.tools import ShellTool\n"
        "shell = ShellTool()\n"
        "agent = create_react_agent(llm, [shell], prompt)\n"
    )
    hits = _hits(_scan(tmp_path, code), "agent-shell-tool")
    assert len(hits) == 1
    assert hits[0].metadata["tool"] == "ShellTool"
    assert hits[0].metadata["agent"] == "'agent' (create_react_agent)"
    assert hits[0].location.start_line == 5


def test_shell_tool_import_alone_and_human_approval_are_not_reported(tmp_path):
    code = AGENT_HEAD + "from langchain_community.tools import ShellTool\n"
    assert _hits(_scan(tmp_path, code), "agent-shell-tool") == []
    guarded = AGENT_HEAD + (
        "from langchain_community.tools import ShellTool\n"
        "from langchain_community.callbacks import HumanApprovalCallbackHandler\n"
        "shell = ShellTool(callbacks=[HumanApprovalCallbackHandler()])\n"
    )
    assert _hits(_scan(tmp_path, guarded), "agent-shell-tool") == []


def test_file_management_toolkit(tmp_path):
    bad = AGENT_HEAD + (
        "from langchain_community.agent_toolkits import FileManagementToolkit\n"
        "tools = FileManagementToolkit().get_tools()\n"
        "agent = create_react_agent(llm, tools, prompt)\n"
    )
    hits = _hits(_scan(tmp_path, bad), "agent-file-write-tool")
    assert len(hits) == 1 and hits[0].severity.name == "HIGH"
    assert "'agent'" in hits[0].metadata["agent"]
    ok = AGENT_HEAD + (
        "from langchain_community.agent_toolkits import FileManagementToolkit\n"
        "tools = FileManagementToolkit(root_dir='/srv/ws', selected_tools=['read_file', 'list_directory'])\n"
    )
    assert _hits(_scan(tmp_path, ok), "agent-file-write-tool") == []


def test_requests_toolkit_needs_the_dangerous_opt_in(tmp_path):
    bad = AGENT_HEAD + (
        "from langchain_community.agent_toolkits.openapi.toolkit import RequestsToolkit\n"
        "t = RequestsToolkit(requests_wrapper=w, allow_dangerous_requests=True)\n"
    )
    findings = _scan(tmp_path, bad)
    assert len(_hits(findings, "agent-requests-tool")) == 1
    # The line rule for allow_dangerous_* is not reported a second time.
    assert _hits(findings, "unrestricted-tool-registration") == []
    ok = AGENT_HEAD + (
        "from langchain_community.agent_toolkits.openapi.toolkit import RequestsToolkit\n"
        "t = RequestsToolkit(requests_wrapper=w)\n"
    )
    assert _hits(_scan(tmp_path, ok), "agent-requests-tool") == []


def test_sql_toolkit_without_read_only_scoping(tmp_path):
    base = AGENT_HEAD + (
        "from langchain_community.utilities import SQLDatabase\n"
        "from langchain_community.agent_toolkits import SQLDatabaseToolkit\n"
    )
    bad = base + "db = SQLDatabase.from_uri(URI)\nkit = SQLDatabaseToolkit(db=db, llm=llm)\n"
    assert len(_hits(_scan(tmp_path, bad), "agent-sql-write-tool")) == 1
    ok = base + (
        "db = SQLDatabase.from_uri('sqlite:///file:app.db?mode=ro&uri=true')\n"
        "kit = SQLDatabaseToolkit(db=db, llm=llm)\n"
    )
    assert _hits(_scan(tmp_path, ok), "agent-sql-write-tool") == []


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (
            "import autogen\n"
            "u = autogen.UserProxyAgent('u', code_execution_config={'work_dir': 'w', 'use_docker': False})\n",
            1,
        ),
        (
            "import autogen\n"
            "u = autogen.UserProxyAgent('u', code_execution_config={'work_dir': 'w', 'use_docker': True})\n",
            0,
        ),
        ("import autogen\nu = autogen.UserProxyAgent('u', code_execution_config=False)\n", 0),
        (
            "from autogen_ext.code_executors.local import LocalCommandLineCodeExecutor\n"
            "ex = LocalCommandLineCodeExecutor(work_dir='w')\n",
            1,
        ),
        (
            "from crewai import Agent\n"
            "a = Agent(role='r', goal='g', backstory='b', allow_code_execution=True,"
            " code_execution_mode='unsafe')\n",
            1,
        ),
        (
            "from crewai import Agent\n"
            "a = Agent(role='r', goal='g', backstory='b', allow_code_execution=True)\n",
            0,
        ),
    ],
)
def test_agent_code_execution(tmp_path, code, expected):
    findings = _scan(tmp_path, code)
    assert len(_hits(findings, "agent-code-execution")) == expected
    assert _hits(findings, "unrestricted-tool-registration") == []


def test_unparseable_python_does_not_break_the_scan(tmp_path):
    findings = _scan(tmp_path, "import openai\n" + "(" * 5000 + "\n")
    assert all(f.severity.name == "INFO" for f in findings)


#: Inputs shaped to make an overlapping-quantifier regex backtrack.
ADVERSARIAL = [
    "a" * 2000,
    " " * 2000,
    "password" + " " * 1990 + "!",
    "sk-" + "A" * 1997,
    "http://" + "a." * 996,
    "@" + "a" * 1998,
    "-" * 2000,
]


def slow_patterns(*modules) -> list[str]:
    """Module-level regexes that take more than 0.5s on an adversarial line."""
    import re
    import time

    slow = []
    for mod in modules:
        for name, val in vars(mod).items():
            if isinstance(val, re.Pattern):
                for s in ADVERSARIAL:
                    start = time.perf_counter()
                    val.search(s)
                    if time.perf_counter() - start > 0.5:
                        slow.append(f"{mod.__name__}.{name}")
    return slow


def test_module_regexes_are_linear():
    from nephilex.scanners import llm, llm_agency, llm_ast, llm_prompt, llm_taint, llm_taint_js

    assert not slow_patterns(llm, llm_agency, llm_ast, llm_prompt, llm_taint, llm_taint_js)
