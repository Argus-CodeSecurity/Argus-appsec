"""Agent trust-boundary rules: indirect prompt injection, tool chaining, message
roles, tool selection and secrets in prompts (Python and JS/TS).

Each rule has cases that must fire and look-alikes that must not; the snippets
here are written for the tests and are not taken from benchmarks/agent.
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


def _scan(tmp_path: Path, code: str, name: str = "app.py") -> list:
    (tmp_path / name).write_text(code, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return list(registry.get_scanner("llm")().scan(ctx))


def _rules(findings) -> set[str]:
    return {f.rule_id.removeprefix("llm.") for f in findings}


def _hits(findings, rule: str) -> list:
    return [f for f in findings if f.rule_id == f"llm.{rule}"]


# --- indirect prompt injection (LLM01) -------------------------------------------

PAGE_TO_AGENT = """\
import json
import subprocess
import requests
from openai import OpenAI

client = OpenAI()
TOOLS = [{"type": "function", "function": {"name": "sh", "parameters": {}}}]

def research(url):
    page = requests.get(url, timeout=10).text
    messages = [{"role": "user", "content": "Summarize this page:\\n" + page}]
    for _ in range(3):
        msg = client.chat.completions.create(model="m", messages=messages, tools=TOOLS).choices[0].message
        for call in msg.tool_calls or []:
            cmd = json.loads(call.function.arguments)["cmd"]
            {sink}
    return msg.content
"""


def test_external_page_into_model_whose_output_reaches_a_shell(tmp_path):
    code = PAGE_TO_AGENT.replace("{sink}", "subprocess.run(cmd, shell=True)")
    hits = _hits(_scan(tmp_path, code), "indirect-prompt-injection")
    assert len(hits) == 1
    hit = hits[0]
    assert hit.owasp == ["LLM01:2025-Prompt Injection"]
    assert hit.severity.label == "High"
    assert hit.metadata["source"] == "an HTTP response"
    assert hit.metadata["sinks"][0]["kind"] == "shell"
    assert "CWE-1427" in hit.cwe


def test_summarizing_a_page_without_tools_or_sinks_is_not_reported(tmp_path):
    code = (
        "import requests\nfrom openai import OpenAI\nclient = OpenAI()\n"
        "def summarize(url):\n"
        "    page = requests.get(url, timeout=10).text\n"
        "    r = client.chat.completions.create(model='m', messages=["
        "{'role': 'user', 'content': page}])\n"
        "    return r.choices[0].message.content\n"
    )
    assert _hits(_scan(tmp_path, code), "indirect-prompt-injection") == []


def test_agent_tool_result_with_a_side_effecting_tool(tmp_path):
    code = (
        "import os\n"
        "from langchain_core.tools import tool\n"
        "from langchain_openai import ChatOpenAI\n"
        "from langgraph.prebuilt import create_react_agent\n"
        "@tool\n"
        "def read_note(path: str) -> str:\n"
        "    '''Read a note.'''\n"
        "    return open(path).read()\n"
        "@tool\n"
        "def delete(path: str) -> str:\n"
        "    '''Delete a file.'''\n"
        "    os.remove(path)\n"
        "    return 'ok'\n"
        "agent = create_react_agent(ChatOpenAI(), [read_note, delete])\n"
        "def run(q):\n"
        "    return agent.invoke({'messages': [('user', q)]})\n"
    )
    findings = _scan(tmp_path, code)
    hits = _hits(findings, "indirect-prompt-injection")
    assert len(hits) == 1
    assert hits[0].metadata["tools"] == {"delete": ["file"]}
    assert "read_note" in hits[0].metadata["source"]
    assert _hits(findings, "tool-argument-to-sink")


def test_tools_without_model_chosen_side_effects_are_not_reported(tmp_path):
    code = (
        "from typing import Literal\n"
        "import httpx\n"
        "from langchain_core.tools import tool\n"
        "from langchain_openai import ChatOpenAI\n"
        "from langgraph.prebuilt import create_react_agent\n"
        "@tool\n"
        "def search(q: str) -> str:\n"
        "    '''Search.'''\n"
        "    return httpx.get('https://api.example.com/s', params={'q': q}).text\n"
        "@tool\n"
        "def set_flag(on: Literal['yes', 'no']) -> str:\n"
        "    '''Set a flag.'''\n"
        "    return httpx.post('https://api.example.com/flag', json={'on': on}).text\n"
        "agent = create_react_agent(ChatOpenAI(), [search, set_flag])\n"
        "def run(q):\n"
        "    return agent.invoke({'messages': [('user', q)]})\n"
    )
    assert _hits(_scan(tmp_path, code), "indirect-prompt-injection") == []


def test_js_fetched_issue_into_generate_text_with_an_exec_tool(tmp_path):
    code = (
        'import { generateText, tool } from "ai";\n'
        'import { openai } from "@ai-sdk/openai";\n'
        'import { exec } from "node:child_process";\n'
        'import { promisify } from "node:util";\n'
        'import { z } from "zod";\n'
        "const sh = promisify(exec);\n"
        "export async function triage(url) {\n"
        "  const issue = await (await fetch(url)).json();\n"
        "  return generateText({\n"
        '    model: openai("gpt-4o"),\n'
        "    prompt: `Fix: ${issue.body}`,\n"
        "    tools: { shell: tool({ parameters: z.object({ cmd: z.string() }),\n"
        "      execute: async ({ cmd }) => (await sh(cmd)).stdout }) },\n"
        "  });\n"
        "}\n"
    )
    findings = _scan(tmp_path, code, "triage.ts")
    assert _hits(findings, "tool-handler-exec")
    hits = _hits(findings, "indirect-prompt-injection")
    assert len(hits) == 1
    assert hits[0].metadata["tools"] == {"shell": ["shell"]}


def test_js_enum_tool_argument_is_not_tracked(tmp_path):
    code = (
        'import { generateText, tool } from "ai";\n'
        'import { openai } from "@ai-sdk/openai";\n'
        'import { execFile } from "node:child_process";\n'
        'import { z } from "zod";\n'
        "export async function triage(url) {\n"
        "  const issue = await (await fetch(url)).json();\n"
        "  return generateText({\n"
        '    model: openai("gpt-4o"),\n'
        "    prompt: issue.body,\n"
        "    tools: { run: tool({ parameters: z.object({ s: z.enum(['a', 'b']) }),\n"
        "      execute: async ({ s }) => execFile(s, []) }) },\n"
        "  });\n"
        "}\n"
    )
    findings = _scan(tmp_path, code, "triage.ts")
    assert _rules(findings) & {"tool-handler-exec", "indirect-prompt-injection"} == set()


# --- tool chaining: model-chosen tool arguments (LLM06) ------------------------------


@pytest.mark.parametrize(
    ("body", "kind"),
    [
        ("    open(path, 'w').write(text)\n", "file"),
        ("    import requests\n    return requests.get(path).text\n", "ssrf"),
        ("    import sqlite3\n    sqlite3.connect('x').execute(f\"SELECT {path}\")\n", "sql"),
        (
            "    import smtplib\n    from email.message import EmailMessage\n"
            "    m = EmailMessage()\n    m['From'], m['To'] = 'a@example.com', path\n"
            "    smtplib.SMTP('localhost').send_message(m)\n",
            "recipient",
        ),
    ],
)
def test_tool_argument_reaches_a_sink(tmp_path, body, kind):
    code = (
        "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
        "@mcp.tool()\ndef act(path: str, text: str = '') -> str:\n" + body
    )
    hits = _hits(_scan(tmp_path, code), "tool-argument-to-sink")
    assert [h.metadata["sink"] for h in hits] == [kind]
    assert hits[0].owasp == ["LLM06:2025-Excessive Agency"]


@pytest.mark.parametrize(
    "body",
    [
        "    p = (BASE / path).resolve()\n    if not p.is_relative_to(BASE):\n"
        "        raise ValueError('no')\n    p.write_text(text)\n",
        "    import requests\n    return requests.get(f'https://api.example.com/{path}').text\n",
        "    import sqlite3\n    sqlite3.connect('x').execute('SELECT ?', (path,))\n",
        "    import smtplib\n    from email.message import EmailMessage\n"
        "    m = EmailMessage()\n    m['To'] = TEAMS['ops']\n    m.set_content(path)\n"
        "    smtplib.SMTP('localhost').send_message(m)\n",
    ],
)
def test_tool_argument_negatives(tmp_path, body):
    code = (
        "from pathlib import Path\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
        "BASE = Path('/srv/notes').resolve()\nTEAMS = {'ops': 'ops@example.com'}\n"
        "@mcp.tool()\ndef act(path: str, text: str = '') -> str:\n" + body
    )
    assert _hits(_scan(tmp_path, code), "tool-argument-to-sink") == []


def test_js_mcp_tool_handlers(tmp_path):
    code = (
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'import { z } from "zod";\n'
        'const server = new McpServer({ name: "x", version: "1.0.0" });\n'
        'server.tool("fetch", "Fetch", { url: z.string() }, async ({ url }) => {\n'
        "  const r = await fetch(url);\n"
        '  return { content: [{ type: "text", text: await r.text() }] };\n'
        "});\n"
        'server.registerTool("calc", { inputSchema: { e: z.string() } }, async ({ e }) => {\n'
        '  return { content: [{ type: "text", text: String(eval(e)) }] };\n'
        "});\n"
    )
    findings = _scan(tmp_path, code, "server.ts")
    assert [h.metadata["sink"] for h in _hits(findings, "tool-argument-to-sink")] == ["ssrf"]
    assert [h.metadata["sink"] for h in _hits(findings, "tool-handler-exec")] == ["code"]


def test_js_host_allowlist_and_path_prefix_guards(tmp_path):
    code = (
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'import { writeFile } from "node:fs/promises";\n'
        'import path from "node:path";\n'
        'import { z } from "zod";\n'
        'const server = new McpServer({ name: "x", version: "1.0.0" });\n'
        'const HOSTS = new Set(["docs.example.com"]);\n'
        'const ROOT = path.resolve("/work");\n'
        'server.tool("fetch", "Fetch", { url: z.string() }, async ({ url }) => {\n'
        "  const u = new URL(url);\n"
        "  if (!HOSTS.has(u.hostname)) return { content: [] };\n"
        "  return { content: [{ type: 'text', text: await (await fetch(u)).text() }] };\n"
        "});\n"
        'server.tool("save", "Save", { p: z.string(), s: z.string() }, async ({ p, s }) => {\n'
        "  const target = path.resolve(ROOT, p);\n"
        "  if (!target.startsWith(ROOT + path.sep)) return { content: [] };\n"
        "  await writeFile(target, s);\n"
        "  return { content: [] };\n"
        "});\n"
    )
    assert _hits(_scan(tmp_path, code, "server.ts"), "tool-argument-to-sink") == []


def test_js_dispatched_tool_call_recipient(tmp_path):
    code = (
        'import Anthropic from "@anthropic-ai/sdk";\n'
        'import nodemailer from "nodemailer";\n'
        "const anthropic = new Anthropic();\n"
        "const mailer = nodemailer.createTransport({});\n"
        "async function send(input) {\n"
        '  await mailer.sendMail({ from: "a@example.com", to: input.to, text: input.body });\n'
        "}\n"
        "export async function handle(messages) {\n"
        "  const res = await anthropic.messages.create({ model: 'm', max_tokens: 9, messages });\n"
        "  for (const block of res.content) { await send(block.input); }\n"
        "}\n"
    )
    hits = _hits(_scan(tmp_path, code, "a.ts"), "tool-argument-to-sink")
    assert [h.metadata["sink"] for h in hits] == ["recipient"]


# --- trust boundaries ----------------------------------------------------------------


def test_client_supplied_message_list_and_role(tmp_path):
    code = (
        "from fastapi import FastAPI\nfrom openai import OpenAI\nfrom pydantic import BaseModel\n"
        "app = FastAPI()\nclient = OpenAI()\n"
        "class Req(BaseModel):\n    messages: list[dict]\n    role: str\n    text: str\n"
        "@app.post('/a')\ndef a(req: Req):\n"
        "    return client.chat.completions.create(model='m', messages=["
        "{'role': 'system', 'content': 'Rules.'}] + req.messages)\n"
        "@app.post('/b')\ndef b(req: Req):\n"
        "    return client.chat.completions.create(model='m', messages=["
        "{'role': req.role, 'content': req.text}])\n"
    )
    hits = _hits(_scan(tmp_path, code), "untrusted-message-role")
    assert len(hits) == 2


def test_user_text_in_a_fixed_role_is_not_a_role_problem(tmp_path):
    code = (
        "from fastapi import FastAPI\nfrom openai import OpenAI\nfrom pydantic import BaseModel\n"
        "app = FastAPI()\nclient = OpenAI()\nHISTORY = []\n"
        "class Req(BaseModel):\n    text: str\n"
        "@app.post('/a')\ndef a(req: Req):\n"
        "    HISTORY.append({'role': 'user', 'content': req.text})\n"
        "    return client.chat.completions.create(model='m', messages=["
        "{'role': 'system', 'content': 'Rules.'}] + HISTORY)\n"
    )
    assert _hits(_scan(tmp_path, code), "untrusted-message-role") == []


def test_js_role_and_system_prompt_from_request(tmp_path):
    code = (
        'import express from "express";\nimport OpenAI from "openai";\n'
        "const app = express();\nconst openai = new OpenAI();\n"
        'app.post("/c", async (req, res) => {\n'
        "  const { role, text, persona } = req.body;\n"
        "  const r = await openai.chat.completions.create({ model: 'm', messages: [\n"
        "    { role: 'system', content: `Act as ${persona}` },\n"
        "    { role, content: text },\n"
        "  ] });\n"
        "  res.json(r.choices[0].message);\n"
        "});\n"
    )
    findings = _scan(tmp_path, code, "server.js")
    assert len(_hits(findings, "untrusted-input-in-system-prompt")) == 1
    assert len(_hits(findings, "untrusted-message-role")) == 1


def test_request_flag_choosing_a_write_tool(tmp_path):
    code = (
        "import httpx\nfrom fastapi import FastAPI\nfrom langchain_core.tools import tool\n"
        "from langchain_openai import ChatOpenAI\nfrom langgraph.prebuilt import create_react_agent\n"
        "app = FastAPI()\n"
        "@tool\ndef read(i: int) -> str:\n    '''Read.'''\n"
        "    return httpx.get(f'https://t.example.com/{i}').text\n"
        "@tool\ndef close(i: int) -> str:\n    '''Close.'''\n"
        "    return httpx.delete(f'https://t.example.com/{i}').text\n"
        "@app.post('/ask')\ndef ask(q: str, admin: bool = False):\n"
        "    tools = [read, close] if {cond} else [read]\n"
        "    return create_react_agent(ChatOpenAI(), tools).invoke({'messages': [('user', q)]})\n"
    )
    hits = _hits(_scan(tmp_path, code.replace("{cond}", "admin")), "untrusted-tool-selection")
    assert len(hits) == 1
    assert hits[0].metadata["tools"] == ["close"]
    safe = code.replace("{cond}", "is_admin()").replace(
        "app = FastAPI()\n", "app = FastAPI()\ndef is_admin():\n    return False\n"
    )
    assert _hits(_scan(tmp_path, safe), "untrusted-tool-selection") == []


def test_stored_free_text_in_a_system_prompt(tmp_path):
    code = (
        "from anthropic import Anthropic\nfrom models import Shop\nclient = Anthropic()\n"
        "def ask(shop_id, q):\n"
        "    shop = Shop.query.get_or_404(shop_id)\n"
        "    return client.messages.create(model='m', max_tokens=9,\n"
        "        system=f'Rules. Shop {shop.name}. Policy: {shop.policy_text}',\n"
        "        messages=[{'role': 'user', 'content': q}])\n"
    )
    hits = _hits(_scan(tmp_path, code), "untrusted-input-in-system-prompt")
    assert len(hits) == 1
    assert "shop.policy_text" in hits[0].metadata["source"]


# --- secrets in prompts (LLM02) ---------------------------------------------------------


def test_secret_from_environment_in_prompt(tmp_path):
    code = (
        "import os\nfrom openai import OpenAI\n"
        "client = OpenAI(api_key=os.environ['OPENAI_API_KEY'])\n"
        "def draft(q):\n"
        "    key = os.getenv('STRIPE_SECRET_KEY')\n"
        "    return client.chat.completions.create(model='m', messages=["
        "{'role': 'user', 'content': f'Use key {key} to answer {q}'}])\n"
    )
    hits = _hits(_scan(tmp_path, code), "secret-sent-to-model")
    assert len(hits) == 1
    assert hits[0].owasp == ["LLM02:2025-Sensitive Information Disclosure"]
    assert "STRIPE_SECRET_KEY" in hits[0].metadata["source"]


def test_secret_only_used_for_the_client_is_not_reported(tmp_path):
    code = (
        'import OpenAI from "openai";\n'
        "const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\n"
        "export async function ask(q) {\n"
        "  const r = await fetch('https://api.example.com', "
        "{ headers: { Authorization: `Bearer ${process.env.API_TOKEN}` } });\n"
        "  return openai.chat.completions.create({ model: 'm', messages: "
        "[{ role: 'user', content: q }] });\n"
        "}\n"
    )
    assert _hits(_scan(tmp_path, code, "a.js"), "secret-sent-to-model") == []


# --- smaller precision fixes ------------------------------------------------------------


def test_argv_variable_with_a_fixed_program_is_not_a_shell_sink(tmp_path):
    code = (
        "import subprocess\nfrom langchain_core.tools import tool\n"
        "BASE = ['docker', 'run', '--rm', 'sandbox']\n"
        "@tool\ndef run(code: str) -> str:\n"
        "    '''Run code in a sandbox.'''\n"
        "    argv = BASE + ['python', '-c', code]\n"
        "    return subprocess.run(argv, capture_output=True).stdout\n"
    )
    assert _hits(_scan(tmp_path, code), "tool-handler-exec") == []


def test_express_html_response_of_model_output(tmp_path):
    code = (
        'import express from "express";\nimport OpenAI from "openai";\n'
        "const app = express();\nconst openai = new OpenAI();\n"
        'app.get("/b", async (req, res) => {\n'
        "  const c = await openai.chat.completions.create({ model: 'm', messages: [] });\n"
        "  const text = c.choices[0].message.content;\n"
        "  res.send(`<main>${text}</main>`);\n"
        "  res.send(text);\n"
        "});\n"
    )
    hits = _hits(_scan(tmp_path, code, "a.js"), "insecure-output-handling")
    assert [(h.metadata["sink"], h.location.start_line) for h in hits] == [("html", 8)]


def test_client_built_with_a_secret_does_not_taint_its_responses(tmp_path):
    py = (
        "import os\nfrom github import Github\nfrom openai import OpenAI\n"
        "client = OpenAI()\ngh = Github(os.environ['GITHUB_TOKEN'])\n"
        "def triage(repo, n):\n"
        "    issue = gh.get_repo(repo).get_issue(n)\n"
        "    return client.chat.completions.create(model='m', messages=["
        "{'role': 'user', 'content': issue.body}])\n"
    )
    assert _hits(_scan(tmp_path, py), "secret-sent-to-model") == []
    js = (
        'const { WebClient } = require("@slack/web-api");\nconst OpenAI = require("openai");\n'
        "const slack = new WebClient(process.env.SLACK_BOT_TOKEN);\nconst openai = new OpenAI();\n"
        "async function digest(channel) {\n"
        "  const h = await slack.conversations.history({ channel });\n"
        "  const text = h.messages.map((m) => m.text).join('\\n');\n"
        "  return openai.chat.completions.create({ model: 'm', messages: "
        "[{ role: 'user', content: text }] });\n"
        "}\n"
    )
    assert _hits(_scan(tmp_path, js, "digest.js"), "secret-sent-to-model") == []


def test_tool_object_over_loaded_documents_is_not_a_tool_selection(tmp_path):
    code = (
        "import sqlite3\n"
        "from llama_index.core import SimpleDirectoryReader, VectorStoreIndex\n"
        "from llama_index.core.agent import ReActAgent\n"
        "from llama_index.core.tools import FunctionTool, QueryEngineTool\n"
        "from llama_index.llms.openai import OpenAI\n"
        "DB = sqlite3.connect('x.db')\n"
        "def lookup(i: int) -> str:\n"
        "    '''Look up a row.'''\n"
        "    return str(DB.execute('SELECT * FROM t WHERE id = ?', (i,)).fetchone())\n"
        "docs = SimpleDirectoryReader('uploads').load_data()\n"
        "search = QueryEngineTool.from_defaults(VectorStoreIndex.from_documents(docs).as_query_engine())\n"
        "agent = ReActAgent.from_tools([search, FunctionTool.from_defaults(fn=lookup)], llm=OpenAI())\n"
    )
    assert _hits(_scan(tmp_path, code), "untrusted-tool-selection") == []
