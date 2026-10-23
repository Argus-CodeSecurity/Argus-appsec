import subprocess

import httpx
from anthropic import Anthropic

client = Anthropic()
TOOLS = [
    {"name": "web_search", "description": "Search the web.",
     "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]}},
    {"name": "bash", "description": "Run a shell command on the build host after the operator approves it.",
     "input_schema": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}},
]


def call_tool(name: str, args: dict) -> str:
    if name == "web_search":
        r = httpx.get("https://api.search.example.com/v1/search", params={"q": args["q"]}, timeout=15)
        return "\n".join(f"{h['title']}: {h['snippet']}" for h in r.json()["results"])
    print(f"\nThe agent wants to run:\n  {args['cmd']}")
    if input("Run this command? [y/N] ").strip().lower() != "y":
        return "The operator declined to run this command."
    proc = subprocess.run(args["cmd"], shell=True, capture_output=True, text=True, timeout=300)
    return proc.stdout + proc.stderr


def fix_build(error_log: str) -> str:
    messages = [{"role": "user", "content": f"The build failed with:\n{error_log}\nFind a fix and apply it."}]
    while True:
        resp = client.messages.create(model="claude-sonnet-4-5", max_tokens=2048, tools=TOOLS, messages=messages)
        messages.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            return "".join(b.text for b in resp.content if b.type == "text")
        results = [
            {"type": "tool_result", "tool_use_id": b.id, "content": call_tool(b.name, b.input)}
            for b in resp.content
            if b.type == "tool_use"
        ]
        messages.append({"role": "user", "content": results})
