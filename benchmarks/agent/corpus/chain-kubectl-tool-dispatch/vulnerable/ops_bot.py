import json
import subprocess

from openai import OpenAI

client = OpenAI()
TOOLS = [{
    "type": "function",
    "function": {
        "name": "kubectl",
        "description": "Run kubectl against the staging cluster.",
        "parameters": {"type": "object", "properties": {"args": {"type": "string"}}, "required": ["args"]},
    },
}]


def ask(question: str) -> str:
    messages = [
        {"role": "system", "content": "You help on-call engineers inspect the staging cluster."},
        {"role": "user", "content": question},
    ]
    for _ in range(6):
        msg = client.chat.completions.create(model="gpt-4o", messages=messages, tools=TOOLS).choices[0].message
        if not msg.tool_calls:
            return msg.content
        messages.append(msg)
        for tc in msg.tool_calls:
            args = json.loads(tc.function.arguments)["args"]
            out = subprocess.run(f"kubectl {args}", shell=True, capture_output=True, text=True, timeout=60)
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": out.stdout + out.stderr})
    return "Stopped after too many steps."
