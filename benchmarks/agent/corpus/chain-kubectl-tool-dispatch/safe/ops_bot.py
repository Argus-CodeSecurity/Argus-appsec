import json
import subprocess

from openai import OpenAI

client = OpenAI()
NAMESPACES = ["web", "workers", "payments"]
ACTIONS = {
    "list_pods": ["get", "pods", "-o", "wide"],
    "list_deployments": ["get", "deployments"],
    "recent_events": ["get", "events", "--sort-by=.lastTimestamp"],
}
PARAMS = {
    "type": "object",
    "properties": {"action": {"type": "string", "enum": list(ACTIONS)}, "namespace": {"type": "string", "enum": NAMESPACES}},
    "required": ["action", "namespace"],
}
TOOLS = [{"type": "function", "function": {"name": "kubectl", "description": "Run a read-only kubectl query.", "parameters": PARAMS}}]


def run_kubectl(action: str, namespace: str) -> str:
    if action not in ACTIONS or namespace not in NAMESPACES:
        return "action or namespace not allowed"
    out = subprocess.run(["kubectl", *ACTIONS[action], "-n", namespace], capture_output=True, text=True, timeout=60)
    return out.stdout + out.stderr


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
            args = json.loads(tc.function.arguments)
            out = run_kubectl(args.get("action", ""), args.get("namespace", ""))
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": out})
    return "Stopped after too many steps."
