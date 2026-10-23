import os

import httpx
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI


@tool
def find_host(service: str) -> str:
    """Look up the hostname that runs a service in the inventory."""
    r = httpx.get("https://inventory.internal.example.com/api/hosts", params={"service": service}, timeout=10)
    return r.json()[0]["hostname"]


@tool
def ping_host(host: str) -> str:
    """Ping a host three times and return the output."""
    return os.popen(f"ping -c 3 {host}").read()


TOOLS = {"find_host": find_host, "ping_host": ping_host}
llm = ChatOpenAI(model="gpt-4o-mini").bind_tools(list(TOOLS.values()))


def check_service(service: str) -> str:
    messages = [HumanMessage(f"Is the host running {service} reachable?")]
    for _ in range(4):
        ai = llm.invoke(messages)
        messages.append(ai)
        if not ai.tool_calls:
            return ai.content
        for call in ai.tool_calls:
            output = TOOLS[call["name"]].invoke(call["args"])
            messages.append(ToolMessage(content=str(output), tool_call_id=call["id"]))
    return "no answer"
