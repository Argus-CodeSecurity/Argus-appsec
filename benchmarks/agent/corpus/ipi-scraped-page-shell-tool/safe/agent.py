import subprocess
import sys
from typing import Literal

from langchain_community.document_loaders import WebBaseLoader
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

CHECKS = {"disk": ["df", "-h"], "uptime": ["uptime"], "memory": ["free", "-m"]}


@tool
def run_check(name: Literal["disk", "uptime", "memory"]) -> str:
    """Run one of the fixed host health checks."""
    argv = CHECKS.get(name)
    if argv is None:
        return "unknown check"
    return subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout


llm = ChatOpenAI(model="gpt-4o", temperature=0)
agent = create_react_agent(
    llm,
    [run_check],
    prompt="You are a DevOps helper. Check whether this host meets the requirements in the guide the user gives you.",
)


def load_guide(url: str) -> str:
    docs = WebBaseLoader(url).load()
    return "\n".join(d.page_content for d in docs)[:20000]


def check_requirements(url: str) -> str:
    guide = load_guide(url)
    task = f"Does this host meet the requirements in this guide from {url}?\n\n{guide}"
    result = agent.invoke({"messages": [("user", task)]})
    return result["messages"][-1].content


if __name__ == "__main__":
    print(check_requirements(sys.argv[1]))
