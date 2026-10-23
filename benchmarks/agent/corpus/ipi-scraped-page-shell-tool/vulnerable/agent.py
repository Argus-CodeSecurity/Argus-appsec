import sys

from langchain_community.document_loaders import WebBaseLoader
from langchain_community.tools import ShellTool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

llm = ChatOpenAI(model="gpt-4o", temperature=0)
agent = create_react_agent(
    llm,
    [ShellTool()],
    prompt="You are a DevOps helper. Follow the setup guide the user gives you and run the steps on this host.",
)


def load_guide(url: str) -> str:
    docs = WebBaseLoader(url).load()
    return "\n".join(d.page_content for d in docs)[:20000]


def set_up(url: str) -> str:
    guide = load_guide(url)
    task = f"Set up the project using this guide from {url}:\n\n{guide}"
    result = agent.invoke({"messages": [("user", task)]})
    return result["messages"][-1].content


if __name__ == "__main__":
    print(set_up(sys.argv[1]))
