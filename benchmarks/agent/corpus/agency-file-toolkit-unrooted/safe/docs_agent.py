from langchain_community.agent_toolkits import FileManagementToolkit
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

DOCS_ROOT = "/srv/team-docs"

toolkit = FileManagementToolkit(
    root_dir=DOCS_ROOT,
    selected_tools=["read_file", "write_file", "list_directory"],
)
tools = toolkit.get_tools()

agent = create_react_agent(
    ChatOpenAI(model="gpt-4o-mini"),
    tools,
    prompt="You maintain the team's documentation. Create and tidy up markdown files when asked.",
)


def handle(request: str) -> str:
    out = agent.invoke({"messages": [("user", request)]})
    return out["messages"][-1].content


if __name__ == "__main__":
    print(handle(input("What should I do with the docs? ")))
