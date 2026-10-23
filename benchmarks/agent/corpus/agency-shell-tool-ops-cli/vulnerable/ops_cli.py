from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_community.tools import ShellTool
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

shell = ShellTool()

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a Linux operations assistant on the production database host. Use the shell to help."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
llm = ChatOpenAI(model="gpt-4o", temperature=0)
agent = create_tool_calling_agent(llm, [shell], prompt)
executor = AgentExecutor(agent=agent, tools=[shell], verbose=True)


def main() -> None:
    while True:
        request = input("ops> ").strip()
        if request in {"exit", "quit"}:
            break
        print(executor.invoke({"input": request})["output"])


if __name__ == "__main__":
    main()
