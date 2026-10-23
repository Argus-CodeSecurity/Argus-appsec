from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

ALLOWED_HOSTS = {"en.wikipedia.org", "docs.python.org", "arxiv.org"}


@tool
def fetch_url(url: str) -> str:
    """Fetch a page from Wikipedia, the Python docs or arXiv and return its text."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        return "That site is not on the allowed list."
    resp = requests.get(url, timeout=10, allow_redirects=False)
    return BeautifulSoup(resp.text, "html.parser").get_text(" ", strip=True)[:8000]


prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a research assistant. Fetch pages to answer questions and cite them."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
llm = ChatOpenAI(model="gpt-4o-mini")
agent = create_tool_calling_agent(llm, [fetch_url], prompt)
executor = AgentExecutor(agent=agent, tools=[fetch_url], max_iterations=5)


def research(question: str) -> str:
    return executor.invoke({"input": question})["output"]
