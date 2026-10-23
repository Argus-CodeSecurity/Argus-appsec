from typing import Literal

import httpx
from fastapi import Depends, FastAPI
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from pydantic import BaseModel

from auth import User, get_current_user

app = FastAPI()
TRACKER = "https://tracker.internal.example.com/api"


@tool
def get_issue(issue_id: int) -> dict:
    """Fetch the status, assignee and priority of an issue."""
    data = httpx.get(f"{TRACKER}/issues/{issue_id}", timeout=10).json()
    return {k: data.get(k) for k in ("id", "status", "assignee", "priority")}


@tool
def set_status(issue_id: int, status: Literal["open", "in_progress", "closed"]) -> dict:
    """Change the status of an issue."""
    return httpx.patch(f"{TRACKER}/issues/{issue_id}", json={"status": status}, timeout=10).json()


class AskRequest(BaseModel):
    question: str


@app.post("/ask")
def ask(req: AskRequest, user: User = Depends(get_current_user)):
    # write access comes from the user's role in the tracker, never from the request
    allow_writes = user.role in {"maintainer", "admin"}
    tools = [get_issue, set_status] if allow_writes else [get_issue]
    agent = create_react_agent(ChatOpenAI(model="gpt-4o-mini"), tools)
    out = agent.invoke({"messages": [("user", req.question)]})
    return {"answer": out["messages"][-1].content}
