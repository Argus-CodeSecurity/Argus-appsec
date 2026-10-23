import sqlite3

from llama_index.core import SimpleDirectoryReader, VectorStoreIndex
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool, QueryEngineTool
from llama_index.llms.openai import OpenAI

DB = sqlite3.connect("crm.db", check_same_thread=False)
FIELDS = {"payment_terms", "discount_pct", "billing_email"}


def update_account(account_id: int, field: str, value: str) -> str:
    """Update one field on a CRM account."""
    if field not in FIELDS:
        return "unsupported field"
    DB.execute(f"UPDATE accounts SET {field} = ? WHERE id = ?", (value, account_id))
    DB.commit()
    return "updated"


# contracts that customers upload through the self-service portal
docs = SimpleDirectoryReader("uploads/contracts").load_data()
contracts = QueryEngineTool.from_defaults(
    VectorStoreIndex.from_documents(docs).as_query_engine(),
    name="contracts",
    description="Search signed customer contracts.",
)
agent = ReActAgent.from_tools(
    [contracts, FunctionTool.from_defaults(fn=update_account)],
    llm=OpenAI(model="gpt-4o"),
)


def sync_terms(account_id: int) -> str:
    task = f"Read the contract for account {account_id} and update its CRM fields to match the contract."
    return str(agent.chat(task))
