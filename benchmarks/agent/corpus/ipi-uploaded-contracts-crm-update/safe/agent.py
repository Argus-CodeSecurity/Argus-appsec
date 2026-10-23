import sqlite3

from llama_index.core import SimpleDirectoryReader, VectorStoreIndex
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool, QueryEngineTool
from llama_index.llms.openai import OpenAI

DB = sqlite3.connect("crm.db", check_same_thread=False)


def get_account(account_id: int) -> str:
    """Return the CRM billing fields for one account."""
    row = DB.execute(
        "SELECT payment_terms, discount_pct, billing_email FROM accounts WHERE id = ?",
        (account_id,),
    ).fetchone()
    return str(row) if row else "no such account"


# contracts that customers upload through the self-service portal
docs = SimpleDirectoryReader("uploads/contracts").load_data()
contracts = QueryEngineTool.from_defaults(
    VectorStoreIndex.from_documents(docs).as_query_engine(),
    name="contracts",
    description="Search signed customer contracts.",
)
agent = ReActAgent.from_tools(
    [contracts, FunctionTool.from_defaults(fn=get_account)],
    llm=OpenAI(model="gpt-4o"),
)


def compare_terms(account_id: int) -> str:
    # the account manager reads this report and edits the CRM by hand
    task = f"Compare the contract for account {account_id} with its CRM fields and list any differences."
    return str(agent.chat(task))
