import smtplib
from email.message import EmailMessage

from langchain_chroma import Chroma
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langgraph.prebuilt import create_react_agent

# public community forum posts, re-indexed every night
store = Chroma(collection_name="forum_posts", embedding_function=OpenAIEmbeddings(), persist_directory="./chroma")
retriever = store.as_retriever(search_kwargs={"k": 4})


@tool
def search_forum(query: str) -> str:
    """Search community forum posts."""
    return "\n\n".join(d.page_content for d in retriever.invoke(query))


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Email someone on behalf of the support team."""
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "support@example.com", to, subject
    msg.set_content(body)
    with smtplib.SMTP("localhost") as smtp:
        smtp.send_message(msg)
    return "sent"


agent = create_react_agent(
    ChatOpenAI(model="gpt-4o"),
    [search_forum, send_email],
    prompt="You are a support assistant. Answer from forum posts and send follow-up emails when needed.",
)


def answer(question: str, history: list) -> str:
    out = agent.invoke({"messages": history + [("user", question)]})
    return out["messages"][-1].content
