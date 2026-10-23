from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings
from openai import OpenAI

client = OpenAI()
# pages from the company wiki, which every employee and contractor can edit
wiki = Chroma(collection_name="wiki", embedding_function=OpenAIEmbeddings(), persist_directory="./wiki_index")

BASE_RULES = (
    "You are the internal IT helpdesk assistant. Only answer IT questions. "
    "Never tell users how to disable endpoint security or bypass SSO."
)


def answer(question: str) -> str:
    pages = wiki.similarity_search(question, k=4)
    context = "\n\n".join(f"## {p.metadata.get('title', 'untitled')}\n{p.page_content}" for p in pages)
    system_prompt = f"{BASE_RULES}\n\nReference material:\n{context}"
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question},
        ],
    )
    return resp.choices[0].message.content
