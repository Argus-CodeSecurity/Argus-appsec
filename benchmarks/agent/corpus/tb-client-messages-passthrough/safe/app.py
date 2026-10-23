from collections import defaultdict

from fastapi import FastAPI
from openai import OpenAI
from pydantic import BaseModel, Field

app = FastAPI()
client = OpenAI()
HISTORY: dict[str, list[dict]] = defaultdict(list)

SYSTEM_PROMPT = (
    "You are the Acme Bank assistant. Answer questions about Acme products only. "
    "Do not give investment advice and do not promise fee waivers."
)


class ChatRequest(BaseModel):
    conversation_id: str
    message: str = Field(max_length=4000)


@app.post("/chat")
def chat(req: ChatRequest):
    # the transcript lives on the server; the browser only sends the new user turn
    history = HISTORY[req.conversation_id]
    history.append({"role": "user", "content": req.message})
    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + history[-20:]
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=messages)
    reply = resp.choices[0].message.content
    history.append({"role": "assistant", "content": reply})
    return {"reply": reply}
