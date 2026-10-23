from fastapi import FastAPI
from openai import OpenAI
from pydantic import BaseModel

app = FastAPI()
client = OpenAI()

SYSTEM_PROMPT = (
    "You are the Acme Bank assistant. Answer questions about Acme products only. "
    "Do not give investment advice and do not promise fee waivers."
)


class ChatRequest(BaseModel):
    messages: list[dict]


@app.post("/chat")
def chat(req: ChatRequest):
    # the widget keeps the transcript in the browser and sends it with every turn
    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + req.messages
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=messages)
    return {"reply": resp.choices[0].message.content}
