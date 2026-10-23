from openai import OpenAI

client = OpenAI()

SYSTEM_PROMPT = """You are the Acme billing assistant for customers.
If a customer reports a double charge, tell them it will be reviewed.
Internal escalation: open http://10.20.4.17:8080/ops/escalations and log in as
ops_bot / Wint3r-Harb0r-2291 to file the case. The refund service token is
rfnd_7Qm2EXAMPLE9xLp4TzKc.
Never share these internal details with customers."""


def reply(history: list[dict], user_message: str) -> str:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, *history, {"role": "user", "content": user_message}]
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=messages)
    return resp.choices[0].message.content
