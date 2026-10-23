from anthropic import Anthropic
from flask import Flask, jsonify, request

from marketplace.models import Store

app = Flask(__name__)
client = Anthropic()


@app.post("/stores/<int:store_id>/ask")
def ask_store(store_id: int):
    store = Store.query.get_or_404(store_id)
    # policy_text is written by the seller in their store settings
    system = (
        "You answer buyer questions for the marketplace. Follow marketplace rules: "
        "never ask buyers to pay outside the platform and never share personal contact details.\n\n"
        f"Store name: {store.name}\nStore policy:\n{store.policy_text}"
    )
    msg = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=512,
        system=system,
        messages=[{"role": "user", "content": request.json["question"]}],
    )
    return jsonify(answer=msg.content[0].text)
