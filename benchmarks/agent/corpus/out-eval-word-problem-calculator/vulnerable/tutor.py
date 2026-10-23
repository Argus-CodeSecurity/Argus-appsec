from anthropic import Anthropic
from flask import Flask, jsonify, request

app = Flask(__name__)
client = Anthropic()

SYSTEM = (
    "Translate the student's word problem into a single Python arithmetic expression. "
    "Reply with the expression only."
)


@app.post("/solve")
def solve():
    problem = request.json["problem"]
    msg = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=200,
        system=SYSTEM,
        messages=[{"role": "user", "content": problem}],
    )
    expression = msg.content[0].text.strip().strip("`")
    answer = eval(expression)
    return jsonify(expression=expression, answer=answer)
