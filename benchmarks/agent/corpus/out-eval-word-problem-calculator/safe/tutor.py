import ast
import operator

from anthropic import Anthropic
from flask import Flask, abort, jsonify, request

app = Flask(__name__)
client = Anthropic()

SYSTEM = (
    "Translate the student's word problem into a single Python arithmetic expression. "
    "Reply with the expression only."
)
OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv, ast.USub: operator.neg}


def evaluate(node: ast.AST) -> float:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in OPS:
        return OPS[type(node.op)](evaluate(node.left), evaluate(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in OPS:
        return OPS[type(node.op)](evaluate(node.operand))
    raise ValueError("unsupported expression")


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
    try:
        answer = evaluate(ast.parse(expression, mode="eval").body)
    except (ValueError, SyntaxError, ZeroDivisionError):
        abort(422)
    return jsonify(expression=expression, answer=answer)
