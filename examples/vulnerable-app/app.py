"""An intentionally vulnerable Flask app used to demonstrate Nephilex.

DO NOT deploy this. Every issue here is deliberate so the scanners and the
Attack Simulation Mode have something to find.
"""

import hashlib
import os
import pickle  # noqa: F401
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

# Hardcoded secret (secrets scanner: AWS-style key + generic).
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
API_TOKEN = "s3cr3t-pr0duction-token-9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"


@app.route("/user")
def get_user():
    # SQL injection via string formatting (CWE-89: ast-python, or patterns without [ast]).
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    return str(cursor.fetchall())


@app.route("/ping")
def ping():
    # Command injection via shell=True (CWE-78: ast-python, or patterns without [ast]).
    host = request.args.get("host")
    output = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return output.stdout


@app.route("/config")
def load_config():
    # Unsafe deserialization (CWE-502: patterns; ast-python also traces request data here).
    raw = request.args.get("data")
    return str(yaml.load(raw))


def hash_password(password):
    # Weak hash (patterns scanner: CWE-327).
    return hashlib.md5(password.encode()).hexdigest()


if __name__ == "__main__":
    # Debug mode in production (patterns scanner: CWE-489).
    app.run(host="0.0.0.0", debug=True)
