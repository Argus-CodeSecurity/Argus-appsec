import subprocess
import tempfile
from pathlib import Path

from fastapi import FastAPI, UploadFile
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool
from llama_index.llms.openai import OpenAI

app = FastAPI()
SANDBOX = ["docker", "run", "--rm", "--network", "none", "--read-only", "--memory", "512m",
           "--cpus", "1", "--pids-limit", "64", "--user", "65534:65534"]


def make_agent(data_dir: Path) -> ReActAgent:
    def run_python(code: str) -> str:
        """Run Python code in a sandbox. The uploaded CSV is at /data/upload.csv."""
        argv = SANDBOX + ["-v", f"{data_dir}:/data:ro", "analytics-sandbox:3.12", "python", "-c", code]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        return (proc.stdout + proc.stderr)[-8000:]

    return ReActAgent.from_tools([FunctionTool.from_defaults(fn=run_python)], llm=OpenAI(model="gpt-4o"))


@app.post("/analyze")
async def analyze(file: UploadFile, question: str):
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "upload.csv").write_bytes(await file.read())
        agent = make_agent(Path(tmp))
        return {"answer": str(agent.chat(question))}
