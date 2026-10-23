import contextlib
import io

import pandas as pd
from fastapi import FastAPI, UploadFile
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool
from llama_index.llms.openai import OpenAI

app = FastAPI()


def make_agent(df: pd.DataFrame) -> ReActAgent:
    def run_python(code: str) -> str:
        """Run Python code. A pandas DataFrame named df holds the uploaded data."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exec(code, {"df": df, "pd": pd})
        return buf.getvalue()

    return ReActAgent.from_tools([FunctionTool.from_defaults(fn=run_python)], llm=OpenAI(model="gpt-4o"))


@app.post("/analyze")
async def analyze(file: UploadFile, question: str):
    df = pd.read_csv(file.file)
    agent = make_agent(df)
    return {"answer": str(agent.chat(question))}
