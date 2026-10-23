import json
from pathlib import Path

from fastapi import FastAPI, UploadFile
from openai import OpenAI

app = FastAPI()
client = OpenAI()
NOTES_DIR = Path("/srv/notes")

PROMPT = 'Turn the document into a note. Reply as JSON: {"filename": "<short-name>.md", "markdown": "..."}'


@app.post("/import")
async def import_document(file: UploadFile):
    text = (await file.read()).decode("utf-8", errors="replace")
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": PROMPT},
            {"role": "user", "content": text},
        ],
    )
    note = json.loads(resp.choices[0].message.content)
    target = NOTES_DIR / note["filename"]
    target.write_text(note["markdown"], encoding="utf-8")
    return {"saved": str(target)}
