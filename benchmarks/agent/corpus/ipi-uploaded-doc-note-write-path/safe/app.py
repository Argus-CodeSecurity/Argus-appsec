import json
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from openai import OpenAI

app = FastAPI()
client = OpenAI()
NOTES_DIR = Path("/srv/notes").resolve()

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
    name = Path(str(note.get("filename", ""))).name or "note.md"
    target = (NOTES_DIR / f"{uuid.uuid4().hex[:8]}-{name}").resolve()
    if not target.is_relative_to(NOTES_DIR) or target.suffix != ".md":
        raise HTTPException(status_code=422, detail="bad note filename")
    target.write_text(str(note.get("markdown", "")), encoding="utf-8")
    return {"saved": target.name}
