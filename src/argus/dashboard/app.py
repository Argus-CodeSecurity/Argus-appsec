"""The dashboard web app (FastAPI + server-rendered templates).

Pages: projects overview (``/``), project detail with a risk trend
(``/projects/{slug}``), and a scan's findings (``/scans/{id}``). Reports get in
either by uploading a JSON file (``/upload``) or by POSTing one to ``/api/scans``,
e.g. ``argus scan . -f json | curl -T- .../api/scans``.

Ingest endpoints are unauthenticated by design (local-first). Cap request bodies
so a single oversized POST cannot exhaust memory or fill the SQLite store.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session

from argus import __version__
from argus.dashboard import charts, store
from argus.dashboard.db import get_session

_HERE = Path(__file__).parent
#: Hard cap for uploaded / POSTed JSON reports (bytes). Large enough for real
#: scans; small enough to bound memory and disk when the dashboard is exposed.
_MAX_REPORT_BYTES = 20 * 1024 * 1024
_READ_CHUNK = 64 * 1024

templates = Jinja2Templates(directory=str(_HERE / "templates"))
templates.env.globals.update(
    severity_fill=charts.severity_fill,
    severity_label=store.severity_label,
    severity_order=charts.SEVERITY_ORDER,
    risk_band=charts.risk_band,
    argus_version=__version__,
)

app = FastAPI(title="Argus Dashboard", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")


def _too_large() -> HTTPException:
    return HTTPException(
        status_code=413,
        detail=f"Report exceeds {_MAX_REPORT_BYTES} byte limit",
    )


async def _read_body_limited(request: Request) -> str:
    """Read the request body, aborting at ``_MAX_REPORT_BYTES``."""
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > _MAX_REPORT_BYTES:
                raise _too_large()
        except ValueError:
            pass
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > _MAX_REPORT_BYTES:
            raise _too_large()
    return buf.decode("utf-8", "replace")


async def _read_upload_limited(file: UploadFile) -> str:
    """Read an uploaded file, aborting at ``_MAX_REPORT_BYTES``."""
    if file.size is not None and file.size > _MAX_REPORT_BYTES:
        raise _too_large()
    buf = bytearray()
    while True:
        chunk = await file.read(_READ_CHUNK)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > _MAX_REPORT_BYTES:
            raise _too_large()
    return buf.decode("utf-8", "replace")


@app.get("/", response_class=HTMLResponse)
def index(request: Request, session: Session = Depends(get_session)):
    return templates.TemplateResponse(request, "projects.html", {
        "projects": store.list_projects(session),
        "stats": store.overall_stats(session),
    })


@app.get("/projects/{slug}", response_class=HTMLResponse)
def project_detail(slug: str, request: Request, session: Session = Depends(get_session)):
    project = store.get_project(session, slug)
    if project is None or project.id is None:
        raise HTTPException(404, "Project not found")
    return templates.TemplateResponse(request, "project.html", {
        "project": project,
        "scans": store.list_scans(session, project.id),
        "trend": charts.trend_geometry(store.trend(session, project.id)),
    })


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(scan_id: int, request: Request, session: Session = Depends(get_session)):
    scan = store.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return templates.TemplateResponse(request, "scan.html", {
        "scan": scan,
        "project": store.get_project_by_id(session, scan.project_id),
        "findings": store.get_findings(session, scan_id),
        "bar": charts.severity_bar(scan.severity_counts, scan.total_findings),
    })


@app.get("/upload", response_class=HTMLResponse)
def upload_form(request: Request):
    return templates.TemplateResponse(request, "upload.html", {})


@app.post("/upload")
async def upload_submit(file: UploadFile, session: Session = Depends(get_session)):
    raw = await _read_upload_limited(file)
    try:
        scan = store.ingest_report(session, raw)
    except Exception as exc:  # bad/incomplete report
        raise HTTPException(400, f"Not a valid Argus JSON report: {exc}") from exc
    return RedirectResponse(f"/scans/{scan.id}", status_code=303)


@app.post("/api/scans")
async def api_ingest(request: Request, session: Session = Depends(get_session)):
    try:
        raw = await _read_body_limited(request)
    except HTTPException as exc:
        if exc.status_code == 413:
            return JSONResponse({"error": exc.detail}, status_code=413)
        raise
    try:
        scan = store.ingest_report(session, raw)
    except Exception as exc:
        return JSONResponse({"error": f"invalid report: {exc}"}, status_code=400)
    return {"scan_id": scan.id, "url": f"/scans/{scan.id}",
            "risk_score": scan.risk_score, "findings": scan.total_findings}


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Launch the dashboard with uvicorn (used by ``argus dashboard``)."""
    import logging
    import uvicorn

    if host in ("0.0.0.0", "::"):
        logging.getLogger("argus.dashboard").warning(
            "Binding the dashboard to %s exposes scan history to the local network. "
            "Prefer 127.0.0.1 unless you intend to share it.",
            host,
        )
    uvicorn.run(app, host=host, port=port)
