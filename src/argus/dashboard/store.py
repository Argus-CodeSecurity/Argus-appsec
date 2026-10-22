"""Ingesting Argus reports and querying history for the dashboard views.

Ingestion parses an Argus JSON report back into the real
:class:`~argus.core.models.ScanResult`, so the risk score, severity counts, and
per-finding math are computed by Argus's own code, the dashboard never
re-implements them and can never disagree with the CLI.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sqlmodel import Session, col, func, select

from argus.core.models import ScanResult, Severity
from argus.dashboard.db import Finding, Project, Scan


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "project"


def severity_label(value: int) -> str:
    try:
        return Severity(value).label
    except ValueError:
        return "Info"


def _get_or_create_project(session: Session, name: str) -> tuple[Project, int]:
    slug = _slugify(name)
    project = session.exec(select(Project).where(Project.slug == slug)).first()
    if project is None:
        project = Project(slug=slug, name=name)
        session.add(project)
        session.flush()
    assert project.id is not None  # assigned by the database on flush
    return project, project.id


def ingest_report(session: Session, raw_json: str) -> Scan:
    """Parse an Argus JSON report and store it as a scan with its findings.

    The project, scan, and findings are written in one transaction: a report that
    fails part-way through never leaves a half-ingested scan behind.
    """
    result = ScanResult.model_validate_json(raw_json)
    summary = result.project_summary or {}
    name = summary.get("name") or (result.target.rsplit("/", 1)[-1]) or result.target
    try:
        return _store_result(session, result, summary, str(name))
    except Exception:
        session.rollback()
        raise


def _store_result(session: Session, result: ScanResult, summary: dict, name: str) -> Scan:
    _, project_id = _get_or_create_project(session, name)

    scan = Scan(
        project_id=project_id,
        created_at=result.finished_at or result.started_at or datetime.now(timezone.utc),
        argus_version=result.argus_version,
        target=result.target,
        risk_score=result.aggregate_risk(),
        highest_severity=int(result.highest_severity()),
        total_findings=len(result.findings),
        severity_counts=result.counts_by_severity(),
        project_summary=summary,
    )
    session.add(scan)
    session.flush()
    assert scan.id is not None  # assigned by the database on flush
    scan_id = scan.id

    for f in result.sorted_findings():
        session.add(Finding(
            scan_id=scan_id,
            rule_id=f.rule_id, scanner=f.scanner, title=f.title,
            severity=int(f.severity), confidence=int(f.confidence),
            likelihood=int(f.likelihood), risk_score=f.risk_score(),
            path=f.location.path, line=f.location.start_line,
            snippet=f.location.snippet or "",
            cwe=f.cwe, owasp=f.owasp,
            why_vulnerable=f.why_vulnerable,
            attacker_perspective=f.attacker_perspective,
            business_impact=f.business_impact,
            remediation=(f.remediation.summary if f.remediation else ""),
            tags=f.tags,
        ))
    session.commit()
    session.refresh(scan)
    return scan


# --- queries ---------------------------------------------------------------
def list_projects(session: Session) -> list[dict]:
    """Projects with their latest scan's headline numbers, worst risk first."""
    counts: dict[int, int] = {
        project_id: count
        for project_id, count in session.exec(
            select(Scan.project_id, func.count()).group_by(col(Scan.project_id))
        ).all()
    }
    out: list[dict] = []
    for project in session.exec(select(Project)).all():
        latest = session.exec(
            select(Scan).where(Scan.project_id == project.id)
            .order_by(col(Scan.created_at).desc())
        ).first()
        out.append({
            "project": project,
            "latest": latest,
            "scan_count": counts.get(project.id or -1, 0),
        })
    out.sort(key=lambda r: (r["latest"].risk_score if r["latest"] else -1), reverse=True)
    return out


def get_project(session: Session, slug: str) -> Project | None:
    return session.exec(select(Project).where(Project.slug == slug)).first()


def get_project_by_id(session: Session, project_id: int) -> Project | None:
    return session.get(Project, project_id)


def list_scans(session: Session, project_id: int) -> list[Scan]:
    return list(session.exec(
        select(Scan).where(Scan.project_id == project_id)
        .order_by(col(Scan.created_at).desc())
    ).all())


def get_scan(session: Session, scan_id: int) -> Scan | None:
    return session.get(Scan, scan_id)


def get_findings(session: Session, scan_id: int) -> list[Finding]:
    return list(session.exec(
        select(Finding).where(Finding.scan_id == scan_id)
        .order_by(col(Finding.severity).desc(), col(Finding.risk_score).desc())
    ).all())


def trend(session: Session, project_id: int) -> list[Scan]:
    """Scans oldest-first, for time-series charts."""
    return list(session.exec(
        select(Scan).where(Scan.project_id == project_id)
        .order_by(col(Scan.created_at).asc())
    ).all())


def overall_stats(session: Session) -> dict:
    projects = session.exec(select(Project)).all()
    scans = session.exec(select(Scan)).all()
    open_critical = 0
    latest_by_project: dict[int, Scan] = {}
    for s in scans:
        cur = latest_by_project.get(s.project_id)
        if cur is None or s.created_at > cur.created_at:
            latest_by_project[s.project_id] = s
    for s in latest_by_project.values():
        open_critical += s.severity_counts.get("Critical", 0)
    worst = max((s.risk_score for s in latest_by_project.values()), default=0.0)
    return {
        "projects": len(projects),
        "scans": len(scans),
        "open_critical": open_critical,
        "worst_risk": round(worst, 1),
    }
