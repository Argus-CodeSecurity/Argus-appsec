"""Application security graph for correlation (spec §3, §57)."""

from __future__ import annotations

from argus.core.models import Finding, ScanResult


def build_security_graph(result: ScanResult) -> dict:
    """Build a lightweight security graph from scan summary and findings."""
    summary = result.project_summary or {}
    nodes: list[dict] = [{"id": "internet", "type": "trust_boundary", "label": "Internet"}]
    edges: list[dict] = []

    raw_langs = summary.get("languages", [])
    if isinstance(raw_langs, dict):
        langs = list(raw_langs.keys())[:8]
    elif isinstance(raw_langs, list):
        langs = raw_langs[:8]
    else:
        langs = []

    for lang in langs:
        nodes.append({"id": f"lang:{lang}", "type": "language", "label": str(lang)})

    raw_services = summary.get("services") or summary.get("frameworks") or []
    if isinstance(raw_services, dict):
        services = list(raw_services.keys())[:8]
    elif isinstance(raw_services, list):
        services = raw_services[:8]
    else:
        services = []

    for svc in services:
        sid = f"service:{svc}"
        nodes.append({"id": sid, "type": "service", "label": str(svc)})
        edges.append({"from": "internet", "to": sid, "kind": "exposure"})

    if summary.get("has_database") or summary.get("databases"):
        nodes.append({"id": "database", "type": "datastore", "label": "Database"})
        edges.append({"from": "service:app", "to": "database", "kind": "data_flow"})

    for f in result.findings[:200]:
        fid = f"finding:{f.fingerprint()}"
        nodes.append({
            "id": fid,
            "type": "finding",
            "label": f.rule_id,
            "severity": f.severity.label,
        })
        loc = f.location.path
        if loc:
            edges.append({"from": loc, "to": fid, "kind": "affects"})

    chains = [f for f in result.findings if "attack-chain" in f.tags or f.scanner == "chains"]
    for c in chains[:20]:
        edges.append({"from": "internet", "to": f"finding:{c.fingerprint()}", "kind": "attack_path"})

    return {
        "nodes": nodes,
        "edges": edges,
        "trust_boundaries": ["internet", "application", "datastore", "cloud"],
        "supply_chain": (
            list(summary.get("dependencies", {}).keys())[:50]
            if isinstance(summary.get("dependencies"), dict)
            else (summary.get("dependencies") or [])[:50]
        ),
    }
