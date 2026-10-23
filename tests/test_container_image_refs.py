"""Base image references read from Dockerfiles are parsed and passed safely."""

from __future__ import annotations

from pathlib import Path

from nephilex.core.config import Config
from nephilex.core.plugin import ScannerContext
from nephilex.core.project import Project
from nephilex.scanners import container_image
from nephilex.scanners.container_image import ContainerImageScanner, _from_refs


def test_from_skips_flags_stages_and_args():
    text = (
        "ARG BASE=python:3.12\n"
        "FROM --platform=$BUILDPLATFORM golang:1.22 AS builder\n"
        "FROM $BASE\n"
        "FROM builder AS test\n"
        "FROM scratch\n"
        "from --platform=linux/amd64 alpine:3.20\n"
    )
    assert _from_refs(text) == ["golang:1.22", "alpine:3.20"]


def _run(tmp_path: Path, files: dict[str, str], monkeypatch, options=None) -> list[list[str]]:
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    calls: list[list[str]] = []

    def fake_check_output(argv, **kwargs):
        calls.append(list(argv))
        return "[]"

    monkeypatch.setattr(container_image.subprocess, "check_output", fake_check_output)
    cfg = Config(scanner_options={"container-image": options or {}})
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=cfg)
    list(ContainerImageScanner().scan(ctx))
    return calls


def test_every_dockerfile_is_read_and_ref_follows_double_dash(tmp_path, monkeypatch):
    calls = _run(
        tmp_path,
        {
            "Dockerfile": "FROM --platform=linux/amd64 python:3.12-slim\n",
            "services/api/Dockerfile": "FROM node:22-alpine\n",
            "worker.Dockerfile": "FROM python:3.12-slim\n",
        },
        monkeypatch,
    )
    refs = [c[-1] for c in calls]
    assert sorted(refs) == ["node:22-alpine", "python:3.12-slim"]
    assert all(c[:3] == ["docker", "inspect", "--"] for c in calls)


def test_option_like_refs_never_reach_docker(tmp_path, monkeypatch):
    calls = _run(
        tmp_path,
        {"Dockerfile": "FROM -v\n"},
        monkeypatch,
        options={"images": ["--help", "-f{{json .}}", "ok/image:1"]},
    )
    assert [c[-1] for c in calls] == ["ok/image:1"]
