"""Phase 3 platform tests: CI/CD, container, and cloud scanners."""

from __future__ import annotations

from pathlib import Path

from argus.core.config import Config
from argus.core.plugin import ScannerContext
from argus.core.project import Project
from argus.scanners.cicd import CicdScanner
from argus.scanners.cloud import CloudScanner
from argus.scanners.container import ContainerScanner


def _ctx(tmp_path: Path, *files: tuple[str, str]) -> ScannerContext:
    for name, content in files:
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return ScannerContext(project=Project.from_path(tmp_path), config=Config())


def test_cicd_pull_request_target(tmp_path: Path) -> None:
    wf = """
name: ci
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    rules = {f.rule_id for f in CicdScanner().scan(_ctx(tmp_path, (".github/workflows/ci.yml", wf)))}
    assert "cicd.pull-request-target" in rules


def test_cicd_unpinned_action(tmp_path: Path) -> None:
    wf = """
jobs:
  x:
    steps:
      - uses: actions/checkout@main
"""
    rules = {f.rule_id for f in CicdScanner().scan(_ctx(tmp_path, (".github/workflows/ci.yml", wf)))}
    assert "cicd.unpinned-action" in rules


def test_container_compose_privileged(tmp_path: Path) -> None:
    compose = """
services:
  app:
    image: nginx:latest
    privileged: true
"""
    rules = {f.rule_id for f in ContainerScanner().scan(_ctx(tmp_path, ("docker-compose.yml", compose)))}
    assert "container.privileged" in rules
    assert "container.image-latest" in rules


def test_cloud_open_sg(tmp_path: Path) -> None:
    tf = """
resource "aws_security_group_rule" "ingress" {
  cidr_blocks = ["0.0.0.0/0"]
}
"""
    rules = {f.rule_id for f in CloudScanner().scan(_ctx(tmp_path, ("main.tf", tf)))}
    assert "cloud.open-security-group" in rules


def test_cloud_gcp_public_bucket(tmp_path: Path) -> None:
    tf = """
resource "google_storage_bucket_iam_member" "public" {
  member = "allUsers"
}
"""
    rules = {f.rule_id for f in CloudScanner().scan(_ctx(tmp_path, ("gcp.tf", tf)))}
    assert "cloud.gcp-public-bucket" in rules
