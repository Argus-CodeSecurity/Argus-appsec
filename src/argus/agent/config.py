"""Agent configuration loader."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from argus.core.models import Severity


@dataclass
class AgentTarget:
    path: str
    scanners: list[str] = field(default_factory=list)
    config: Path | None = None


@dataclass
class AgentConfig:
    interval: int = 600
    state_dir: Path = field(default_factory=lambda: Path(".argus/agent"))
    push: bool = False
    cloud_url: str | None = None
    cloud_token: str | None = None
    fail_on_drift: Severity | None = None
    host_label: str | None = None
    host_posture: bool = True
    integrity_paths: list[str] = field(default_factory=list)
    targets: list[AgentTarget] = field(default_factory=list)


def _env_expand(value: str | None) -> str | None:
    if value is None:
        return None
    if value.startswith("${") and value.endswith("}"):
        key = value[2:-1]
        return os.environ.get(key)
    return value


def load_agent_config(path: Path) -> AgentConfig:
    """Load agent config from YAML."""
    if not path.is_file():
        raise FileNotFoundError(f"Agent config not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("Agent config must be a YAML mapping.")

    targets_raw = data.get("targets") or []
    if not isinstance(targets_raw, list) or not targets_raw:
        raise ValueError("Agent config requires at least one target under `targets:`.")

    targets: list[AgentTarget] = []
    for entry in targets_raw:
        if not isinstance(entry, dict) or not entry.get("path"):
            raise ValueError("Each target needs a `path` key.")
        scanners = entry.get("scanners") or []
        if isinstance(scanners, str):
            scanners = [s.strip() for s in scanners.split(",") if s.strip()]
        cfg_path = entry.get("config")
        targets.append(AgentTarget(
            path=str(entry["path"]),
            scanners=list(scanners),
            config=Path(cfg_path) if cfg_path else None,
        ))

    drift = data.get("fail_on_drift")
    integrity = data.get("integrity_paths") or []
    if isinstance(integrity, str):
        integrity = [integrity]
    return AgentConfig(
        interval=int(data.get("interval", 600)),
        state_dir=Path(data.get("state_dir", ".argus/agent")),
        push=bool(data.get("push", False)),
        cloud_url=_env_expand(data.get("cloud_url")) or os.environ.get("ARGUS_CLOUD_URL"),
        cloud_token=_env_expand(data.get("cloud_token")) or os.environ.get("ARGUS_CLOUD_TOKEN"),
        fail_on_drift=Severity.parse(str(drift)) if drift else None,
        host_label=data.get("host_label") or socket.gethostname(),
        host_posture=bool(data.get("host_posture", True)),
        integrity_paths=[str(p) for p in integrity if p],
        targets=targets,
    )


def default_agent_yaml() -> str:
    return """# Argus server agent configuration
# Run: argus agent --config .argus/agent.yml
# Cron: argus agent --config .argus/agent.yml --once

interval: 600
state_dir: .argus/agent
push: false
# cloud_url: ${ARGUS_CLOUD_URL}
# cloud_token: ${ARGUS_CLOUD_TOKEN}
fail_on_drift: high
host_label: my-server
host_posture: true
integrity_paths:
  - /etc/ssh/sshd_config

targets:
  - path: /var/www/my-app
    scanners: secrets, patterns, sca, iac
  - path: /etc/nginx
    scanners: patterns
"""


def write_default_agent_config(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        return path
    path.write_text(default_agent_yaml(), encoding="utf-8")
    return path
