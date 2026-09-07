"""Configuration loading and defaults.

Config resolution order (later wins):

1. Built-in defaults.
2. ``.argus.yml`` / ``.argus.yaml`` found in the project root.
3. A file passed explicitly with ``--config``.
4. CLI flags.

Kept deliberately small, every field maps to something a user actually tunes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from argus.core.models import Severity

CONFIG_FILENAMES = (".argus.yml", ".argus.yaml")


@dataclass
class AIConfig:
    provider: str = "heuristic"       # heuristic | anthropic | openai | ollama
    model: str | None = None          # provider-specific; None uses the provider default
    enabled: bool = True              # if False, findings are not AI-enriched
    temperature: float = 0.0
    max_tokens: int = 1500


@dataclass
class Config:
    # Which scanners to run. Empty means "all that apply".
    scanners: list[str] = field(default_factory=list)
    # Scanners to explicitly skip.
    exclude_scanners: list[str] = field(default_factory=list)
    # Glob patterns to ignore in addition to the built-in ignore list.
    exclude_paths: list[str] = field(default_factory=list)
    # Minimum severity to report.
    min_severity: Severity = Severity.INFO
    # Enable Attack Simulation Mode (AI-generated, sandboxed demonstrations).
    attack_simulation: bool = False
    # Attempt to generate patches for findings.
    generate_patches: bool = False
    # Fail the process (non-zero exit) at/above this severity, for CI gating.
    fail_on: Severity | None = None
    # Reuse cached findings for unchanged files (file-local scanners only).
    cache: bool = True
    # Run scanners concurrently. Output stays deterministic either way.
    parallel: bool = True
    # Whether the scanned project's own contents are trusted. False for a cloned
    # remote repo scanned without --trust-remote-config: in that case in-repo
    # extension points (the .argus/rules convention dir) must NOT be honored,
    # because a hostile repository could otherwise inject scanner rules. Set by
    # the CLI from the same trust decision that gates the in-repo .argus.yml.
    trust_project_config: bool = True

    ai: AIConfig = field(default_factory=AIConfig)

    # Per-scanner options, keyed by scanner name.
    scanner_options: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Committed allowlist: accepted findings kept outside the source. Each entry is
    # {rule?, path?, reason (required), until? (YYYY-MM-DD)}; see docs/triage.md.
    allow: list[dict[str, Any]] = field(default_factory=list)

    # Security policies evaluated by ``argus policy check``.
    policies: list[dict[str, Any]] = field(default_factory=list)

    # Autonomy ladder (Rung 3): which deterministic fix rules may be applied
    # automatically by `argus fix --auto`. Fixes still land on a branch/PR (never
    # a direct push), so they stay trivially revertible. `graduate`/`demote` are
    # lists of full rule ids that add to / remove from the conservative built-in
    # auto set, so a team promotes rules to automatic one at a time.
    autofix: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path | None = None,
             project_root: str | Path | None = None) -> Config:
        """Load config from an explicit path or by discovery in the project root."""
        data: dict[str, Any] = {}
        chosen: Path | None = None
        if path:
            chosen = Path(path)
            # An explicit --config path that doesn't exist must fail loudly. Falling
            # back to defaults here silently drops fail_on/allow gating, which in CI
            # means a typo'd path turns the security gate off without any signal.
            if not chosen.exists():
                raise FileNotFoundError(f"config file not found: {chosen}")
        elif project_root:
            for name in CONFIG_FILENAMES:
                candidate = Path(project_root) / name
                if candidate.exists():
                    chosen = candidate
                    break
        if chosen and chosen.exists():
            with open(chosen, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        cfg = cls()
        cfg.scanners = list(data.get("scanners", cfg.scanners))
        cfg.exclude_scanners = list(data.get("exclude_scanners", cfg.exclude_scanners))
        cfg.exclude_paths = list(data.get("exclude_paths", cfg.exclude_paths))
        cfg.attack_simulation = bool(data.get("attack_simulation", cfg.attack_simulation))
        cfg.generate_patches = bool(data.get("generate_patches", cfg.generate_patches))
        cfg.scanner_options = dict(data.get("scanner_options", {}))
        cfg.allow = [e for e in data.get("allow", []) if isinstance(e, dict)]
        cfg.policies = [p for p in data.get("policies", []) if isinstance(p, dict)]
        cfg.autofix = data["autofix"] if isinstance(data.get("autofix"), dict) else {}
        cfg.cache = bool(data.get("cache", cfg.cache))
        cfg.parallel = bool(data.get("parallel", cfg.parallel))
        if "min_severity" in data:
            cfg.min_severity = Severity.parse(data["min_severity"])
        if data.get("fail_on"):
            cfg.fail_on = Severity.parse(data["fail_on"])
        ai = data.get("ai", {})
        if ai:
            cfg.ai = AIConfig(
                provider=ai.get("provider", cfg.ai.provider),
                model=ai.get("model", cfg.ai.model),
                enabled=bool(ai.get("enabled", cfg.ai.enabled)),
                temperature=float(ai.get("temperature", cfg.ai.temperature)),
                max_tokens=int(ai.get("max_tokens", cfg.ai.max_tokens)),
            )
        return cfg

    def options_for(self, scanner_name: str) -> dict[str, Any]:
        return self.scanner_options.get(scanner_name, {})
