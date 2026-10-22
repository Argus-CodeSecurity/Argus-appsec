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


class ConfigError(ValueError):
    """The configuration is invalid.

    Commands report this and exit 2 instead of scanning with a configuration
    that does not say what the user meant (a CI gate must fail closed).
    """


class ConfigFileNotFoundError(ConfigError, FileNotFoundError):
    """An explicitly requested config file does not exist."""


def _str_list(data: dict[str, Any], key: str) -> list[str]:
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(
            f"{key}: expected a list of strings (e.g. {key}: [\"value\"]), "
            f"got {value!r}"
        )
    return [v.strip() for v in value if v.strip()]


def _dict_list(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise ConfigError(f"{key}: expected a list of mappings, got {value!r}")
    return list(value)


def _mapping(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{key}: expected a mapping, got {type(value).__name__}")
    return dict(value)


def _bool(data: dict[str, Any], key: str, default: bool, *, prefix: str = "") -> bool:
    value = data.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(f"{prefix}{key}: expected true or false, got {value!r}")
    return value


def _severity(value: Any, key: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise ConfigError(f"{key}: {exc}") from exc


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
    # Fail when any scanner crashes (recommended for ci/production profiles).
    fail_on_error: bool = False
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
                raise ConfigFileNotFoundError(f"config file not found: {chosen}")
        elif project_root:
            for name in CONFIG_FILENAMES:
                candidate = Path(project_root) / name
                if candidate.exists():
                    chosen = candidate
                    break
        if chosen and chosen.exists():
            with open(chosen, encoding="utf-8") as fh:
                return cls.from_yaml(fh.read(), source=str(chosen))
        return cls.from_dict(data)

    @classmethod
    def from_yaml(cls, text: str, *, source: str = "config") -> Config:
        """Parse YAML config text; any problem is a :class:`ConfigError`."""
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ConfigError(f"{source}: invalid YAML: {exc}") from exc
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError(
                f"{source}: expected a mapping of settings at the top level, "
                f"got {type(data).__name__}"
            )
        try:
            return cls.from_dict(data)
        except ConfigError as exc:
            raise ConfigError(f"{source}: {exc}") from exc

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Build a Config from parsed settings, validating every field's type.

        Values are checked strictly rather than coerced: ``list("dist/*")`` is a
        list of characters (and ``*`` then excludes every file), and
        ``bool("false")`` is True. Either would silently change what the scan
        covers, so a wrong type is a :class:`ConfigError` instead.
        """
        cfg = cls()
        cfg.scanners = _str_list(data, "scanners")
        cfg.exclude_scanners = _str_list(data, "exclude_scanners")
        cfg.exclude_paths = _str_list(data, "exclude_paths")
        cfg.attack_simulation = _bool(data, "attack_simulation", cfg.attack_simulation)
        cfg.generate_patches = _bool(data, "generate_patches", cfg.generate_patches)
        cfg.cache = _bool(data, "cache", cfg.cache)
        cfg.parallel = _bool(data, "parallel", cfg.parallel)
        if data.get("fail_on_error") is not None:
            cfg.fail_on_error = _bool(data, "fail_on_error", cfg.fail_on_error)

        options = _mapping(data, "scanner_options")
        for name, value in options.items():
            if not isinstance(value, dict):
                raise ConfigError(
                    f"scanner_options.{name}: expected a mapping, "
                    f"got {type(value).__name__}"
                )
        cfg.scanner_options = {str(k): dict(v) for k, v in options.items()}
        cfg.allow = _dict_list(data, "allow")
        cfg.policies = _dict_list(data, "policies")
        cfg.autofix = _mapping(data, "autofix")

        if data.get("min_severity") not in (None, ""):
            cfg.min_severity = _severity(data["min_severity"], "min_severity")
        if data.get("fail_on") not in (None, ""):
            cfg.fail_on = _severity(data["fail_on"], "fail_on")

        ai = _mapping(data, "ai")
        if ai:
            try:
                cfg.ai = AIConfig(
                    provider=str(ai.get("provider", cfg.ai.provider)),
                    model=ai.get("model", cfg.ai.model),
                    enabled=_bool(ai, "enabled", cfg.ai.enabled, prefix="ai."),
                    temperature=float(ai.get("temperature", cfg.ai.temperature)),
                    max_tokens=int(ai.get("max_tokens", cfg.ai.max_tokens)),
                )
            except (TypeError, ValueError) as exc:
                if isinstance(exc, ConfigError):
                    raise
                raise ConfigError(f"ai: {exc}") from exc
        return cfg

    def options_for(self, scanner_name: str) -> dict[str, Any]:
        return self.scanner_options.get(scanner_name, {})
