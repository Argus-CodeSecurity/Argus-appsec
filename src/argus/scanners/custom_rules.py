"""Load user/community SAST rules from YAML, no Python required.

The `patterns` scanner is rule-driven, and this module lets anyone extend it
with a YAML file instead of code, lowering the contribution bar to "regex + a
few fields" (the model that grew Semgrep's community rule registry). Rules are
loaded from:

* any path(s) in ``scanner_options.patterns.rules`` (a string or list; globs
  allowed), and
* the convention directory ``.argus/rules/*.yml`` in the project root.

A YAML rules file:

    rules:
      - id: hardcoded-internal-ip
        title: Hardcoded internal IP address
        pattern: '\\b10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b'
        severity: low            # info | low | medium | high | critical
        languages: [Python, Go]  # optional; omit for all languages
        cwe: [CWE-1188]          # optional
        owasp: ["A05:2021-Security Misconfiguration"]   # optional
        confidence: medium       # optional: low | medium | high
        why: "An internal IP is baked into source."
        attack: "..."            # optional
        impact: "..."            # optional
        fix: "Move host addresses to configuration."
        suppress: 'ALLOW_INTERNAL_IP'   # optional: a regex that clears a match

Invalid rules are skipped with a warning rather than aborting the scan, a
malformed community rule must never break a user's pipeline.
"""

from __future__ import annotations

import importlib
import logging
import re
from pathlib import Path
from typing import Any

import yaml

from argus.core.models import Confidence, Severity
from argus.scanners.patterns import Rule

log = logging.getLogger("argus.scanners.custom_rules")

_CONFIDENCE = {"low": Confidence.LOW, "medium": Confidence.MEDIUM,
               "high": Confidence.HIGH}

# Defense-in-depth ReDoS lint. Custom rules can come from an untrusted
# repository, and Python's ``re`` cannot be interrupted mid-match, so a
# pathological pattern would otherwise hang the whole scan. The pattern is parsed
# with the stdlib regex parser and rejected when a repeat that can run many times
# (unbounded, or more than _LARGE_REPEAT) contains either
#
# * another variable-length repeat: ``(a+)+``, ``([a-z]*)+``, ``(.*a){25}``, or
# * an alternation whose branches can start with the same character or match
#   the empty string: ``(a|aa)+``, ``(\w|\d)+``.
#
# Those are the shapes where one input splits across the iterations in
# exponentially many ways. It is a heuristic, not a proof; the other controls are
# the trust gate on where rules are loaded from and the per-line length cap the
# patterns scanner applies to every rule.
_sre_parse: Any
try:  # Python 3.11+ moved the parser; the old module still exists but warns.
    _sre_parse = importlib.import_module("re._parser")
except ImportError:  # pragma: no cover - Python 3.10
    _sre_parse = importlib.import_module("sre_parse")

_LARGE_REPEAT = 10
_REPEATS = {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}
# Character "universe" for first-character sets: Latin-1 plus one stand-in for
# everything above it, which is enough to see whether two branches overlap.
_OTHER = 256
_UNIVERSE = frozenset(range(257))


def _category_chars(category: str) -> frozenset[int]:
    probe = {"CATEGORY_DIGIT": r"\d", "CATEGORY_NOT_DIGIT": r"\D",
             "CATEGORY_SPACE": r"\s", "CATEGORY_NOT_SPACE": r"\S",
             "CATEGORY_WORD": r"\w", "CATEGORY_NOT_WORD": r"\W"}.get(category)
    if probe is None:
        return _UNIVERSE
    rx = re.compile(probe)
    chars = {i for i in range(256) if rx.match(chr(i))}
    if category != "CATEGORY_DIGIT":
        chars.add(_OTHER)  # every other class also matches some non-Latin-1 char
    return frozenset(chars)


def _class_chars(items) -> frozenset[int]:
    chars: set[int] = set()
    negate = False
    for op, av in items:
        name = str(op)
        if name == "NEGATE":
            negate = True
        elif name == "LITERAL":
            chars.add(av if av < 256 else _OTHER)
        elif name == "RANGE":
            lo, hi = av
            chars.update(range(lo, min(hi, 255) + 1))
            if hi > 255:
                chars.add(_OTHER)
        elif name == "CATEGORY":
            chars |= _category_chars(str(av))
        else:
            return _UNIVERSE  # unknown member: assume it can match anything
    return frozenset(_UNIVERSE - chars | {_OTHER}) if negate else frozenset(chars)


def _first(seq) -> tuple[frozenset[int], bool]:
    """(characters a match of ``seq`` can start with, whether it can be empty)."""
    out: set[int] = set()
    for op, av in seq:
        chars, nullable = _first_item(str(op), av)
        out |= chars
        if not nullable:
            return frozenset(out), False
    return frozenset(out), True


def _first_item(name: str, av) -> tuple[frozenset[int], bool]:
    if name == "LITERAL":
        return frozenset({av if av < 256 else _OTHER}), False
    if name == "NOT_LITERAL":
        return _UNIVERSE - {av}, False
    if name == "ANY":
        return _UNIVERSE, False
    if name == "IN":
        return _class_chars(av), False
    if name == "SUBPATTERN":
        return _first(av[-1])
    if name == "ATOMIC_GROUP":
        return _first(av)
    if name == "BRANCH":
        chars: set[int] = set()
        nullable = False
        for alt in av[1]:
            c, n = _first(alt)
            chars |= c
            nullable = nullable or n
        return frozenset(chars), nullable
    if name in _REPEATS:
        lo, _hi, body = av
        c, n = _first(body)
        return c, n or lo == 0
    if name in ("AT", "ASSERT", "ASSERT_NOT"):
        return frozenset(), True  # zero-width
    return _UNIVERSE, True  # back-references and anything unknown


def _children(name: str, av) -> list:
    """Sub-sequences of a parsed item, for walking the whole pattern."""
    if name == "SUBPATTERN":
        return [av[-1]]
    if name == "ATOMIC_GROUP":
        return [av]
    if name == "BRANCH":
        return list(av[1])
    if name in _REPEATS:
        return [av[2]]
    if name in ("ASSERT", "ASSERT_NOT"):
        return [av[1]]
    if name == "GROUPREF_EXISTS":
        return [s for s in av[1:] if s is not None]
    return []


def _items(seq):
    """Every (name, av) item in ``seq`` and below it, iteratively."""
    stack = [seq]
    while stack:
        for op, av in stack.pop():
            name = str(op)
            yield name, av
            stack.extend(_children(name, av))


def _ambiguous_branch(alts) -> bool:
    seen: set[int] = set()
    for alt in alts:
        chars, nullable = _first(alt)
        if nullable or seen & chars:
            return True
        seen |= chars
    return False


def _is_catastrophic(pattern: str) -> bool:
    try:
        parsed = _sre_parse.parse(pattern)
    except Exception:  # invalid pattern: re.compile reports it later
        return False
    for name, av in _items(parsed):
        if name not in _REPEATS:
            continue
        _lo, hi, body = av
        if hi != _sre_parse.MAXREPEAT and hi <= _LARGE_REPEAT:
            continue
        for inner_name, inner_av in _items(body):
            if inner_name in _REPEATS and inner_av[0] != inner_av[1]:
                return True  # nested variable-length repeat
            if inner_name == "BRANCH" and _ambiguous_branch(inner_av[1]):
                return True  # overlapping alternatives under a repeat
    return False


def _coerce_rule(raw: dict, source: str) -> Rule | None:
    try:
        rid = str(raw["id"]).strip()
        raw_pattern = str(raw["pattern"])
        raw_suppress = str(raw["suppress"]) if raw.get("suppress") else None
        if _is_catastrophic(raw_pattern) or (
                raw_suppress is not None and _is_catastrophic(raw_suppress)):
            log.warning("skipping custom rule in %s: pattern rejected as a possible "
                        "ReDoS (nested or overlapping repetition)", source)
            return None
        if not rid:
            log.warning("skipping custom rule in %s: empty id", source)
            return None
        # Everything that can fail on a malformed rule (bad regex, unknown
        # severity, a scalar where a list belongs) stays inside this try, so one
        # bad rule is skipped instead of aborting the load.
        return Rule(
            id=rid,
            title=str(raw.get("title", rid)),
            pattern=re.compile(raw_pattern),
            severity=Severity.parse(str(raw.get("severity", "medium"))),
            cwe=_str_list(raw.get("cwe")),
            owasp=_str_list(raw.get("owasp")),
            why=str(raw.get("why", "")),
            attack=str(raw.get("attack", "")),
            impact=str(raw.get("impact", "")),
            fix=str(raw.get("fix", "")),
            languages=set(_str_list(raw.get("languages"))),
            confidence=_CONFIDENCE.get(str(raw.get("confidence", "medium")).lower(),
                                       Confidence.MEDIUM),
            references=_str_list(raw.get("references")),
            suppress=re.compile(raw_suppress) if raw_suppress is not None else None,
        )
    except (KeyError, ValueError, re.error, TypeError) as exc:
        log.warning("skipping custom rule in %s: %s", source, exc)
        return None


def _str_list(value) -> list[str]:
    """A YAML list of strings; a bare string counts as a one-item list."""
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    raise TypeError(f"expected a list, got {type(value).__name__}")


def _load_file(path: Path) -> list[Rule]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        log.warning("could not read custom rules from %s: %s", path, exc)
        return []
    raw_rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(raw_rules, list):
        log.warning("%s: expected a top-level 'rules:' list", path)
        return []
    out = []
    for raw in raw_rules:
        if isinstance(raw, dict):
            rule = _coerce_rule(raw, str(path))
            if rule is not None:
                out.append(rule)
    return out


def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root)
    except OSError:
        return True  # cannot tell: treat as inside, i.e. untrusted


def _resolve_paths(project_root: Path, option,
                   include_convention_dir: bool = True) -> list[Path]:
    """Collect rule-file paths from the config option and the convention dir.

    ``include_convention_dir`` is False for untrusted targets (a cloned remote
    repo without ``--trust-remote-config``): the ``.argus/rules/*.yml``
    convention directory ships *inside* the scanned repo, so honoring it there
    would let a hostile repository inject regexes into the scanner. For the same
    reason, relative ``option`` paths that resolve inside an untrusted target
    are ignored. Absolute ``option`` paths and relative ones that resolve
    outside the target come from the operator's config and are honored.
    """
    paths: list[Path] = []
    specs: list[str] = []
    if isinstance(option, str):
        specs = [option]
    elif isinstance(option, (list, tuple)):
        specs = [str(s) for s in option]
    root = project_root.resolve()
    for spec in specs:
        p = Path(spec)
        if p.is_absolute():
            paths.append(p)
            continue
        for match in sorted(project_root.glob(spec)):
            # A relative path is resolved against the scanned tree. When that
            # tree is untrusted, a rules file found inside it was written by the
            # repository, not by whoever configured the scan: ignore it.
            if not include_convention_dir and _inside(match, root):
                log.warning("ignoring custom rules file %s: it is inside the "
                            "untrusted scan target", match)
                continue
            paths.append(match)
    # Convention directory (deterministic order), only for trusted targets.
    conv = project_root / ".argus" / "rules"
    if include_convention_dir and conv.is_dir():
        paths.extend(sorted(conv.glob("*.yml")))
        paths.extend(sorted(conv.glob("*.yaml")))
    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[Path] = []
    for p in paths:
        key = str(p.resolve())
        if key not in seen and p.is_file():
            seen.add(key)
            unique.append(p)
    return unique


def load_custom_rules(project_root: Path, option=None,
                      include_convention_dir: bool = True) -> list[Rule]:
    """Load and validate all custom rules for a project. Never raises."""
    rules: list[Rule] = []
    for path in _resolve_paths(project_root, option, include_convention_dir):
        rules.extend(_load_file(path))
    if rules:
        log.info("loaded %d custom rule(s)", len(rules))
    return rules


def config_signature(project_root: Path, option=None,
                     include_convention_dir: bool = True) -> str:
    """A stable signature of the active custom-rule files (path + mtime + size).

    Folded into the scanner cache key so editing a rules file invalidates cached
    findings for that project.
    """
    parts: list[str] = []
    for path in _resolve_paths(project_root, option, include_convention_dir):
        try:
            st = path.stat()
            parts.append(f"{path}:{int(st.st_mtime)}:{st.st_size}")
        except OSError:
            continue
    return "|".join(parts)
