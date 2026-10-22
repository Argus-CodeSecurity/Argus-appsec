"""Schema, parsing and validation for ``.argus/context.yml``.

Validation is strict, like the rest of the configuration: an unknown key, a
wrong type or a malformed name is a :class:`~argus.core.config.ConfigError`
(exit 2), never a silently ignored setting. A typo in a sanitizer entry that
was quietly dropped would leave the team believing a flow is covered when it
is not, and a typo that was quietly accepted could hide real findings.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from argus.core.config import ConfigError

CONTEXT_FILENAME = "context.yml"
#: Project-relative location of the context file.
CONTEXT_PATH = f".argus/{CONTEXT_FILENAME}"
_CONTEXT_FILENAMES = (CONTEXT_FILENAME, "context.yaml")

#: Languages whose AST taint tiers consume sanitizers and trusted sources.
#: ``typescript`` is accepted as an alias of ``javascript`` (one analyzer
#: handles both).
LANGUAGES = ("python", "javascript")
_LANGUAGE_ALIASES = {"python": "python", "javascript": "javascript", "typescript": "javascript"}

#: Exposure levels and the direction they move likelihood.
EXPOSURE_LEVELS: dict[str, int] = {
    "public_api": 1,
    "public_web": 1,
    "internal_service": -1,
    "offline": -1,
}

#: Data classes that raise impact.
DATA_CLASSES = ("pii", "secrets", "credentials", "financial", "health")

_TOP_LEVEL_KEYS = (
    "version",
    "sanitizers",
    "trusted_sources",
    "internal_paths",
    "exposure",
    "data_classification",
)
_SUPPORTED_VERSIONS = (1,)

# A dotted name as it appears at a call site: identifiers joined by dots.
# ``$`` is a legal identifier character in JavaScript.
_NAME = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$")
_CWE = re.compile(r"^CWE-[0-9]{1,5}$")
_MAX_NAME = 200
_MAX_GLOB = 500
_MAX_NOTE = 500
# Bounds the work the taint tiers do per call site.
_MAX_ENTRIES = 1000
_MAX_BYTES = 1_000_000


@dataclass(frozen=True)
class Sanitizer:
    """A function whose return value is safe for ``cwe`` (all CWEs when empty)."""

    name: str
    language: str
    cwe: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class TrustedSource:
    """A value or function result that is not attacker-controlled."""

    name: str
    language: str
    note: str = ""


@dataclass(frozen=True)
class InternalPath:
    path: str
    note: str = ""


@dataclass(frozen=True)
class ExposureNote:
    path: str
    level: str
    note: str = ""


@dataclass(frozen=True)
class DataClassification:
    """A path glob or a model name whose data raises the impact of a finding."""

    classes: tuple[str, ...]
    path: str | None = None
    model: str | None = None
    note: str = ""


def _segments(name: str) -> tuple[str, ...]:
    return tuple(name.split("."))


def _call_segments(fn_text: str) -> tuple[str, ...]:
    """The dotted parts of a call target as written, e.g. ``a . b?.c`` -> (a, b, c)."""
    compact = re.sub(r"\s+", "", fn_text).replace("?.", ".")
    return tuple(compact.split("."))


def _is_suffix(call: tuple[str, ...], configured: tuple[str, ...]) -> bool:
    return 0 < len(call) <= len(configured) and configured[-len(call) :] == call


class LanguageContext:
    """The sanitizers and trusted sources for one language, ready for matching.

    A call matches a configured name when the call's dotted target is a
    trailing part of it: ``myapp.security.escape_html`` matches
    ``escape_html(x)``, ``security.escape_html(x)`` and the full name, but not
    ``other.escape_html(x)``. Imports are not resolved, so a local function
    with the same short name also matches; the file is trusted configuration,
    so prefer fully qualified names when short names are ambiguous.
    """

    def __init__(
        self,
        language: str,
        sanitizers: tuple[Sanitizer, ...],
        trusted_sources: tuple[TrustedSource, ...],
    ) -> None:
        self.language = language
        self.sanitizers = sanitizers
        self.trusted_sources = trusted_sources
        self._sanitizers = [(_segments(s.name), frozenset(s.cwe)) for s in sanitizers]
        self._trusted = [_segments(t.name) for t in trusted_sources]
        #: CWEs named by CWE-specific sanitizers; the analyzers track partial
        #: sanitization for exactly these.
        self.cwes: frozenset[str] = frozenset(c for s in sanitizers for c in s.cwe)
        names = sorted({t.name for t in trusted_sources}, key=len, reverse=True)
        self._mask = (
            re.compile(
                r"(?<![A-Za-z0-9_$.])(?:"
                + "|".join(re.escape(n) for n in names)
                + r")(?![A-Za-z0-9_$])"
            )
            if names
            else None
        )
        self._words = {seg[-1] for seg, _ in self._sanitizers} | {seg[-1] for seg in self._trusted}

    def relevant(self, text: str) -> bool:
        """Whether any configured name could match in ``text`` (cheap pre-check)."""
        return any(word in text for word in self._words)

    def is_trusted_call(self, fn_text: str) -> bool:
        call = _call_segments(fn_text)
        return any(_is_suffix(call, seg) for seg in self._trusted)

    def clears(self, fn_text: str, cwes: frozenset[str] | None) -> bool:
        """Whether a call to ``fn_text`` yields a clean value for a sink of ``cwes``.

        ``cwes`` is None when the question is "clean for every sink", which a
        CWE-specific sanitizer never answers yes to.
        """
        call = _call_segments(fn_text)
        if any(_is_suffix(call, seg) for seg in self._trusted):
            return True
        for seg, only in self._sanitizers:
            if not _is_suffix(call, seg):
                continue
            if not only or (cwes is not None and only & cwes):
                return True
        return False

    def mask_trusted(self, text: str) -> str:
        """``text`` with trusted-source names blanked, before source matching."""
        if self._mask is None:
            return text
        return self._mask.sub(lambda m: " " * len(m.group(0)), text)

    def matched_names(self, text: str) -> list[str]:
        """Configured names whose short form appears in ``text`` (for reports)."""
        out = [s.name for s in self.sanitizers if s.name.rsplit(".", 1)[-1] in text]
        out += [t.name for t in self.trusted_sources if t.name.rsplit(".", 1)[-1] in text]
        return sorted(set(out))


@dataclass
class ProjectContext:
    """Parsed ``.argus/context.yml``. An empty instance changes nothing."""

    #: Where it was read from (``.argus/context.yml`` or ``REF:.argus/context.yml``).
    source: str = ""
    sanitizers: tuple[Sanitizer, ...] = ()
    trusted_sources: tuple[TrustedSource, ...] = ()
    internal_paths: tuple[InternalPath, ...] = ()
    exposure: tuple[ExposureNote, ...] = ()
    data_classification: tuple[DataClassification, ...] = ()
    _languages: dict[str, LanguageContext | None] = field(
        default_factory=dict, repr=False, compare=False
    )

    def is_empty(self) -> bool:
        return not (
            self.sanitizers
            or self.trusted_sources
            or self.internal_paths
            or self.exposure
            or self.data_classification
        )

    def for_language(self, language: str) -> LanguageContext | None:
        """Sanitizers and trusted sources for ``language``, or None if there are none."""
        lang = _LANGUAGE_ALIASES.get(language.lower(), language.lower())
        if lang not in self._languages:
            sans = tuple(s for s in self.sanitizers if s.language == lang)
            trusted = tuple(t for t in self.trusted_sources if t.language == lang)
            self._languages[lang] = (
                LanguageContext(lang, sans, trusted) if (sans or trusted) else None
            )
        return self._languages[lang]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sanitizers": [
                {"name": s.name, "language": s.language, "cwe": list(s.cwe), "note": s.note}
                for s in self.sanitizers
            ],
            "trusted_sources": [
                {"name": t.name, "language": t.language, "note": t.note}
                for t in self.trusted_sources
            ],
            "internal_paths": [{"path": p.path, "note": p.note} for p in self.internal_paths],
            "exposure": [{"path": e.path, "level": e.level, "note": e.note} for e in self.exposure],
            "data_classification": [
                {"path": d.path, "model": d.model, "classes": list(d.classes), "note": d.note}
                for d in self.data_classification
            ],
        }

    def digest(self) -> str:
        """A short content hash; part of the scan-cache key for the taint tiers."""
        blob = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    def language_digest(self, language: str) -> str:
        """Content hash of only what the ``language`` taint tier consumes."""
        lc = self.for_language(language)
        if lc is None:
            return ""
        blob = json.dumps(
            [
                [(s.name, list(s.cwe)) for s in lc.sanitizers],
                [t.name for t in lc.trusted_sources],
            ],
            sort_keys=True,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


# --- parsing -------------------------------------------------------------------
def _note(entry: dict[str, Any], where: str) -> str:
    value = entry.get("note", "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ConfigError(f"{where}.note: expected a string, got {type(value).__name__}")
    if len(value) > _MAX_NOTE:
        raise ConfigError(f"{where}.note: longer than {_MAX_NOTE} characters")
    return value.strip()


def _check_keys(entry: dict[str, Any], allowed: tuple[str, ...], where: str) -> None:
    unknown = sorted(str(k) for k in entry if k not in allowed)
    if unknown:
        raise ConfigError(
            f"{where}: unknown key(s) {', '.join(unknown)} (allowed: {', '.join(allowed)})"
        )


def _name(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{where}: expected a dotted name string, got {type(value).__name__}")
    name = value.strip()
    if len(name) > _MAX_NAME or not _NAME.match(name):
        raise ConfigError(
            f"{where}: {value!r} is not a dotted name such as myapp.security.escape_html"
        )
    return name


def _glob(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}: expected a non-empty path glob string, got {value!r}")
    glob = value.strip().replace("\\", "/")
    if len(glob) > _MAX_GLOB or "\0" in glob:
        raise ConfigError(f"{where}: path glob is too long or contains a NUL byte")
    return glob.removeprefix("./")


def _cwes(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or not all(isinstance(v, str) for v in items):
        raise ConfigError(f"{where}: expected a CWE id or a list of them, got {value!r}")
    out: list[str] = []
    for item in items:
        cwe = item.strip().upper()
        if not _CWE.match(cwe):
            raise ConfigError(f"{where}: {item!r} is not a CWE id such as CWE-79")
        out.append(cwe)
    return tuple(dict.fromkeys(out))


def _list(data: dict[str, Any], key: str, where: str) -> list[Any]:
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError(f"{where}: expected a list, got {type(value).__name__}")
    if len(value) > _MAX_ENTRIES:
        raise ConfigError(f"{where}: more than {_MAX_ENTRIES} entries")
    return value


def _per_language(data: dict[str, Any], key: str) -> list[tuple[str, int, Any]]:
    """Entries of a ``{language: [entries]}`` mapping as (language, index, entry)."""
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, dict):
        raise ConfigError(
            f"{key}: expected a mapping of language to a list "
            f"(e.g. {key}: {{python: [...]}}), got {type(value).__name__}"
        )
    out: list[tuple[str, int, Any]] = []
    for lang_key, entries in value.items():
        lang = _LANGUAGE_ALIASES.get(str(lang_key).lower()) if isinstance(lang_key, str) else None
        if lang is None:
            raise ConfigError(
                f"{key}: unknown language {lang_key!r} "
                f"(choose from: {', '.join(sorted(_LANGUAGE_ALIASES))})"
            )
        if entries is None:
            continue
        if not isinstance(entries, list):
            raise ConfigError(f"{key}.{lang_key}: expected a list, got {type(entries).__name__}")
        out.extend((lang, i, entry) for i, entry in enumerate(entries, start=1))
    if len(out) > _MAX_ENTRIES:
        raise ConfigError(f"{key}: more than {_MAX_ENTRIES} entries")
    return out


def _parse_sanitizers(data: dict[str, Any]) -> tuple[Sanitizer, ...]:
    out: list[Sanitizer] = []
    for lang, i, entry in _per_language(data, "sanitizers"):
        where = f"sanitizers.{lang} #{i}"
        if isinstance(entry, str):
            out.append(Sanitizer(name=_name(entry, where), language=lang))
            continue
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: expected a name or a mapping, got {type(entry).__name__}")
        _check_keys(entry, ("name", "cwe", "note"), where)
        if "name" not in entry:
            raise ConfigError(f"{where}: 'name' is required")
        out.append(
            Sanitizer(
                name=_name(entry["name"], f"{where}.name"),
                language=lang,
                cwe=_cwes(entry.get("cwe"), f"{where}.cwe"),
                note=_note(entry, where),
            )
        )
    return tuple(out)


def _parse_trusted(data: dict[str, Any]) -> tuple[TrustedSource, ...]:
    out: list[TrustedSource] = []
    for lang, i, entry in _per_language(data, "trusted_sources"):
        where = f"trusted_sources.{lang} #{i}"
        if isinstance(entry, str):
            out.append(TrustedSource(name=_name(entry, where), language=lang))
            continue
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: expected a name or a mapping, got {type(entry).__name__}")
        _check_keys(entry, ("name", "note"), where)
        if "name" not in entry:
            raise ConfigError(f"{where}: 'name' is required")
        out.append(
            TrustedSource(
                name=_name(entry["name"], f"{where}.name"), language=lang, note=_note(entry, where)
            )
        )
    return tuple(out)


def _parse_internal(data: dict[str, Any]) -> tuple[InternalPath, ...]:
    out: list[InternalPath] = []
    for i, entry in enumerate(_list(data, "internal_paths", "internal_paths"), start=1):
        where = f"internal_paths #{i}"
        if isinstance(entry, str):
            out.append(InternalPath(path=_glob(entry, where)))
            continue
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: expected a glob or a mapping, got {type(entry).__name__}")
        _check_keys(entry, ("path", "note"), where)
        if "path" not in entry:
            raise ConfigError(f"{where}: 'path' is required")
        out.append(
            InternalPath(path=_glob(entry["path"], f"{where}.path"), note=_note(entry, where))
        )
    return tuple(out)


def _parse_exposure(data: dict[str, Any]) -> tuple[ExposureNote, ...]:
    out: list[ExposureNote] = []
    for i, entry in enumerate(_list(data, "exposure", "exposure"), start=1):
        where = f"exposure #{i}"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: expected a mapping, got {type(entry).__name__}")
        _check_keys(entry, ("path", "level", "note"), where)
        for required in ("path", "level"):
            if required not in entry:
                raise ConfigError(f"{where}: '{required}' is required")
        level = entry["level"]
        if not isinstance(level, str) or level not in EXPOSURE_LEVELS:
            raise ConfigError(
                f"{where}.level: unknown level {level!r} "
                f"(choose from: {', '.join(EXPOSURE_LEVELS)})"
            )
        out.append(
            ExposureNote(
                path=_glob(entry["path"], f"{where}.path"), level=level, note=_note(entry, where)
            )
        )
    return tuple(out)


def _parse_classification(data: dict[str, Any]) -> tuple[DataClassification, ...]:
    out: list[DataClassification] = []
    for i, entry in enumerate(_list(data, "data_classification", "data_classification"), start=1):
        where = f"data_classification #{i}"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: expected a mapping, got {type(entry).__name__}")
        _check_keys(entry, ("path", "model", "classes", "note"), where)
        path = _glob(entry["path"], f"{where}.path") if entry.get("path") is not None else None
        model = _name(entry["model"], f"{where}.model") if entry.get("model") is not None else None
        if path is None and model is None:
            raise ConfigError(f"{where}: give a 'path' glob, a 'model' name, or both")
        raw = entry.get("classes")
        items = [raw] if isinstance(raw, str) else raw
        if not isinstance(items, list) or not items or not all(isinstance(c, str) for c in items):
            raise ConfigError(
                f"{where}.classes: expected a non-empty list (choose from: {', '.join(DATA_CLASSES)})"
            )
        classes = tuple(dict.fromkeys(c.strip().lower() for c in items))
        bad = [c for c in classes if c not in DATA_CLASSES]
        if bad:
            raise ConfigError(
                f"{where}.classes: unknown class(es) {', '.join(bad)} "
                f"(choose from: {', '.join(DATA_CLASSES)})"
            )
        out.append(
            DataClassification(classes=classes, path=path, model=model, note=_note(entry, where))
        )
    return tuple(out)


def context_from_dict(data: dict[str, Any], *, source: str = "") -> ProjectContext:
    """Build a :class:`ProjectContext` from parsed YAML, validating every field."""
    _check_keys(data, _TOP_LEVEL_KEYS, "context")
    version = data.get("version", 1)
    if isinstance(version, bool) or version not in _SUPPORTED_VERSIONS:
        raise ConfigError(
            f"version: unsupported context file version {version!r} "
            f"(supported: {', '.join(map(str, _SUPPORTED_VERSIONS))})"
        )
    return ProjectContext(
        source=source,
        sanitizers=_parse_sanitizers(data),
        trusted_sources=_parse_trusted(data),
        internal_paths=_parse_internal(data),
        exposure=_parse_exposure(data),
        data_classification=_parse_classification(data),
    )


def parse_context(text: str, *, source: str = CONTEXT_PATH) -> ProjectContext:
    """Parse context YAML text; any problem is a :class:`ConfigError` naming ``source``."""
    if len(text.encode("utf-8", "replace")) > _MAX_BYTES:
        raise ConfigError(f"{source}: larger than {_MAX_BYTES} bytes")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{source}: invalid YAML: {exc}") from exc
    if data is None:
        return ProjectContext(source=source)
    if not isinstance(data, dict):
        raise ConfigError(
            f"{source}: expected a mapping at the top level, got {type(data).__name__}"
        )
    try:
        return context_from_dict(data, source=source)
    except ConfigError as exc:
        raise ConfigError(f"{source}: {exc}") from exc


def context_file(project_root: str | Path) -> Path | None:
    """The context file under ``project_root``, or None if there is none."""
    base = Path(project_root) / ".argus"
    for name in _CONTEXT_FILENAMES:
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def context_ref_paths() -> tuple[str, ...]:
    """Candidate paths for the context file at a git ref, relative to the scan dir."""
    return tuple(f"./.argus/{name}" for name in _CONTEXT_FILENAMES)


def load_context(project_root: str | Path) -> ProjectContext:
    """Read ``.argus/context.yml`` from a project; a missing file is an empty context.

    Callers decide trust; see :func:`argus.core.config.load_project_config`.
    """
    path = context_file(project_root)
    if path is None:
        return ProjectContext()
    rel = f".argus/{path.name}"
    try:
        if path.stat().st_size > _MAX_BYTES:
            raise ConfigError(f"{rel}: larger than {_MAX_BYTES} bytes")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{rel}: cannot read context file: {exc}") from exc
    return parse_context(text, source=rel)
