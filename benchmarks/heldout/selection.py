"""Case selection rule for the held-out benchmark (pure functions, no I/O).

The rule is fixed here, in code, and was committed before any tool was run on
the selected files. It is restated in ``docs/benchmarks.md``. Every step that
drops an advisory or a file records a reason, and those reasons are published
in the manifest, so the case count can be audited.

Rule, in order:

1. Source: GitHub Advisory Database, ``type=reviewed``, ecosystems ``pip`` and
   ``npm``, advisories published in ``PUBLISHED_WINDOW`` and not withdrawn.
2. CWE: the advisory lists at least one CWE in ``TARGET_CWES``: the CWEs that
   Nephilex's Python and JavaScript/TypeScript source-code rules report, plus
   the members of the equivalence groups in ``benchmarks/public/mapping.py``
   that contain one of them. The advisory's label is the subset of its CWEs
   that is in ``TARGET_CWES``.
3. Fix commit: at least one advisory reference is a GitHub commit URL
   (``github.com/<owner>/<repo>/commit/<sha>`` or ``.../pull/<n>/commits/<sha>``).
   Every such commit is used, in reference order.
4. Files: from each fix commit, every file whose status is ``modified`` or
   ``renamed`` with a Python (``.py``) or JavaScript/TypeScript extension, that
   is not a test, documentation, example, vendored, minified or generated file
   (``exclusion_reason``). Within one advisory a path is taken once, from the
   first commit that touches it.
5. Localized fixes only: an advisory whose fix touches more than
   ``MAX_FILES_PER_ADVISORY`` eligible files is excluded as a refactor, since
   the changed lines would not point at the vulnerable code.
6. Sampling: candidate advisories are ordered by SHA-256 of their GHSA id
   (a fixed pseudo-random order that nobody chose) and taken in that order
   until ``CASE_BUDGET[ecosystem]`` files are reached. The order does not
   depend on any tool's output.

A *case* is one file of one advisory: the vulnerable version is the file at the
fix commit's first parent, the patched version is the file at the fix commit.

Three sets use this rule (``SetRule``). They differ only in the published
window, the case budget, the sampling order and what they exclude:

* ``V1_RULE``: the frozen v1 held-out set (``benchmarks/heldout/manifest.json``).
* ``DEV_RULE``: the development set. Same window as v1, minus every advisory
  v1 examined, sampled in a different order. Its misses are meant to be read.
* ``timesplit_rule``: the time-split test set. Advisories published on or after
  ``TIMESPLIT_START`` up to a freeze date given when it is selected, minus
  every advisory the earlier sets examined. It is selected only after the
  detection rules for a release are frozen (see ``cli.py``).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from benchmarks.public.mapping import accepted_cwes

# 1. Source window (inclusive dates, UTC). The end date is fixed so that later
#    runs of ``select`` see the same population, apart from advisories GitHub
#    adds, edits or withdraws after the snapshot (the manifest is the frozen
#    record).
PUBLISHED_WINDOW = ("2024-01-01", "2026-09-30")
ECOSYSTEMS = ("pip", "npm")

# 2. CWEs reported by Nephilex's Python and JS/TS source-code rules, with the
#    scanner modules that report them (src/nephilex/scanners/). Rules that only
#    look at configuration, infrastructure, dependencies, CI files, secrets,
#    other languages or LLM-specific misuse heuristics (llm.py, llm_agency.py
#    except SSRF, api.py, iac.py, cicd.py, lang_sast.py, ...) are not counted:
#    their CWEs (for example 200, 250, 732) name broad weakness classes that
#    those rules detect only in narrow contexts.
CLAIMED_CWES: dict[int, str] = {
    22: "ast_python, _pyflow, ast_js, patterns, llm_taint",
    73: "llm_taint",
    74: "llm_taint",
    77: "llm_taint",
    78: "ast_python, _pyflow, ast_js, patterns, llm_taint",
    79: "ast_python, _pyflow, ast_js, patterns, llm_taint",
    80: "_pyflow",
    89: "ast_python, _pyflow, ast_js, patterns, llm_taint",
    90: "ast_python, _pyflow",
    94: "_pyflow",
    95: "ast_python, _pyflow, ast_js, patterns, llm_taint",
    295: "patterns",
    306: "authz",
    327: "patterns",
    330: "ast_python, _pyflow, patterns",
    338: "ast_python, patterns",
    347: "authz",
    352: "authz",
    489: "patterns",
    501: "ast_python, _pyflow",
    502: "ast_python, _pyflow, patterns, llm_taint",
    598: "authz",
    601: "ast_python, _pyflow, patterns",
    611: "ast_python, _pyflow, patterns",
    614: "authz",
    639: "authz",
    643: "ast_python, _pyflow",
    918: "patterns, llm_taint, llm_agency",
    1004: "authz",
    1336: "llm_taint",
}
TARGET_CWES: frozenset[int] = frozenset(
    c for claimed in CLAIMED_CWES for c in accepted_cwes(claimed)
)

# 4. Languages by extension.
LANGUAGES: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "typescript",
}

# 5. and 6.
MAX_FILES_PER_ADVISORY = 5
CASE_BUDGET: dict[str, int] = {"pip": 120, "npm": 80}

# Also applied at fetch time: Semgrep's default per-file limit is 1 MB.
MAX_FILE_BYTES = 1_000_000

_COMMIT_RE = re.compile(
    r"^https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/"
    r"(?:commit|pull/\d+/commits)/([0-9a-fA-F]{7,40})(?:[/?#].*)?$"
)
_TEST_DIRS = frozenset(
    {"test", "tests", "testing", "__tests__", "__test__", "spec", "specs", "e2e", "__mocks__"}
)
# ``tests?.py`` (the Django convention) and ``tests?.js`` were added on
# 2026-10-23 after the first selection, before any score existed: three
# selected cases were test modules (see docs/benchmarks.md, "Amendment").
_TEST_FILE_RE = re.compile(
    r"(^test_.*\.py$|.*_test\.py$|^conftest\.py$|^tests?\.py$"
    r"|^tests?\.[cm]?[jt]sx?$|.*\.(test|spec)\.[cm]?[jt]sx?$)"
)
_DOC_DIRS = frozenset({"doc", "docs", "documentation", "example", "examples", "sample", "samples"})
_VENDOR_DIRS = frozenset(
    {
        "vendor",
        "vendored",
        "_vendor",
        "third_party",
        "thirdparty",
        "third-party",
        "node_modules",
        "bower_components",
        "dist",
        "build",
        "lib-cov",
        "coverage",
    }
)
_GENERATED_FILE_RE = re.compile(r"(\.min\.[cm]?js$|\.bundle\.js$|-bundle\.js$|_pb2(_grpc)?\.py$)")
_DECLARATION_RE = re.compile(r"\.d\.[cm]?ts$")


@dataclass(frozen=True)
class FixCommit:
    repo: str  # owner/name as written in the reference URL
    sha: str  # as written; resolved to the full SHA from the API

    @property
    def key(self) -> tuple[str, str]:
        return (self.repo.lower(), self.sha.lower())


@dataclass
class Exclusion:
    """One dropped advisory or file, with the rule that dropped it."""

    ghsa_id: str
    reason: str
    detail: str = ""


@dataclass
class LineChanges:
    """Lines a diff touched, on each side, 1-based."""

    old: set[int] = field(default_factory=set)
    new: set[int] = field(default_factory=set)


def language_of(path: str) -> str | None:
    suffix = PurePosixPath(path).suffix.lower()
    if _DECLARATION_RE.search(path.lower()):
        return None
    return LANGUAGES.get(suffix)


def exclusion_reason(path: str) -> str | None:
    """Why a changed file is not a case, or None when it is eligible."""
    if language_of(path) is None:
        return "not a Python or JavaScript/TypeScript source file"
    p = PurePosixPath(path.lower())
    dirs = set(p.parts[:-1])
    name = p.name
    if dirs & _TEST_DIRS or _TEST_FILE_RE.match(name):
        return "test file"
    if dirs & _DOC_DIRS:
        return "documentation or example file"
    if dirs & _VENDOR_DIRS or "/site-packages/" in f"/{p}/":
        return "vendored or build output"
    if _GENERATED_FILE_RE.search(name):
        return "minified or generated file"
    return None


def fix_commits(references: Iterable[str]) -> list[FixCommit]:
    """GitHub commit references, in order, de-duplicated."""
    out: list[FixCommit] = []
    seen: set[tuple[str, str]] = set()
    for ref in references:
        m = _COMMIT_RE.match(ref.strip())
        if not m:
            continue
        repo = f"{m.group(1)}/{m.group(2).removesuffix('.git')}"
        fc = FixCommit(repo, m.group(3).lower())
        if fc.key not in seen:
            seen.add(fc.key)
            out.append(fc)
    return out


def advisory_label(cwe_ids: Iterable[str | int]) -> list[int]:
    """The advisory's CWEs that are in ``TARGET_CWES``, sorted."""
    out = set()
    for raw in cwe_ids:
        m = re.match(r"(?i)^\s*(?:cwe-)?0*(\d+)\s*$", str(raw))
        if m and int(m.group(1)) in TARGET_CWES:
            out.add(int(m.group(1)))
    return sorted(out)


def sample_order(ghsa_id: str, prefix: str = "") -> str:
    """Fixed pseudo-random order key for sampling (rule step 6).

    v1 hashes the upper-cased GHSA id alone. Other sets hash ``prefix`` plus
    the id (``"dev:GHSA-..."``), which gives an unrelated order.
    """
    return hashlib.sha256((prefix + ghsa_id.upper()).encode("ascii")).hexdigest()


# --- benchmark sets -------------------------------------------------------------


@dataclass(frozen=True)
class SetRule:
    """What one benchmark set changes in the shared rule (steps 1 and 6)."""

    name: str
    published_window: tuple[str, str]  # inclusive ISO dates, UTC
    case_budget: Mapping[str, int]
    order_prefix: str  # "" for v1, see ``sample_order``

    def order_key(self, ghsa_id: str) -> str:
        return sample_order(ghsa_id, self.order_prefix)

    def in_window(self, published_at: str | None) -> bool:
        """Client-side re-check of the API's ``published`` filter."""
        day = str(published_at or "")[:10]
        return bool(day) and self.published_window[0] <= day <= self.published_window[1]

    @property
    def sampling(self) -> str:
        key = f'"{self.order_prefix}" + GHSA id' if self.order_prefix else "GHSA id"
        return f"advisories ordered by sha256({key}), taken until the budget is reached"


V1_RULE = SetRule("v1", PUBLISHED_WINDOW, CASE_BUDGET, "")

# Development set: the v1 window, about 200 pip and 150 npm cases.
DEV_CASE_BUDGET: dict[str, int] = {"pip": 200, "npm": 150}
DEV_RULE = SetRule("dev", PUBLISHED_WINDOW, DEV_CASE_BUDGET, "dev:")

# Time-split test set: published on or after this date, up to a freeze date.
TIMESPLIT_START = "2026-10-01"
TIMESPLIT_CASE_BUDGET: dict[str, int] = {"pip": 200, "npm": 150}


def timesplit_rule(until: str, since: str = TIMESPLIT_START) -> SetRule:
    """The time-split rule for the window ``since..until`` (both inclusive).

    Raises ``ValueError`` for a malformed date, a start before
    ``TIMESPLIT_START`` (that would reach into the v1 and dev window) or an
    empty window. The caller checks that ``until`` is already in the past.
    """
    start = _parse_date(since, "since")
    end = _parse_date(until, "until")
    if start < _dt.date.fromisoformat(TIMESPLIT_START):
        raise ValueError(f"since {start} is before the time-split start {TIMESPLIT_START}")
    if end < start:
        raise ValueError(f"until {end} is before since {start}")
    return SetRule(
        "timesplit", (start.isoformat(), end.isoformat()), TIMESPLIT_CASE_BUDGET, "timesplit:"
    )


def _parse_date(value: str, name: str) -> _dt.date:
    try:
        return _dt.date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a date written YYYY-MM-DD, got {value!r}") from exc


@dataclass(frozen=True)
class PriorSets:
    """Advisories and files that earlier sets examined. A later set skips them.

    ``ghsa_ids`` holds every advisory an earlier selection examined, whether it
    became a case or was dropped. ``cve_ids`` holds their CVE ids, so the same
    vulnerability filed under a second GHSA id is skipped too. ``files`` holds
    (repository, fix commit, path) of every earlier case.
    """

    ghsa_ids: frozenset[str] = frozenset()
    cve_ids: frozenset[str] = frozenset()
    files: frozenset[tuple[str, str, str]] = frozenset()
    sources: tuple[dict[str, Any], ...] = ()

    def reason(self, adv: Mapping[str, Any]) -> str | None:
        """Why an advisory is skipped because of an earlier set, or None."""
        if str(adv.get("ghsa_id", "")).upper() in self.ghsa_ids:
            return "examined by an earlier set"
        cve = str(adv.get("cve_id") or "").upper()
        if cve and cve in self.cve_ids:
            return "shares a CVE id with an advisory an earlier set examined"
        return None

    def merge(self, other: PriorSets) -> PriorSets:
        return PriorSets(
            self.ghsa_ids | other.ghsa_ids,
            self.cve_ids | other.cve_ids,
            self.files | other.files,
            self.sources + other.sources,
        )


def prior_from_manifest(doc: Mapping[str, Any], set_name: str, path: str, sha256: str) -> PriorSets:
    """Everything one manifest's selection examined: its cases and its drops."""
    examined = [*doc.get("cases", []), *doc.get("excluded_advisories", [])]
    ghsa = frozenset(str(a["ghsa_id"]).upper() for a in examined)
    cves = frozenset(str(a["cve_id"]).upper() for a in examined if a.get("cve_id"))
    files = frozenset(
        (str(c["repo"]).lower(), str(c["fix_sha"]).lower(), str(c["path_patched"]))
        for c in doc.get("cases", [])
    )
    source = {
        "set": set_name,
        "manifest": path,
        "sha256": sha256,
        "advisories_examined": len(ghsa),
        "cve_ids": len(cves),
        "case_files": len(files),
        "ghsa_ids": sorted(ghsa),
    }
    return PriorSets(ghsa, cves, files, (source,))


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def changed_lines(patch: str) -> LineChanges:
    """Lines a unified-diff ``patch`` (GitHub's per-file ``patch``) touches.

    ``old`` holds the removed lines of the parent version; ``new`` holds the
    added lines of the fixed version. A pure insertion has no removed line, so
    the parent lines on either side of the insertion point are recorded as
    ``old`` (and symmetrically for a pure deletion), so that every hunk marks
    at least one line on each side.
    """
    out = LineChanges()
    old_no = new_no = 0
    hunk_old: set[int] = set()
    hunk_new: set[int] = set()
    anchors_old: set[int] = set()
    anchors_new: set[int] = set()

    def close() -> None:
        out.old.update(hunk_old or anchors_old)
        out.new.update(hunk_new or anchors_new)

    in_hunk = False
    for line in patch.splitlines():
        m = _HUNK_RE.match(line)
        if m:
            if in_hunk:
                close()
            in_hunk = True
            old_no, new_no = int(m.group(1)), int(m.group(3))
            hunk_old, hunk_new, anchors_old, anchors_new = set(), set(), set(), set()
            continue
        if not in_hunk:
            continue
        if line.startswith("\\"):  # "\ No newline at end of file"
            continue
        if line.startswith("-"):
            hunk_old.add(old_no)
            anchors_new.update(x for x in (new_no - 1, new_no) if x > 0)
            old_no += 1
        elif line.startswith("+"):
            hunk_new.add(new_no)
            anchors_old.update(x for x in (old_no - 1, old_no) if x > 0)
            new_no += 1
        else:
            old_no += 1
            new_no += 1
    if in_hunk:
        close()
    return out


def to_ranges(lines: Iterable[int]) -> list[list[int]]:
    """``{1,2,3,7}`` -> ``[[1, 3], [7, 7]]``."""
    out: list[list[int]] = []
    for n in sorted(set(lines)):
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return out


def from_ranges(ranges: Sequence[Sequence[int]]) -> set[int]:
    return {n for a, b in ranges for n in range(int(a), int(b) + 1)}
