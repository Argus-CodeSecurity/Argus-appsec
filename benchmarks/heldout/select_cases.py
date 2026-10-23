"""Apply the selection rule in ``selection.py`` and write the manifest.

Network access is read-only GitHub REST API calls, cached under
``benchmarks/.corpora/<set>/api``. The manifest lists every selected case
and every exclusion with its reason. ``client`` only needs an ``api(path)``
method, so the tests drive ``select`` with synthetic advisories.
"""

from __future__ import annotations

import datetime as _dt
import urllib.parse
from collections import Counter
from typing import Any

from benchmarks.heldout import selection as sel
from benchmarks.heldout.github import Client, GitHubError

_PAGE = 100


def _advisory_query(ecosystem: str, start: _dt.date, end: _dt.date) -> str:
    params = {
        "type": "reviewed",
        "ecosystem": ecosystem,
        "cwes": ",".join(str(c) for c in sorted(sel.TARGET_CWES)),
        "published": f"{start.isoformat()}..{end.isoformat()}",
        "per_page": str(_PAGE),
        "sort": "published",
        "direction": "asc",
    }
    return "/advisories?" + urllib.parse.urlencode(params, safe=",.")


def list_advisories(
    client: Client, ecosystem: str, window: tuple[str, str] = sel.PUBLISHED_WINDOW
) -> list[dict[str, Any]]:
    """Every reviewed advisory in ``window`` with a target CWE.

    The advisories endpoint pages with an opaque cursor in the ``Link`` header,
    so instead the date range is split until each slice returns fewer than one
    full page. That keeps every request a plain, cacheable GET.
    """
    start = _dt.date.fromisoformat(window[0])
    end = _dt.date.fromisoformat(window[1])
    out: dict[str, dict[str, Any]] = {}
    stack = [(start, end)]
    while stack:
        a, b = stack.pop()
        page = client.api(_advisory_query(ecosystem, a, b))
        if len(page) >= _PAGE:
            if a == b:
                raise RuntimeError(f"more than {_PAGE} advisories published on {a}")
            mid = a + (b - a) // 2
            stack.extend([(a, mid), (mid + _dt.timedelta(days=1), b)])
            continue
        for adv in page:
            out[adv["ghsa_id"]] = adv
    return sorted(out.values(), key=lambda a: a["ghsa_id"])


def _slim(adv: dict[str, Any], ecosystem: str) -> dict[str, Any]:
    return {
        "ghsa_id": adv["ghsa_id"],
        "cve_id": adv.get("cve_id"),
        "ecosystem": ecosystem,
        "packages": sorted(
            {
                v["package"]["name"]
                for v in adv.get("vulnerabilities") or []
                if (v.get("package") or {}).get("ecosystem") == ecosystem
            }
        ),
        "published_at": adv.get("published_at"),
        "advisory_cwes": sorted(
            int(c["cwe_id"].split("-")[1]) for c in adv.get("cwes") or [] if c.get("cwe_id")
        ),
        "html_url": adv.get("html_url"),
    }


def _commit_files(client: Client, fc: sel.FixCommit) -> dict[str, Any]:
    owner, name = fc.repo.split("/", 1)
    return client.api(f"/repos/{owner}/{name}/commits/{fc.sha}")


def select(
    client: Client, rule: sel.SetRule = sel.V1_RULE, prior: sel.PriorSets | None = None
) -> dict[str, Any]:
    """Apply the rule for one set. ``prior`` lists what earlier sets examined.

    An advisory an earlier set examined (or that shares a CVE id with one) is
    skipped before sampling, and a file and commit that is already an earlier
    case is never a case again. With ``rule=V1_RULE`` and no ``prior`` this is
    the v1 selection unchanged.
    """
    prior = prior or sel.PriorSets()
    cases: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    file_exclusions: list[dict[str, Any]] = []
    population: dict[str, dict[str, int]] = {}
    seen_files: set[tuple[str, str, str]] = set()

    for eco in sel.ECOSYSTEMS:
        advisories = list_advisories(client, eco, rule.published_window)
        stats: Counter[str] = Counter(listed=len(advisories))
        candidates = []
        for adv in advisories:
            if not rule.in_window(adv.get("published_at")):
                stats["outside_published_window"] += 1
                continue
            prior_reason = prior.reason(adv)
            if prior_reason:
                stats[f"skipped: {prior_reason}"] += 1
                continue
            if adv.get("withdrawn_at"):
                stats["withdrawn"] += 1
                continue
            label = sel.advisory_label(c.get("cwe_id", "") for c in adv.get("cwes") or [])
            if not label:  # the API filter matched a CWE that is not a target
                stats["no_target_cwe"] += 1
                continue
            commits = sel.fix_commits(adv.get("references") or [])
            if not commits:
                stats["no_fix_commit_reference"] += 1
                continue
            candidates.append((rule.order_key(adv["ghsa_id"]), adv, label, commits))
        stats["candidates"] = len(candidates)
        candidates.sort(key=lambda t: t[0])

        taken = 0
        for _, adv, label, commits in candidates:
            if taken >= rule.case_budget[eco]:
                stats["not_sampled_budget_reached"] += 1
                continue
            stats["examined"] += 1
            slim = _slim(adv, eco)
            new_cases, reason, per_file = _advisory_cases(
                client, slim, label, commits, seen_files, prior.files
            )
            file_exclusions.extend(per_file)
            if reason:
                excluded.append({**slim, "reason": reason})
                stats[f"excluded: {reason}"] += 1
                continue
            stats["selected_advisories"] += 1
            taken += len(new_cases)
            cases.extend(new_cases)
        stats["selected_cases"] = taken
        population[eco] = dict(sorted(stats.items()))

    for i, case in enumerate(cases):
        case["case_id"] = f"{i + 1:03d}-{case['ghsa_id']}"
    return {
        "population": population,
        "cases": cases,
        "excluded_advisories": excluded,
        "excluded_files": file_exclusions,
    }


def _advisory_cases(
    client: Client,
    slim: dict[str, Any],
    label: list[int],
    commits: list[sel.FixCommit],
    seen_files: set[tuple[str, str, str]],
    prior_files: frozenset[tuple[str, str, str]] = frozenset(),
) -> tuple[list[dict[str, Any]], str | None, list[dict[str, Any]]]:
    out: list[dict[str, Any]] = []
    file_excl: list[dict[str, Any]] = []
    paths: set[str] = set()
    retrieved = 0
    for fc in commits:
        try:
            data = _commit_files(client, fc)
        except GitHubError as exc:
            file_excl.append(
                {"ghsa_id": slim["ghsa_id"], "repo": fc.repo, "fix_sha": fc.sha,
                 "path": None, "reason": "fix commit not retrievable", "detail": str(exc)[:200]}
            )  # fmt: skip
            continue
        retrieved += 1
        parents = data.get("parents") or []
        full_sha = data["sha"]
        repo = _repo_from_api(data) or fc.repo
        if not parents:
            file_excl.append(_fx(slim, repo, full_sha, None, "fix commit has no parent"))
            continue
        if len(data.get("files") or []) >= 300:
            file_excl.append(
                _fx(slim, repo, full_sha, None, "fix commit lists 300 or more files (API limit)")
            )
            continue
        for f in data.get("files") or []:
            path = f["filename"]
            reason = sel.exclusion_reason(path)
            status = f.get("status")
            if reason is None and status not in ("modified", "renamed"):
                reason = f"file {status} by the fix (no before/after pair)"
            if reason is None and not f.get("patch"):
                reason = "diff not provided by the API"
            if reason is None and path in paths:
                reason = "path already taken from an earlier fix commit of this advisory"
            if reason is None and (repo.lower(), full_sha, path) in seen_files:
                reason = "same file and commit already a case of another advisory"
            if reason is None and (repo.lower(), full_sha.lower(), path) in prior_files:
                reason = "same file and commit already a case in an earlier set"
            if reason is not None:
                if sel.language_of(path) is not None:  # only log source files
                    file_excl.append(_fx(slim, repo, full_sha, path, reason))
                continue
            changes = sel.changed_lines(f["patch"])
            paths.add(path)
            out.append(
                {
                    **slim,
                    "label_cwes": label,
                    "repo": repo,
                    "fix_sha": full_sha,
                    "parent_sha": parents[0]["sha"],
                    "path_vulnerable": f.get("previous_filename") or path,
                    "path_patched": path,
                    "language": sel.language_of(path),
                    "vulnerable_lines": sel.to_ranges(changes.old),
                    "patched_lines": sel.to_ranges(changes.new),
                    "commit_url": f"https://github.com/{repo}/commit/{full_sha}",
                }
            )
    if retrieved == 0:
        return [], "no fix commit retrievable", file_excl
    if not out:
        return [], "no eligible source file in the fix commits", file_excl
    if len(out) > sel.MAX_FILES_PER_ADVISORY:
        return [], f"fix touches more than {sel.MAX_FILES_PER_ADVISORY} source files", file_excl
    for c in out:
        seen_files.add((c["repo"].lower(), c["fix_sha"], c["path_patched"]))
    return out, None, file_excl


def _fx(slim: dict[str, Any], repo: str, sha: str, path: str | None, reason: str) -> dict[str, Any]:
    return {
        "ghsa_id": slim["ghsa_id"],
        "repo": repo,
        "fix_sha": sha,
        "path": path,
        "reason": reason,
    }


def _repo_from_api(data: dict[str, Any]) -> str | None:
    """``owner/name`` from the commit's ``html_url`` (follows renamed repos)."""
    url = str(data.get("html_url") or "")
    parts = url.removeprefix("https://github.com/").split("/")
    return f"{parts[0]}/{parts[1]}" if len(parts) >= 4 and parts[2] == "commit" else None
