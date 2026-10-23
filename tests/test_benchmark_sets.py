"""Tests for the development and time-split benchmark sets (benchmarks/heldout).

Every input here is synthetic: invented GHSA ids, repositories and commits,
served by an in-memory stand-in for the GitHub client. Nothing in this file
queries GitHub, and in particular nothing reads real advisories published on
or after the time-split start date.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

import pytest
from benchmarks.heldout import cli, harness, selection
from benchmarks.heldout.select_cases import select

PATCH = "@@ -1,3 +1,3 @@\n a\n-b\n+c\n d\n"


def _sha(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()


def _adv(
    ghsa: str,
    *,
    eco: str = "pip",
    published: str = "2025-03-01T10:00:00Z",
    cve: str | None = None,
    cwes: tuple[str, ...] = ("CWE-79",),
    repo: str = "acme/app",
    sha: str | None = None,
    withdrawn: bool = False,
) -> dict[str, Any]:
    return {
        "ghsa_id": ghsa,
        "cve_id": cve,
        "published_at": published,
        "withdrawn_at": "2025-04-01T00:00:00Z" if withdrawn else None,
        "cwes": [{"cwe_id": c} for c in cwes],
        "references": [f"https://github.com/{repo}/commit/{sha or _sha(ghsa)}"],
        "vulnerabilities": [{"package": {"ecosystem": eco, "name": "pkg"}}],
        "html_url": f"https://github.com/advisories/{ghsa}",
    }


def _commit(repo: str, sha: str, files: tuple[str, ...] = ("src/app.py",)) -> dict[str, Any]:
    return {
        "sha": sha,
        "html_url": f"https://github.com/{repo}/commit/{sha}",
        "parents": [{"sha": "0" * 40}],
        "files": [{"filename": f, "status": "modified", "patch": PATCH} for f in files],
    }


class FakeClient:
    """In-memory stand-in for ``github.Client``.

    The advisory listing ignores the ``published`` filter on purpose, so the
    tests also see what the client-side window check drops.
    """

    def __init__(
        self,
        advisories: list[dict[str, Any]],
        commits: dict[tuple[str, str], dict[str, Any]] | None = None,
    ):
        self.advisories = advisories
        self.commits = dict(commits or {})
        for a in advisories:
            for ref in a["references"]:
                m = re.search(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]+)", ref)
                if m and (m[1], m[2]) not in self.commits:
                    self.commits[(m[1], m[2])] = _commit(m[1], m[2])
        self.paths: list[str] = []
        self.requests = 0

    def api(self, path: str) -> Any:
        self.paths.append(path)
        self.requests += 1
        if path.startswith("/advisories?"):
            eco = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["ecosystem"][0]
            return [
                a for a in self.advisories if a["vulnerabilities"][0]["package"]["ecosystem"] == eco
            ]
        m = re.fullmatch(r"/repos/([^/]+)/([^/]+)/commits/([0-9a-f]+)", path)
        assert m, path
        return self.commits[(f"{m[1]}/{m[2]}", m[3])]


def _published_ranges(client: FakeClient) -> set[str]:
    out = set()
    for p in client.paths:
        if p.startswith("/advisories?"):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(p).query)
            out.add(q["published"][0])
    return out


def _manifest(cases: list[dict[str, Any]], dropped: list[dict[str, Any]]) -> dict[str, Any]:
    return {"schema_version": 1, "cases": cases, "excluded_advisories": dropped}


def _case_entry(ghsa: str, cve: str | None, repo: str, sha: str, path: str) -> dict[str, Any]:
    return {"ghsa_id": ghsa, "cve_id": cve, "repo": repo, "fix_sha": sha, "path_patched": path}


# --- sampling order ----------------------------------------------------------------


def test_dev_order_is_sha256_of_prefixed_id_and_differs_from_v1() -> None:
    ghsa = "GHSA-aaaa-bbbb-cccc"
    # The id is upper-cased before hashing, as in v1.
    want = hashlib.sha256(b"dev:GHSA-AAAA-BBBB-CCCC").hexdigest()
    assert selection.DEV_RULE.order_key(ghsa) == want
    assert selection.DEV_RULE.order_key(ghsa.upper()) == want
    # v1 keeps its original key.
    assert selection.V1_RULE.order_key(ghsa) == hashlib.sha256(b"GHSA-AAAA-BBBB-CCCC").hexdigest()
    assert selection.V1_RULE.order_key(ghsa) == selection.sample_order(ghsa)
    ids = [f"GHSA-test-{i:04d}-zzzz" for i in range(40)]
    assert sorted(ids, key=selection.DEV_RULE.order_key) != sorted(
        ids, key=selection.V1_RULE.order_key
    )


def test_dev_rule_reuses_the_v1_window_and_rule() -> None:
    assert selection.DEV_RULE.published_window == selection.PUBLISHED_WINDOW
    assert dict(selection.DEV_RULE.case_budget) == {"pip": 200, "npm": 150}
    assert selection.V1_RULE.case_budget == selection.CASE_BUDGET
    assert "dev:" in selection.DEV_RULE.sampling


def test_select_samples_in_dev_order_until_the_budget() -> None:
    ids = [f"GHSA-test-{i:04d}-ordr" for i in range(12)]
    client = FakeClient([_adv(g) for g in ids])
    rule = selection.SetRule("dev", selection.PUBLISHED_WINDOW, {"pip": 4, "npm": 0}, "dev:")
    out = select(client, rule)  # type: ignore[arg-type]
    chosen = [c["ghsa_id"] for c in out["cases"]]
    assert chosen == sorted(ids, key=rule.order_key)[:4]
    assert chosen != sorted(ids, key=selection.V1_RULE.order_key)[:4]
    assert out["population"]["pip"]["not_sampled_budget_reached"] == 8


# --- exclusion of earlier sets --------------------------------------------------------


def test_prior_from_manifest_covers_cases_and_dropped_advisories() -> None:
    doc = _manifest(
        [_case_entry("GHSA-case-0001-aaaa", "CVE-2025-0001", "Acme/App", "a" * 40, "x.py")],
        [{"ghsa_id": "ghsa-drop-0002-aaaa", "cve_id": None}],
    )
    prior = selection.prior_from_manifest(doc, "v1", "m.json", "f" * 64)
    assert prior.ghsa_ids == {"GHSA-CASE-0001-AAAA", "GHSA-DROP-0002-AAAA"}
    assert prior.cve_ids == {"CVE-2025-0001"}
    assert prior.files == {("acme/app", "a" * 40, "x.py")}
    (source,) = prior.sources
    assert source["advisories_examined"] == 2
    assert source["ghsa_ids"] == ["GHSA-CASE-0001-AAAA", "GHSA-DROP-0002-AAAA"]
    assert prior.reason({"ghsa_id": "GHSA-drop-0002-aaaa"}) == "examined by an earlier set"
    assert prior.reason({"ghsa_id": "GHSA-new0-0003-aaaa", "cve_id": "cve-2025-0001"}) == (
        "shares a CVE id with an advisory an earlier set examined"
    )
    assert prior.reason({"ghsa_id": "GHSA-new0-0004-aaaa", "cve_id": None}) is None


def test_select_skips_everything_an_earlier_set_examined() -> None:
    shared_sha = _sha("shared")
    advisories = [
        _adv("GHSA-v1ca-0001-aaaa"),  # a v1 case
        _adv("GHSA-v1dr-0002-aaaa"),  # examined by v1 and dropped
        _adv("GHSA-cve0-0003-aaaa", cve="CVE-2025-1111"),  # same CVE as a v1 advisory
        _adv("GHSA-file-0004-aaaa", sha=shared_sha),  # its only file is a v1 case file
        _adv("GHSA-new0-0005-aaaa"),
    ]
    v1 = _manifest(
        [
            _case_entry("GHSA-v1ca-0001-aaaa", None, "acme/app", _sha("GHSA-v1ca-0001-aaaa"), "a"),
            _case_entry("GHSA-zzzz-0009-aaaa", None, "acme/app", shared_sha, "src/app.py"),
        ],
        [
            {"ghsa_id": "GHSA-v1dr-0002-aaaa", "cve_id": None},
            {"ghsa_id": "GHSA-othr-0006-aaaa", "cve_id": "CVE-2025-1111"},
        ],
    )
    prior = selection.prior_from_manifest(v1, "v1", "m.json", "0" * 64)
    out = select(FakeClient(advisories), selection.DEV_RULE, prior)  # type: ignore[arg-type]

    assert [c["ghsa_id"] for c in out["cases"]] == ["GHSA-new0-0005-aaaa"]
    pip = out["population"]["pip"]
    assert pip["skipped: examined by an earlier set"] == 2
    assert pip["skipped: shares a CVE id with an advisory an earlier set examined"] == 1
    assert pip["candidates"] == 2
    dropped = {a["ghsa_id"]: a["reason"] for a in out["excluded_advisories"]}
    assert dropped == {"GHSA-file-0004-aaaa": "no eligible source file in the fix commits"}
    assert any(
        f["reason"] == "same file and commit already a case in an earlier set"
        for f in out["excluded_files"]
    )


def test_v1_rule_without_prior_is_unchanged() -> None:
    advisories = [_adv(f"GHSA-test-{i:04d}-vone") for i in range(3)]
    out = select(FakeClient(advisories))  # type: ignore[arg-type]
    assert [c["ghsa_id"] for c in out["cases"]] == sorted(
        (a["ghsa_id"] for a in advisories), key=selection.sample_order
    )
    assert not any(k.startswith("skipped") for k in out["population"]["pip"])


# --- time-split rule ------------------------------------------------------------------


def test_timesplit_rule_window() -> None:
    rule = selection.timesplit_rule("2026-12-31")
    assert rule.published_window == ("2026-10-01", "2026-12-31")
    assert rule.order_key("GHSA-x") == hashlib.sha256(b"timesplit:GHSA-X").hexdigest()
    assert selection.timesplit_rule("2027-03-31", since="2027-01-01").published_window == (
        "2027-01-01",
        "2027-03-31",
    )
    with pytest.raises(ValueError, match="before the time-split start"):
        selection.timesplit_rule("2026-12-31", since="2026-09-30")
    with pytest.raises(ValueError, match="before since"):
        selection.timesplit_rule("2026-09-15")
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        selection.timesplit_rule("31/12/2026")


def test_timesplit_selection_keeps_only_its_window() -> None:
    advisories = [
        _adv("GHSA-ts00-0001-aaaa", published="2026-09-30T23:59:59Z"),
        _adv("GHSA-ts00-0002-aaaa", published="2026-10-01T00:00:00Z"),
        _adv("GHSA-ts00-0003-aaaa", published="2026-12-31T23:00:00Z", eco="npm"),
        _adv("GHSA-ts00-0004-aaaa", published="2027-01-01T00:00:00Z"),
        _adv("GHSA-ts00-0005-aaaa", published=None),  # type: ignore[arg-type]
    ]
    client = FakeClient(advisories)
    out = select(client, selection.timesplit_rule("2026-12-31"))  # type: ignore[arg-type]
    assert sorted(c["ghsa_id"] for c in out["cases"]) == [
        "GHSA-ts00-0002-aaaa",
        "GHSA-ts00-0003-aaaa",
    ]
    assert out["population"]["pip"]["outside_published_window"] == 3
    # The API was asked for the time-split window and nothing else.
    assert _published_ranges(client) == {"2026-10-01..2026-12-31"}


def test_dev_selection_never_asks_for_the_timesplit_window() -> None:
    client = FakeClient([_adv("GHSA-dev0-0001-aaaa")])
    select(client, selection.DEV_RULE)  # type: ignore[arg-type]
    for rng in _published_ranges(client):
        start, end = rng.split("..")
        assert end < selection.TIMESPLIT_START, rng


# --- freeze guard ----------------------------------------------------------------------

FROZEN = "c" * 40
TODAY = _dt.date(2027, 2, 1)


def _git(diff_code: int = 0, known: bool = True, untracked: str = "") -> cli.Git:
    def run(args: list[str]) -> tuple[int, str]:
        if args[0] == "rev-parse" and args[1] == "--verify":
            return (0 if known else 1), ""
        if args[0] == "rev-parse":
            return 0, "d" * 40
        if args[0] == "diff":
            return diff_code, ""
        if args[0] == "ls-files":
            return 0, untracked
        raise AssertionError(args)

    return run


def _sets(tmp_path: Path, with_priors: bool = True) -> dict[str, cli.BenchSet]:
    out = {}
    for name in ("v1", "dev", "timesplit"):
        out[name] = cli.BenchSet(
            name,
            tmp_path / name / "manifest.json",
            tmp_path / "corpora" / name,
            tmp_path / "results" / name,
            f"{name}.json",
            name,
        )
    if with_priors:
        v1 = _manifest(
            [_case_entry("GHSA-v1ca-0001-aaaa", "CVE-2026-0001", "acme/app", "a" * 40, "x.py")],
            [{"ghsa_id": "GHSA-v1dr-0002-aaaa", "cve_id": None}],
        )
        dev = _manifest(
            [_case_entry("GHSA-dvca-0003-aaaa", None, "acme/app", "b" * 40, "y.py")], []
        )
        for name, doc in (("v1", v1), ("dev", dev)):
            out[name].manifest.parent.mkdir(parents=True)
            out[name].manifest.write_text(json.dumps(doc), encoding="utf-8")
    return out


def _problems(tmp_path: Path, **kw: Any) -> list[str]:
    args: dict[str, Any] = {
        "rules_frozen_at": FROZEN,
        "until": "2026-12-31",
        "since": selection.TIMESPLIT_START,
        "today": TODAY,
        "git": _git(),
    }
    args.update(kw)
    if "sets" not in args:
        args["sets"] = _sets(tmp_path)
    return cli.timesplit_problems(**args)


def test_freeze_guard_passes_when_everything_is_in_order(tmp_path: Path) -> None:
    assert _problems(tmp_path) == []


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"rules_frozen_at": None}, "--rules-frozen-at <commit> is required"),
        ({"rules_frozen_at": "main"}, "full 40-character"),
        ({"rules_frozen_at": "c" * 12}, "full 40-character"),
        ({"git": _git(known=False)}, "is not a commit"),
        ({"git": _git(diff_code=1)}, "src/nephilex differs from the frozen commit"),
        ({"git": _git(untracked="src/nephilex/new.py")}, "untracked files"),
        ({"until": None}, "--until YYYY-MM-DD"),
        ({"until": "2027-02-01"}, "must be before today"),
        ({"until": "2027-06-30"}, "must be before today"),
        ({"until": "2026-09-30"}, "before since"),
        ({"since": "2026-06-01"}, "before the time-split start"),
    ],
)
def test_freeze_guard_refuses(tmp_path: Path, kw: dict[str, Any], message: str) -> None:
    problems = _problems(tmp_path, **kw)
    assert any(message in p for p in problems), problems


def test_freeze_guard_refuses_a_second_selection_and_missing_priors(tmp_path: Path) -> None:
    sets = _sets(tmp_path, with_priors=False)
    sets["timesplit"].manifest.parent.mkdir(parents=True)
    sets["timesplit"].manifest.write_text("{}", encoding="utf-8")
    problems = _problems(tmp_path, sets=sets)
    assert any("selected once" in p for p in problems)
    assert sum("manifest it excludes is missing" in p for p in problems) == 2


def _cli_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, client: FakeClient | None
) -> dict[str, cli.BenchSet]:
    sets = _sets(tmp_path)
    for name, bs in sets.items():
        monkeypatch.setitem(cli.SETS, name, bs)
    monkeypatch.setattr(cli, "_git", _git())
    monkeypatch.setattr(cli, "_today", lambda: TODAY)

    def make_client(*_a: Any, **_k: Any) -> FakeClient:
        if client is None:
            raise AssertionError("the guard must refuse before any GitHub request")
        return client

    monkeypatch.setattr(cli, "Client", make_client)
    return sets


def test_cli_timesplit_without_acknowledgement_makes_no_request(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sets = _cli_env(monkeypatch, tmp_path, client=None)
    code = cli.main(["select", "--set", "timesplit", "--until", "2026-12-31"])
    assert code == 2
    assert "--rules-frozen-at <commit> is required" in capsys.readouterr().err
    assert not sets["timesplit"].manifest.exists()


def test_cli_timesplit_dry_run_on_synthetic_advisories(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = FakeClient(
        [
            _adv("GHSA-v1ca-0001-aaaa", published="2026-10-05T00:00:00Z"),  # in v1: skipped
            _adv("GHSA-dvca-0003-aaaa", published="2026-10-06T00:00:00Z"),  # in dev: skipped
            _adv("GHSA-tsnw-0007-aaaa", published="2026-10-07T00:00:00Z", cve="CVE-2026-0001"),
            _adv("GHSA-tsnw-0008-aaaa", published="2026-11-02T00:00:00Z", eco="npm"),
            _adv("GHSA-tsld-0009-aaaa", published="2026-08-01T00:00:00Z"),  # before the window
            _adv("GHSA-tsln-0010-aaaa", published="2027-01-15T00:00:00Z"),  # after --until
        ]
    )
    sets = _cli_env(monkeypatch, tmp_path, client)
    code = cli.main(
        ["select", "--set", "timesplit", "--until", "2026-12-31", "--rules-frozen-at", FROZEN]
    )
    assert code == 0
    doc = json.loads(sets["timesplit"].manifest.read_text(encoding="utf-8"))
    assert doc["set"] == "timesplit"
    assert doc["freeze"]["rules_frozen_at"] == FROZEN
    assert doc["freeze"]["harness_commit"] == "d" * 40
    assert doc["rule"]["published_window"] == ["2026-10-01", "2026-12-31"]
    assert [s["set"] for s in doc["excluded_prior_sets"]] == ["v1", "dev"]
    assert [c["ghsa_id"] for c in doc["cases"]] == ["GHSA-tsnw-0008-aaaa"]
    pip = doc["population"]["pip"]
    assert pip["skipped: examined by an earlier set"] == 2
    assert pip["skipped: shares a CVE id with an advisory an earlier set examined"] == 1
    assert pip["outside_published_window"] == 2
    assert _published_ranges(client) == {"2026-10-01..2026-12-31"}
    # Selected once: a second run is refused before any request.
    monkeypatch.setattr(cli, "Client", lambda *a, **k: pytest.fail("no request expected"))
    assert (
        cli.main(
            ["select", "--set", "timesplit", "--until", "2026-12-31", "--rules-frozen-at", FROZEN]
        )
        == 2
    )


def test_cli_freeze_flags_are_rejected_for_other_sets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _cli_env(monkeypatch, tmp_path, client=None)
    assert cli.main(["select", "--set", "dev", "--rules-frozen-at", FROZEN]) == 2
    assert cli.main(["select", "--set", "dev", "--until", "2026-12-31"]) == 2


def test_cli_existing_manifest_needs_replace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _cli_env(monkeypatch, tmp_path, client=None)
    assert cli.main(["select", "--set", "dev"]) == 2
    assert "--replace" in capsys.readouterr().err


def test_scan_refuses_when_src_differs_from_frozen_commit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sets = _cli_env(monkeypatch, tmp_path, client=None)
    ts = sets["timesplit"]
    ts.manifest.parent.mkdir(parents=True)
    ts.manifest.write_text(
        json.dumps({"freeze": {"rules_frozen_at": FROZEN}, "cases": []}), encoding="utf-8"
    )
    monkeypatch.setattr(cli, "_git", _git(diff_code=1))
    monkeypatch.setattr(harness, "scored_cases", lambda *a: pytest.fail("must not scan"))
    assert cli.main(["scan", "--set", "timesplit"]) == 2
    assert "differs from the frozen commit" in capsys.readouterr().err


def test_set_paths_are_separate() -> None:
    sets = list(cli.SETS.values())
    for attr in ("manifest", "cache", "results"):
        values = [getattr(bs, attr) for bs in sets]
        assert len(set(values)) == len(values), attr
    assert cli.SETS["v1"].manifest == cli.MANIFEST
    assert cli.SETS["v1"].results_file == "heldout.json"
    assert cli.PRIOR["dev"] == ("v1",)
    assert cli.PRIOR["timesplit"] == ("v1", "dev")
