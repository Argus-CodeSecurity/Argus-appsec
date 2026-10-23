"""Manifest parsers survive hostile JSON shapes.

Manifests come from the scanned repository. A value of the wrong JSON type
(a number where a version string belongs, a list where an object belongs) or
pathologically deep nesting used to raise inside the parser and take down the
dependency, supply-chain and SBOM scanners that share the inventory.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nephilex.core.config import Config
from nephilex.core.plugin import ScannerContext
from nephilex.core.project import Project
from nephilex.scanners import dependencies
from nephilex.scanners.api import ApiScanner
from nephilex.scanners.dependencies import (
    _loads,
    _parse_composer_lock,
    _parse_package_json,
    _parse_package_lock,
    _parse_pipfile_lock,
    collect_packages,
)
from nephilex.scanners.provenance import ProvenanceScanner
from nephilex.scanners.supply_chain import SupplyChainScanner

DEEP = '{"a":' * 100_000 + "1" + "}" * 100_000

HOSTILE_PACKAGE_JSON = [
    '{"dependencies": {"a": 1, "b": null, "c": ["1.0"], "ok": "^1.2.3"}}',
    '{"dependencies": ["a", "b"]}',
    '{"dependencies": "lodash"}',
    '{"devDependencies": 7}',
    "[1, 2, 3]",
    '"just a string"',
    DEEP,
]


@pytest.mark.parametrize("text", HOSTILE_PACKAGE_JSON, ids=range(len(HOSTILE_PACKAGE_JSON)))
def test_package_json_wrong_types(text):
    pairs = _parse_package_json(text)
    assert all(isinstance(n, str) and isinstance(v, str) for n, v in pairs)


def test_package_json_keeps_valid_entries_next_to_bad_ones():
    assert _parse_package_json(HOSTILE_PACKAGE_JSON[0]) == [("ok", "1.2.3")]


@pytest.mark.parametrize(
    "text",
    [
        '{"default": ["requests"], "develop": 3}',
        '{"default": {"requests": {"version": 2}}, "develop": {"x": "==1.0"}}',
        DEEP,
    ],
    ids=["list-and-int", "int-version", "deep"],
)
def test_pipfile_lock_wrong_types(text):
    _parse_pipfile_lock(text)


@pytest.mark.parametrize(
    "text",
    [
        '{"packages": 5, "packages-dev": {"a": 1}}',
        '{"packages": [{"name": ["x"], "version": "1.0"}, {"name": "ok/pkg", "version": "v2.0"}]}',
        DEEP,
    ],
    ids=["wrong-sections", "list-name", "deep"],
)
def test_composer_lock_wrong_types(text):
    pairs = _parse_composer_lock(text)
    assert all(isinstance(n, str) for n, _ in pairs)


def test_package_lock_v1_deep_tree_does_not_recurse(monkeypatch):
    # The JSON decoder itself stops near the recursion limit, so hand the
    # parser an already-decoded tree that is far deeper than that.
    leaf: dict = {}
    tree = leaf
    for i in range(5000):
        tree = {f"p{i}": {"version": "1.0.0", "dependencies": tree}}
    monkeypatch.setattr(dependencies, "_loads", lambda text: {"dependencies": tree})
    pairs = _parse_package_lock("ignored")
    assert len(pairs) == 5000 and ("p0", "1.0.0") in pairs


def test_loads_tolerates_bom_and_deep_nesting():
    assert _loads('﻿{"a": 1}') == {"a": 1}
    assert _loads(DEEP) is None


def _project(tmp_path: Path, files: dict[str, str]) -> Project:
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return Project.from_path(tmp_path)


def test_collect_packages_skips_a_parser_crash(tmp_path, monkeypatch):
    def broken(text):
        raise AttributeError("boom")

    monkeypatch.setitem(dependencies._PARSERS, "package.json", ("npm", broken))
    project = _project(tmp_path, {"package.json": "{}", "requirements.txt": "django==4.2\n"})
    assert collect_packages(project) == [("PyPI", "requirements.txt", "django", "4.2")]


def test_supply_chain_applies_to_does_not_parse(tmp_path, monkeypatch):
    def explode(text):
        raise AssertionError("applies_to must not parse manifests")

    for name, (eco, _parser) in list(dependencies._PARSERS.items()):
        monkeypatch.setitem(dependencies._PARSERS, name, (eco, explode))
    project = _project(tmp_path, {"package-lock.json": DEEP})
    assert SupplyChainScanner().applies_to(project)


def test_provenance_wrong_types(tmp_path):
    docs = [
        {"predicate": {"buildType": "x", "builder": "github"}},
        {"predicate": {"buildType": "x", "builder": {"id": 5}}},
        {"predicate": {"buildType": "x", "builder": ["a"]}},
        {"_type": "https://in-toto.io/Statement/v1", "subject": "x"},
    ]
    files = {f"provenance{i}.json": json.dumps(d) for i, d in enumerate(docs)}
    files["deep.intoto.jsonl"] = DEEP + "\n" + json.dumps(docs[0]) + "\n"
    files["bom.provenance.json"] = "﻿" + json.dumps(docs[0])
    ctx = ScannerContext(project=_project(tmp_path, files), config=Config())
    findings = list(ProvenanceScanner().scan(ctx))
    missing = {f.location.path for f in findings if f.rule_id == "provenance.missing-builder-id"}
    assert {
        "provenance0.json",
        "provenance1.json",
        "provenance2.json",
        "deep.intoto.jsonl",
        "bom.provenance.json",
    } <= missing


def test_openapi_wrong_types(tmp_path):
    files = {
        "openapi.json": json.dumps({"paths": ["a"], "components": [1]}),
        "api/openapi.yaml": "paths:\n  /admin:\n    200: {}\n    get: []\n  7: {}\n",
        "swagger.json": "[1, 2]",
    }
    ctx = ScannerContext(project=_project(tmp_path, files), config=Config())
    list(ApiScanner().scan(ctx))
