"""Crash-resistance: a scanner that dies on ugly input gets uninstalled in the
first hour. A scan must survive malformed manifests, broken unicode, truncated
files, huge single lines, and null bytes without raising or hanging.
"""

from __future__ import annotations

from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.project import Project
from argus.scanners import dependencies


def _hostile_repo(tmp_path):
    # Malformed dependency manifests.
    (tmp_path / "requirements.txt").write_bytes(b"\x00\xff\xfe garbage== ===\n-e .\nflask\n")
    (tmp_path / "package-lock.json").write_text('{"packages": {"": {', encoding="utf-8")
    (tmp_path / "package.json").write_text("not json at all {[}", encoding="utf-8")
    (tmp_path / "yarn.lock").write_bytes(b'\xc3\x28 invalid utf8 \xff version "1.0"')
    (tmp_path / "go.mod").write_text("require (\n  broken", encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text("[[package]]\nname =", encoding="utf-8")
    (tmp_path / "Gemfile.lock").write_text("    (((", encoding="utf-8")
    (tmp_path / "composer.lock").write_text('{"packages":', encoding="utf-8")
    # Malformed IaC.
    (tmp_path / "Dockerfile").write_text("FROM\nRUN\nCMD", encoding="utf-8")
    (tmp_path / "k8s.yaml").write_text("apiVersion: v1\n\t\tbad: : :\n  - - -\n", encoding="utf-8")
    # Broken source: invalid syntax, weird unicode, a huge single line.
    (tmp_path / "broken.py").write_bytes(
        "def (:\n\tx = '\udce9'\n".encode("utf-8", "surrogatepass")
    )
    (tmp_path / "huge.py").write_text("x = '" + "A" * 1_900_000 + "'\n", encoding="utf-8")
    # Null bytes (binary sniff) and an empty file.
    (tmp_path / "blob.dat").write_bytes(b"\x00\x01\x02" * 5000)
    (tmp_path / "empty.py").write_text("", encoding="utf-8")
    return Project.from_path(tmp_path)


def test_scan_survives_hostile_inputs(tmp_path):
    project = _hostile_repo(tmp_path)
    cfg = Config(scanner_options={"dependencies": {"online": False}})
    # The only assertion that matters: it returns without raising or hanging.
    result = ScanEngine(cfg).scan(project)
    assert result is not None


def test_dependency_parsers_never_raise_on_garbage():
    garbage = ['{"broken', "\x00\xff", "]]][[[", "require (\n", "name =", "", "\n" * 100]
    parsers = [
        dependencies._parse_requirements,
        dependencies._parse_package_json,
        dependencies._parse_package_lock,
        dependencies._parse_yarn_lock,
        dependencies._parse_toml_packages,
        dependencies._parse_go_mod,
        dependencies._parse_gemfile_lock,
        dependencies._parse_composer_lock,
        dependencies._parse_pipfile_lock,
    ]
    for parse in parsers:
        for text in garbage:
            out = parse(text)
            # tolerant: a list of (name, version) pairs (often empty), never an exception
            assert isinstance(out, list)
            assert all(isinstance(p, tuple) and len(p) == 2 for p in out)
