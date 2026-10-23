"""Tests for glob-based exclude_paths in the project walker."""

from __future__ import annotations

from nephilex.core.project import Project


def _make_tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "vuln.py").write_text("y = 2\n", encoding="utf-8")
    (tmp_path / "thirdparty").mkdir()
    (tmp_path / "thirdparty" / "lib.js").write_text("z=3\n", encoding="utf-8")
    (tmp_path / "bundle.min.js").write_text("a=4\n", encoding="utf-8")
    return tmp_path


def _rel_paths(project) -> set[str]:
    return {f.rel_path for f in project.files()}


def test_no_excludes_sees_everything(tmp_path):
    project = Project.from_path(_make_tree(tmp_path))
    rels = _rel_paths(project)
    assert "src/app.py" in rels
    assert "examples/vuln.py" in rels


def test_exclude_subtree_glob(tmp_path):
    project = Project.from_path(_make_tree(tmp_path))
    project.extra_ignores = ("examples/**",)
    rels = _rel_paths(project)
    assert "examples/vuln.py" not in rels
    assert "src/app.py" in rels


def test_exclude_single_file(tmp_path):
    project = Project.from_path(_make_tree(tmp_path))
    project.extra_ignores = ("src/app.py",)
    assert "src/app.py" not in _rel_paths(project)


def test_exclude_by_extension_glob(tmp_path):
    project = Project.from_path(_make_tree(tmp_path))
    project.extra_ignores = ("*.min.js",)
    assert "bundle.min.js" not in _rel_paths(project)
    assert "thirdparty/lib.js" in _rel_paths(project)


def test_exclude_by_basename(tmp_path):
    project = Project.from_path(_make_tree(tmp_path))
    project.extra_ignores = ("thirdparty",)
    assert not any(r.startswith("thirdparty/") for r in _rel_paths(project))


def test_builtin_ignores_still_apply(tmp_path):
    _make_tree(tmp_path)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "pkg.js").write_text("m=5\n", encoding="utf-8")
    project = Project.from_path(tmp_path)
    assert not any("node_modules" in r for r in _rel_paths(project))
