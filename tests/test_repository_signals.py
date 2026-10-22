"""Repository analysis: datastore/service detection uses word boundaries."""

from __future__ import annotations

from pathlib import Path

from argus.analysis.repository import RepositoryAnalyzer
from argus.core.project import Project


def _arch(tmp_path: Path, files: dict[str, str]) -> dict:
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return RepositoryAnalyzer().analyze(Project.from_path(tmp_path)).architecture


def test_pg_substrings_do_not_imply_postgres(tmp_path):
    arch = _arch(
        tmp_path,
        {
            "requirements.txt": "Pillow\npgpy\npip-upgrader\n",
            "app.py": "logo = 'logo.jpg'\n# upgrade the schema\n",
        },
    )
    assert "PostgreSQL" not in arch["datastores"]


def test_real_postgres_dependencies_are_detected(tmp_path):
    for deps in ("psycopg2-binary==2.9\n", "pg8000\n"):
        arch = _arch(tmp_path, {"requirements.txt": deps})
        assert "PostgreSQL" in arch["datastores"], deps


def test_node_pg_package_is_detected(tmp_path):
    arch = _arch(tmp_path, {"package.json": '{"dependencies": {"pg": "^8.11.0"}}'})
    assert "PostgreSQL" in arch["datastores"]
