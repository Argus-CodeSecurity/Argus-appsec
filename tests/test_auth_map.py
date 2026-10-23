"""Endpoint authorization map: ordering, per-language routes, route windows."""

from __future__ import annotations

from pathlib import Path

from nephilex.analysis.auth_map import build_auth_map
from nephilex.core.project import Project


def _map(tmp_path: Path, files: dict[str, str]):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return build_auth_map(Project.from_path(tmp_path))


def test_entries_are_ordered_high_medium_low(tmp_path):
    entries = _map(
        tmp_path,
        {
            "app.py": (
                "@app.get('/public')\n"
                "def a(): pass\n"
                "\n"
                "@app.get('/admin')\n"
                "def b(): pass\n"
                "\n"
                "@app.get('/me')\n"
                "@login_required\n"
                "def c(): pass\n"
            )
        },
    )
    assert [e.risk for e in entries] == ["HIGH", "MEDIUM", "LOW"]


def test_express_pattern_not_applied_to_python(tmp_path):
    entries = _map(
        tmp_path,
        {
            "client.py": (
                "import requests\nresp = requests.get('/api/users')\ncache.get('/admin')\n"
            )
        },
    )
    assert entries == []


def test_express_routes_only_on_router_receivers(tmp_path):
    entries = _map(
        tmp_path,
        {
            "server.js": (
                "const r = axios.get('/admin/users');\n"
                "app.get('/admin/users', requireAuth, (req, res) => {\n"
                "  res.send('ok');\n"
                "});\n"
                "router.post('/billing', (req, res) => res.send('x'));\n"
            )
        },
    )
    by_path = {e.path: e for e in entries}
    assert set(by_path) == {"/admin/users", "/billing"}
    assert by_path["/admin/users"].authentication == "required"
    assert by_path["/billing"].authentication == "missing"


def test_auth_on_neighbouring_route_does_not_leak(tmp_path):
    entries = _map(
        tmp_path,
        {
            "app.py": (
                "@app.get('/admin/a')\n"
                "@login_required\n"
                "def a():\n"
                "    return 1\n"
                "@app.get('/admin/b')\n"
                "def b():\n"
                "    return 2\n"
            )
        },
    )
    by_path = {e.path: e for e in entries}
    assert by_path["/admin/a"].authentication == "required"
    assert by_path["/admin/b"].authentication == "missing"


def test_fastapi_dependency_in_signature_counts_as_auth(tmp_path):
    entries = _map(
        tmp_path,
        {
            "api.py": (
                "@router.get('/users/me')\n"
                "async def me(\n"
                "    user = Depends(get_current_user),\n"
                "):\n"
                "    return user\n"
            )
        },
    )
    assert entries[0].authentication == "required"
