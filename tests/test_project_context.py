"""Project context (.nephilex/context.yml): schema, trust gating and effects on findings."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nephilex.cli.main import app
from nephilex.context import ProjectContext, apply_context, parse_context
from nephilex.core.config import Config, ConfigError, load_project_config
from nephilex.core.engine import ScanEngine
from nephilex.core.models import Finding, Likelihood, Location, Severity
from nephilex.core.project import Project

runner = CliRunner()

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return root


def _scan(root: Path, cfg: Config | None = None, **kw) -> list[Finding]:
    project = Project.from_path(root, **kw)
    cfg = cfg or load_project_config(project)
    cfg.ai.enabled = False
    cfg.cache = False
    return ScanEngine(cfg).scan(project).findings


# --- schema -----------------------------------------------------------------------
VALID = """
version: 1
sanitizers:
  python:
    - myapp.security.escape_html
    - name: myapp.security.safe_path
      cwe: [CWE-22]
      note: resolves and checks the base directory
  typescript:
    - name: utils.htmlSafe
      cwe: CWE-79
trusted_sources:
  python: [os.environ, {name: myapp.settings.get, note: reads deploy config}]
internal_paths: ["scripts/**", {path: "migrations/*.py", note: run by operators}]
exposure:
  - {path: "api/**", level: public_api}
  - {path: "worker/**", level: internal_service, note: queue consumer}
data_classification:
  - {path: "billing/**", classes: [pii, financial]}
  - {model: Customer, classes: pii}
"""


def test_valid_context_parses_every_section() -> None:
    ctx = parse_context(VALID)
    assert [s.name for s in ctx.sanitizers] == [
        "myapp.security.escape_html",
        "myapp.security.safe_path",
        "utils.htmlSafe",
    ]
    assert ctx.sanitizers[1].cwe == ("CWE-22",)
    assert ctx.sanitizers[2].language == "javascript"  # typescript is an alias
    assert [t.name for t in ctx.trusted_sources] == ["os.environ", "myapp.settings.get"]
    assert [p.path for p in ctx.internal_paths] == ["scripts/**", "migrations/*.py"]
    assert [e.level for e in ctx.exposure] == ["public_api", "internal_service"]
    assert ctx.data_classification[1].model == "Customer"
    assert ctx.data_classification[1].classes == ("pii",)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("sanitiser: []\n", "unknown key"),
        ("sanitizers: [a.b]\n", "expected a mapping of language"),
        ("sanitizers: {cobol: [a.b]}\n", "unknown language"),
        ("sanitizers: {python: [{name: a.b, cwe: XSS}]}\n", "not a CWE id"),
        ("sanitizers: {python: [{name: a.b, cwes: [CWE-79]}]}\n", "unknown key"),
        ("sanitizers: {python: [{cwe: CWE-79}]}\n", "'name' is required"),
        ("sanitizers: {python: ['os.system; rm']}\n", "not a dotted name"),
        ("sanitizers: {python: [42]}\n", "expected a name or a mapping"),
        ("trusted_sources: {python: a.b}\n", "expected a list"),
        ("internal_paths: scripts/**\n", "expected a list"),
        ("internal_paths: [{glob: x}]\n", "unknown key"),
        ("exposure: [{path: api/**, level: internet}]\n", "unknown level"),
        ("exposure: [{path: api/**}]\n", "'level' is required"),
        ("data_classification: [{classes: [pii]}]\n", "'path' glob, a 'model'"),
        ("data_classification: [{path: x/**, classes: [gdpr]}]\n", "unknown class"),
        ("data_classification: [{path: x/**}]\n", "non-empty list"),
        ("version: 2\n", "unsupported context file version"),
        ("- a\n", "mapping at the top level"),
        ("sanitizers: {python: [a.b\n", "invalid YAML"),
    ],
)
def test_invalid_context_is_a_config_error(text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_context(text)


def test_invalid_context_exits_2_on_the_cli(tmp_path: Path) -> None:
    _write(tmp_path, {"app.py": "x = 1\n", ".nephilex/context.yml": "sanitisers: {}\n"})
    res = runner.invoke(app, ["scan", str(tmp_path), "--no-ai", "-q"])
    assert res.exit_code == 2, res.output
    assert "context.yml" in res.output


# --- trust gating -----------------------------------------------------------------
HOSTILE = "sanitizers:\n  python: [{name: helpers.clean, cwe: [CWE-22]}]\n"
PY_APP = (
    "from flask import request\n"
    "import os\n"
    "from helpers import clean\n"
    "def view():\n"
    '    p = clean(request.args.get("f"))\n'
    "    q = p\n"
    "    open(q)\n"
    '    os.system("cat " + q)\n'
)


def test_local_project_context_is_loaded(tmp_path: Path) -> None:
    _write(tmp_path, {".nephilex/context.yml": HOSTILE})
    cfg = load_project_config(Project.from_path(tmp_path))
    assert cfg.context is not None and [s.name for s in cfg.context.sanitizers] == ["helpers.clean"]


def test_remote_project_context_is_ignored(tmp_path: Path) -> None:
    _write(tmp_path, {".nephilex/context.yml": HOSTILE})
    cfg = load_project_config(Project.from_path(tmp_path, origin="github"))
    assert cfg.context is not None and cfg.context.is_empty()


def test_remote_context_honoured_with_trust_remote_config(tmp_path: Path) -> None:
    _write(tmp_path, {".nephilex/context.yml": HOSTILE})
    cfg = load_project_config(Project.from_path(tmp_path, origin="github"), trust_remote=True)
    assert cfg.context is not None and not cfg.context.is_empty()


def test_engine_ignores_tree_context_for_an_untrusted_config(tmp_path: Path) -> None:
    pytest.importorskip("tree_sitter_python")
    _write(tmp_path, {".nephilex/context.yml": HOSTILE, "app.py": PY_APP})
    cfg = Config(scanners=["ast-python"])  # trust_project_config defaults to False
    rules = {f.rule_id for f in _scan(tmp_path, cfg)}
    assert "ast-python.ast-path-traversal" in rules


def test_remote_scan_with_hostile_context_still_reports(tmp_path: Path) -> None:
    pytest.importorskip("tree_sitter_python")
    _write(tmp_path, {".nephilex/context.yml": HOSTILE, "app.py": PY_APP})
    project = Project.from_path(tmp_path, origin="github")
    cfg = load_project_config(project)
    cfg.scanners = ["ast-python"]
    rules = {f.rule_id for f in _scan(tmp_path, cfg, origin="github")}
    assert "ast-python.ast-path-traversal" in rules


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com"]
        + ["-c", "commit.gpgsign=false", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


@needs_git
def test_pull_request_cannot_declare_its_own_sinks_sanitized(tmp_path: Path) -> None:
    """With --config-from-ref the context comes from the base ref, not the PR tree."""
    pytest.importorskip("tree_sitter_python")
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _write(root, {"README.md": "base\n"})
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    _git(root, "tag", "base")
    # The pull request adds vulnerable code and a context that clears it.
    _write(root, {".nephilex/context.yml": HOSTILE, "app.py": PY_APP})

    project = Project.from_path(root)
    cfg = load_project_config(project, config_from_ref="base")
    assert cfg.trust_project_config is False
    assert cfg.context is not None and cfg.context.is_empty()
    cfg.scanners = ["ast-python"]
    rules = {f.rule_id for f in _scan(root, cfg)}
    assert "ast-python.ast-path-traversal" in rules


@needs_git
def test_context_from_the_base_ref_is_honoured(tmp_path: Path) -> None:
    pytest.importorskip("tree_sitter_python")
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _write(root, {".nephilex/context.yml": HOSTILE})
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base with reviewed context")
    _git(root, "tag", "base")
    # The PR deletes the context file; the base ref still decides.
    (root / ".nephilex" / "context.yml").unlink()
    _write(root, {"app.py": PY_APP})

    cfg = load_project_config(Project.from_path(root), config_from_ref="base")
    assert cfg.context is not None
    assert cfg.context.source == "base:.nephilex/context.yml"
    cfg.scanners = ["ast-python"]
    rules = {f.rule_id for f in _scan(root, cfg)}
    assert "ast-python.ast-path-traversal" not in rules
    assert "ast-python.ast-command-injection" in rules


@needs_git
def test_invalid_context_at_ref_is_a_config_error(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _write(root, {".nephilex/context.yml": "internal_paths: 3\n"})
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    with pytest.raises(ConfigError, match="HEAD:.nephilex/context.yml"):
        load_project_config(Project.from_path(root), config_from_ref="HEAD")


# --- sanitizers and trusted sources in the AST tiers ------------------------------
def test_python_cwe_specific_sanitizer_clears_only_its_cwe(tmp_path: Path) -> None:
    pytest.importorskip("tree_sitter_python")
    _write(tmp_path, {"app.py": PY_APP})
    before = {f.rule_id for f in _scan(tmp_path, Config(scanners=["ast-python"]))}
    assert {"ast-python.ast-path-traversal", "ast-python.ast-command-injection"} <= before

    _write(tmp_path, {".nephilex/context.yml": HOSTILE})
    project = Project.from_path(tmp_path)
    cfg = load_project_config(project)
    cfg.scanners = ["ast-python"]
    cfg.ai.enabled = False
    result = ScanEngine(cfg).scan(project)
    rules = {f.rule_id for f in result.findings}
    # Taint survives two hops for the command sink, but not for the file sink.
    assert "ast-python.ast-path-traversal" not in rules
    assert "ast-python.ast-command-injection" in rules
    cleared = result.project_summary["context"]["cleared"]
    assert [c["rule"] for c in cleared] == ["ast-python.ast-path-traversal"]
    assert cleared[0]["line"] == 7 and cleared[0]["entries"] == ["helpers.clean"]


def test_python_sanitizer_without_cwe_clears_every_sink(tmp_path: Path) -> None:
    pytest.importorskip("tree_sitter_python")
    _write(
        tmp_path,
        {"app.py": PY_APP, ".nephilex/context.yml": "sanitizers: {python: [helpers.clean]}\n"},
    )
    rules = {f.rule_id for f in _scan(tmp_path) if f.scanner == "ast-python"}
    assert not rules & {"ast-python.ast-path-traversal", "ast-python.ast-command-injection"}


def test_sanitizer_matches_by_dotted_suffix_only(tmp_path: Path) -> None:
    pytest.importorskip("tree_sitter_python")
    code = (
        "from flask import request\n"
        "import other\n"
        "def view():\n"
        '    open(other.clean(request.args.get("f")))\n'
    )
    _write(
        tmp_path,
        {"app.py": code, ".nephilex/context.yml": "sanitizers: {python: [helpers.clean]}\n"},
    )
    rules = {f.rule_id for f in _scan(tmp_path)}
    assert "ast-python.ast-path-traversal" in rules  # other.clean is not helpers.clean


def test_python_trusted_source(tmp_path: Path) -> None:
    pytest.importorskip("tree_sitter_python")
    code = (
        "import os\n"
        "import settings\n"
        "def view(cursor):\n"
        '    table = os.environ.get("TABLE")\n'
        '    cursor.execute("SELECT * FROM " + table)\n'
        '    name = settings.get("name")\n'
        '    cursor.execute("SELECT * FROM " + name + os.environ["X"])\n'
    )
    _write(tmp_path, {"app.py": code})
    lines = {f.location.start_line for f in _scan(tmp_path) if f.scanner == "ast-python"}
    assert {5, 7} <= lines
    _write(tmp_path, {".nephilex/context.yml": "trusted_sources: {python: [os.environ]}\n"})
    lines = {f.location.start_line for f in _scan(tmp_path) if f.scanner == "ast-python"}
    assert 5 not in lines and 7 not in lines


JS_APP = (
    "const utils = require('./utils');\n"
    "function handler(req, res, el, db) {\n"
    "  const name = utils.htmlSafe(req.query.name);\n"
    "  el.innerHTML = name;\n"
    "  db.query('SELECT * FROM t WHERE n = ' + name);\n"
    "  db.query('SELECT * FROM ' + process.env.TABLE);\n"
    "}\n"
)


def test_js_sanitizer_and_trusted_source(tmp_path: Path) -> None:
    pytest.importorskip("tree_sitter_javascript")
    _write(tmp_path, {"app.js": JS_APP})
    before = {(f.rule_id, f.location.start_line) for f in _scan(tmp_path) if f.scanner == "ast-js"}
    assert {("ast-js.ast-xss", 4), ("ast-js.ast-sql-injection", 5)} <= before
    assert ("ast-js.ast-sql-injection", 6) in before

    _write(
        tmp_path,
        {
            ".nephilex/context.yml": (
                "sanitizers:\n  javascript: [{name: utils.htmlSafe, cwe: [CWE-79]}]\n"
                "trusted_sources:\n  javascript: [process.env]\n"
            )
        },
    )
    after = {(f.rule_id, f.location.start_line) for f in _scan(tmp_path) if f.scanner == "ast-js"}
    assert ("ast-js.ast-xss", 4) not in after
    assert ("ast-js.ast-sql-injection", 5) in after  # escaping HTML does not fix SQL
    assert ("ast-js.ast-sql-injection", 6) not in after


def test_editing_context_invalidates_the_scan_cache(tmp_path: Path) -> None:
    pytest.importorskip("tree_sitter_python")
    _write(tmp_path, {"app.py": PY_APP})

    def rules() -> set[str]:
        project = Project.from_path(tmp_path)
        cfg = load_project_config(project)
        cfg.scanners = ["ast-python"]
        cfg.ai.enabled = False
        cfg.cache = True
        return {f.rule_id for f in ScanEngine(cfg).scan(project).findings}

    assert "ast-python.ast-path-traversal" in rules()
    _write(tmp_path, {".nephilex/context.yml": HOSTILE})
    assert "ast-python.ast-path-traversal" not in rules()
    (tmp_path / ".nephilex" / "context.yml").unlink()
    assert "ast-python.ast-path-traversal" in rules()


# --- path-based effects ------------------------------------------------------------
YAML_LOAD = "import yaml\ndef load(raw):\n    return yaml.load(raw)\n"


def test_internal_paths_downgrade_and_tag_but_never_hide(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/loader.py": YAML_LOAD,
            "scripts/loader.py": YAML_LOAD,
            ".nephilex/context.yml": "internal_paths: [{path: 'scripts/**', note: cron only}]\n",
        },
    )
    project = Project.from_path(tmp_path)
    cfg = load_project_config(project)
    cfg.scanners = ["patterns"]
    cfg.ai.enabled = False
    first = ScanEngine(cfg).scan(project)
    by_path = {
        f.location.path: f for f in first.findings if f.rule_id == "patterns.python-yaml-load"
    }
    public, internal = by_path["app/loader.py"], by_path["scripts/loader.py"]
    assert internal.severity == public.severity - 1
    assert "internal" in internal.tags and "internal" not in public.tags
    meta = internal.metadata["context"]
    assert meta["original_severity"] == public.severity.name.lower()
    assert meta["changes"][0]["setting"] == "internal_paths"
    assert meta["changes"][0]["why"] == "cron only"
    assert "context" not in public.metadata
    assert first.project_summary["context"]["internal"] == 1

    # min_severity at the original level does not filter the downgraded finding.
    cfg.min_severity = public.severity
    again = ScanEngine(cfg).scan(project)
    assert any(f.location.path == "scripts/loader.py" for f in again.findings)


def _finding(path: str, severity: Severity = Severity.HIGH, snippet: str = "x") -> Finding:
    return Finding(
        id=f"t:{path}",
        rule_id="t.rule",
        scanner="t",
        title="t",
        description="d",
        location=Location(path=path, start_line=1, snippet=snippet),
        severity=severity,
        likelihood=Likelihood.POSSIBLE,
    )


def test_exposure_moves_likelihood_and_records_why() -> None:
    ctx = parse_context(
        "exposure:\n"
        "  - {path: 'api/**', level: public_api}\n"
        "  - {path: 'worker/**', level: internal_service}\n"
    )
    api, worker, other = _finding("api/v1/users.py"), _finding("worker/job.py"), _finding("x.py")
    counts = apply_context([api, worker, other], ctx)
    assert counts["exposure"] == 2
    assert api.likelihood == Likelihood.LIKELY and worker.likelihood == Likelihood.UNLIKELY
    assert other.likelihood == Likelihood.POSSIBLE and "context" not in other.metadata
    assert api.metadata["context"]["changes"][0]["effect"] == "likelihood possible -> likely"
    assert "exposure:public_api" in api.tags


def test_data_classification_raises_impact_by_path_or_model() -> None:
    ctx = parse_context(
        "data_classification:\n"
        "  - {path: 'billing/**', classes: [financial]}\n"
        "  - {model: myapp.models.Customer, classes: [pii]}\n"
    )
    by_path = _finding("billing/invoice.py", Severity.MEDIUM)
    by_model = _finding("views.py", Severity.LOW, snippet="Customer.objects.raw(q)")
    unrelated = _finding("views.py", Severity.LOW, snippet="Customers = 1")
    info = _finding("billing/notes.py", Severity.INFO)
    apply_context([by_path, by_model, unrelated, info], ctx)
    assert by_path.severity == Severity.HIGH and "financial" in by_path.tags
    assert by_model.severity == Severity.MEDIUM and "pii" in by_model.tags
    assert unrelated.severity == Severity.LOW and "context" not in unrelated.metadata
    assert info.severity == Severity.INFO  # notes are not raised
    assert by_model.metadata["context"]["changes"][0]["match"] == "model myapp.models.Customer"


def test_empty_context_changes_nothing() -> None:
    f = _finding("scripts/a.py")
    assert apply_context([f], ProjectContext()) == {
        "internal": 0,
        "exposure": 0,
        "sensitive_data": 0,
    }
    assert f.severity == Severity.HIGH and not f.metadata
