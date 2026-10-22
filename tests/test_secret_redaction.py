"""Secrets never reach a report in clear.

Finding snippets are copied into SARIF uploads and PR comments, which are
public on fork pull requests. Every secret-type rule must mask every secret on
the line it reports, not only the value that made the rule fire, and every
match on a line must be reported.
"""

from __future__ import annotations

from pathlib import Path

from argus.core.config import Config
from argus.core.plugin import ScannerContext
from argus.core.project import Project
from argus.scanners._text import MAX_SCAN_LINE
from argus.scanners.cicd import CicdScanner
from argus.scanners.container import ContainerScanner
from argus.scanners.secrets import SecretsScanner, redact_line

# Built at runtime so this file does not itself contain token-shaped literals.
GH_1 = "ghp_" + "A1b2C3d4E5" * 4
GH_2 = "ghp_" + "Z9y8X7w6V5" * 4
AWS_ID = "AKIA" + "Q7RT2LMX9PZK4HNB"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYzQ8vLm3kWd"
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"


def _ctx(tmp_path: Path, files: dict[str, str]) -> ScannerContext:
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return ScannerContext(project=Project.from_path(tmp_path), config=Config())


def _assert_clean(findings, *secrets: str) -> None:
    assert findings, "expected findings"
    for finding in findings:
        dumped = finding.model_dump_json()
        for secret in secrets:
            assert secret not in dumped, f"{finding.rule_id} leaks {secret[:6]}..."


def test_aws_key_id_and_secret_on_one_line_are_both_masked(tmp_path):
    line = f'creds = {{"aws_access_key_id": "{AWS_ID}", "aws_secret_access_key": "{AWS_SECRET}"}}\n'
    findings = list(SecretsScanner().scan(_ctx(tmp_path, {"config.py": line})))
    rules = {f.rule_id for f in findings}
    assert {"secrets.aws-access-key-id", "secrets.aws-secret-access-key"} <= rules
    _assert_clean(findings, AWS_ID, AWS_SECRET)


def test_every_token_on_a_line_is_reported_and_masked(tmp_path):
    line = f"TOKENS = ['{GH_1}', '{GH_2}']\n"
    findings = list(SecretsScanner().scan(_ctx(tmp_path, {"tokens.py": line})))
    gh = [f for f in findings if f.rule_id == "secrets.github-token"]
    assert len(gh) == 2
    _assert_clean(findings, GH_1, GH_2)


def test_entropy_finding_masks_signature_on_same_line(tmp_path):
    line = f'api_key = "Zq8Lr2Vx9Tn4Wb7Kc1Mf"; stripe = "{STRIPE}"\n'
    findings = list(SecretsScanner().scan(_ctx(tmp_path, {"settings.py": line})))
    assert any(f.rule_id == "secrets.high-entropy-string" for f in findings)
    _assert_clean(findings, "Zq8Lr2Vx9Tn4Wb7Kc1Mf", STRIPE)


def test_secret_on_long_line_is_reported_once_and_masked(tmp_path):
    # Lands inside the overlap of the first two windows.
    line = "x" * (MAX_SCAN_LINE - 100) + f" {GH_1} " + "y" * MAX_SCAN_LINE + "\n"
    findings = list(SecretsScanner().scan(_ctx(tmp_path, {"bundle.js": line})))
    gh = [f for f in findings if f.rule_id == "secrets.github-token"]
    assert len(gh) == 1
    _assert_clean(findings, GH_1)


def test_cicd_hardcoded_secret_snippet_is_masked(tmp_path):
    wf = (
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n"
        "      password: hunter2hunter2\n"
        f'      api_key: "{STRIPE}"\n'
    )
    findings = [
        f
        for f in CicdScanner().scan(_ctx(tmp_path, {".github/workflows/ci.yml": wf}))
        if f.rule_id == "cicd.hardcoded-secret"
    ]
    assert len(findings) == 2
    _assert_clean(findings, "hunter2hunter2", STRIPE)


def test_container_env_secrets_are_masked(tmp_path):
    files = {
        "docker-compose.yml": (
            "services:\n  db:\n    image: postgres:16\n"
            "    environment:\n"
            "      - POSTGRES_PASSWORD=S3cr3tValue99\n"
            f"      - GITHUB_TOKEN={GH_1}\n"
        ),
        "Dockerfile": "FROM python:3.12\nENV API_KEY=QkF4cTk3dmJ2OGxM\nUSER app\n",
        "helm/values.yaml": "db:\n  password: Pa55w0rdFromHelm\n",
    }
    findings = list(ContainerScanner().scan(_ctx(tmp_path, files)))
    rules = {f.rule_id for f in findings}
    assert {
        "container.env-secret",
        "container.dockerfile-env-secret",
        "container.helm-values-secret",
    } <= rules
    _assert_clean(findings, "S3cr3tValue99", GH_1, "QkF4cTk3dmJ2OGxM", "Pa55w0rdFromHelm")


def test_redact_line_keeps_context_and_masks_values():
    out = redact_line(f'headers = {{"Authorization": "Bearer {GH_2}"}}  # {AWS_ID}')
    assert GH_2 not in out and AWS_ID not in out
    assert out.startswith('headers = {"Authorization": "')
    assert redact_line("x = compute(1, 2)") == "x = compute(1, 2)"
    masked = redact_line("db_password: 'correct horse battery staple'")
    assert "horse" not in masked and masked.startswith("db_password: '")
