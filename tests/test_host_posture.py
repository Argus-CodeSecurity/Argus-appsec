"""Host posture: listener parsing, sshd_config parsing and check isolation."""

from __future__ import annotations

from pathlib import Path

import pytest

from nephilex.agent import host_posture
from nephilex.core.models import Severity

SS_OUTPUT = """\
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
LISTEN 0      244        127.0.0.1:5432       0.0.0.0:*
LISTEN 0      511     127.0.0.53%lo:53        0.0.0.0:*
LISTEN 0      128             [::]:3389          [::]:*
LISTEN 0      128        10.0.0.5:6379       0.0.0.0:*
"""


def test_ss_output_uses_local_address_column():
    ports = host_posture.parse_listeners(SS_OUTPUT, 3)
    assert [p for p, _ in ports] == [22, 5432, 53, 3389, 6379]


@pytest.mark.parametrize(
    "addr,expected",
    [
        ("0.0.0.0:22", ("0.0.0.0", 22)),
        ("*:22", ("*", 22)),
        ("[::]:22", ("::", 22)),
        (":::22", ("::", 22)),
        ("127.0.0.53%lo:53", ("127.0.0.53", 53)),
        ("*.22", ("*", 22)),
        ("127.0.0.1.5432", ("127.0.0.1", 5432)),
        ("::1.631", ("::1", 631)),
        ("0.0.0.0:*", None),
    ],
)
def test_split_host_port(addr, expected):
    assert host_posture.split_host_port(addr) == expected


def test_bind_scope():
    assert host_posture.bind_scope("0.0.0.0") == "wildcard"
    assert host_posture.bind_scope("*") == "wildcard"
    assert host_posture.bind_scope("::") == "wildcard"
    assert host_posture.bind_scope("127.0.0.1") == "loopback"
    assert host_posture.bind_scope("::1") == "loopback"
    assert host_posture.bind_scope("::ffff:127.0.0.1") == "loopback"
    assert host_posture.bind_scope("10.0.0.5") == "interface"


def test_listeners_skip_loopback_and_flag_exposed(monkeypatch):
    monkeypatch.setattr(
        host_posture, "_listening_ports", lambda: host_posture.parse_listeners(SS_OUTPUT, 3)
    )
    findings: list = []
    host_posture._check_listeners(findings)
    by_port = {f.location.path: f for f in findings}
    assert set(by_port) == {"host:port/22", "host:port/3389", "host:port/6379"}
    assert by_port["host:port/22"].severity == Severity.HIGH
    assert by_port["host:port/22"].metadata["bind_scope"] == "wildcard"
    assert by_port["host:port/6379"].metadata["bind_scope"] == "interface"


def _sshd(monkeypatch, tmp_path: Path, text: str) -> list:
    main = tmp_path / "sshd_config"
    main.write_text(text, encoding="utf-8")
    monkeypatch.setattr(host_posture, "_SSHD_CANDIDATES", (str(main),))
    findings: list = []
    host_posture._check_ssh_config(findings)
    return findings


def test_sshd_tabs_equals_and_first_match_wins(monkeypatch, tmp_path: Path):
    findings = _sshd(
        monkeypatch,
        tmp_path,
        "PermitRootLogin\tyes\nPermitRootLogin no\nPasswordAuthentication=yes\n",
    )
    rules = sorted(f.rule_id for f in findings)
    assert rules == ["host.ssh-password-auth", "host.ssh-root-login"]


def test_sshd_first_value_wins_over_later_yes(monkeypatch, tmp_path: Path):
    findings = _sshd(monkeypatch, tmp_path, "PermitRootLogin no\nPermitRootLogin yes\n")
    assert findings == []


def test_sshd_follows_include_and_stops_at_match(monkeypatch, tmp_path: Path):
    conf_d = tmp_path / "sshd_config.d"
    conf_d.mkdir()
    (conf_d / "50-cloud.conf").write_text("PasswordAuthentication yes\n", encoding="utf-8")
    findings = _sshd(
        monkeypatch,
        tmp_path,
        "Include sshd_config.d/*.conf\nMatch User backup\n    PermitRootLogin yes\n",
    )
    rules = [f.rule_id for f in findings]
    assert rules == ["host.ssh-password-auth"]
    assert findings[0].location.path.endswith("50-cloud.conf")


def test_sshd_include_loop_is_bounded(monkeypatch, tmp_path: Path):
    findings = _sshd(monkeypatch, tmp_path, "Include sshd_config\nPermitRootLogin yes\n")
    assert [f.rule_id for f in findings] == ["host.ssh-root-login"]


def test_unreadable_sshd_config_is_informational(monkeypatch, tmp_path: Path):
    main = tmp_path / "sshd_config"
    main.write_text("PermitRootLogin yes\n", encoding="utf-8")
    monkeypatch.setattr(host_posture, "_SSHD_CANDIDATES", (str(main),))
    real_read = Path.read_text

    def deny(self, *a, **kw):
        if self == main:
            raise PermissionError(13, "Permission denied")
        return real_read(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", deny)
    findings: list = []
    host_posture._check_ssh_config(findings)
    assert [f.rule_id for f in findings] == ["host.ssh-config-unreadable"]
    assert findings[0].severity == Severity.INFO


def test_short_passwd_lines_do_not_crash(monkeypatch, tmp_path: Path):
    passwd = tmp_path / "passwd"
    passwd.write_text(
        "root:x:0:0::/root:/bin/sh\nbroken\ntoor:x:0:0::/:/bin/sh\n+\n", encoding="utf-8"
    )
    monkeypatch.setattr(host_posture, "_PASSWD", passwd)
    monkeypatch.setattr(host_posture.platform, "system", lambda: "Linux")
    findings: list = []
    host_posture._check_local_users(findings)
    assert [f.rule_id for f in findings] == ["host.multiple-uid0"]


def test_failing_check_becomes_info_finding(monkeypatch):
    def boom(findings):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(host_posture, "_check_ssh_config", boom)
    monkeypatch.setattr(host_posture, "_listening_ports", lambda: [])
    result = host_posture.assess_host(label="t")
    failed = [f for f in result.findings if f.rule_id == "host.check-failed"]
    assert len(failed) == 1 and failed[0].severity == Severity.INFO
