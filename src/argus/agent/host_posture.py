"""Read-only host posture assessment (spec §23)."""

from __future__ import annotations

import glob
import ipaddress
import platform
import re
import socket
import subprocess
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    ScanResult,
    Severity,
)


def _finding(
    rule: str,
    title: str,
    why: str,
    fix: str,
    severity: Severity,
    path: str,
    snippet: str = "",
) -> Finding:
    return Finding(
        id=f"host:{rule}:{path}",
        rule_id=rule,
        scanner="host",
        title=title,
        description=why,
        location=Location(path=path, snippet=snippet[:200] or path),
        severity=severity,
        confidence=Confidence.HIGH,
        likelihood=Likelihood.POSSIBLE,
        cwe=["CWE-284"],
        owasp=["A05:2021-Security Misconfiguration"],
        why_vulnerable=why,
        remediation=Remediation(summary=fix, guidance=fix),
        tags=["host", "posture"],
        metadata={"verification": "detected"},
    )


def split_host_port(addr: str) -> tuple[str, int] | None:
    """Parse a listener address from ss/netstat into (host, port).

    Handles ``0.0.0.0:22``, ``*:22``, ``[::]:22``, ``:::22``,
    ``127.0.0.53%lo:53`` (ss/Linux and Windows netstat) and ``*.22``,
    ``127.0.0.1.5432`` (BSD/macOS netstat).
    """
    addr = addr.strip()
    if addr.startswith("["):
        host, sep, port = addr[1:].partition("]:")
        if not sep:
            return None
    else:
        host, port = "", ""
        for sep in (":", "."):
            if sep in addr:
                host, port = addr.rsplit(sep, 1)
                if port.isdigit():
                    break
    if not port.isdigit():
        return None
    return host.split("%", 1)[0], int(port)


def bind_scope(host: str) -> str:
    """Classify a listener's bind address: ``wildcard``, ``loopback`` or ``interface``."""
    h = host.strip("[]").split("%", 1)[0].lower()
    if h in ("", "*", "0.0.0.0", "::"):
        return "wildcard"
    if h == "localhost":
        return "loopback"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return "interface"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        return "wildcard"
    if ip.is_loopback:
        return "loopback"
    return "interface"


def parse_listeners(output: str, local_column: int) -> list[tuple[int, str]]:
    """Extract (port, local address) of LISTEN sockets from ss/netstat output."""
    ports: list[tuple[int, str]] = []
    for line in output.splitlines():
        if "LISTEN" not in line.upper():
            continue
        parts = line.split()
        if len(parts) <= local_column:
            continue
        local = parts[local_column]
        parsed = split_host_port(local)
        if parsed is not None:
            ports.append((parsed[1], local))
    return ports


def _listening_ports() -> list[tuple[int, str]]:
    system = platform.system().lower()
    # (command, column holding the *local* address). ss prints
    # "State Recv-Q Send-Q Local Peer"; Linux/BSD netstat prints
    # "Proto Recv-Q Send-Q Local Foreign State"; Windows netstat prints
    # "Proto Local Foreign State".
    if system == "windows":
        attempts = [(["netstat", "-an"], 1)]
    else:
        attempts = [(["ss", "-tln"], 3), (["netstat", "-an"], 3)]
    for cmd, column in attempts:
        try:
            out = subprocess.check_output(
                cmd, text=True, timeout=15, stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        return parse_listeners(out, column)
    return []


_SSHD_CANDIDATES = (
    "/etc/ssh/sshd_config",
    "C:/ProgramData/ssh/sshd_config",
)
_MAX_INCLUDE_DEPTH = 4
_MAX_SSHD_FILES = 32
_DIRECTIVE = re.compile(r"^(\w+)(?:\s*=\s*|\s+)(.*)$")


class _SshdReader:
    """Collect global sshd_config directives, sshd-style.

    First value wins, ``Include`` globs are followed in place (relative paths
    are resolved against the main config's directory, bounded in depth and
    file count), and reading stops at the first ``Match`` block, whose
    settings are conditional. Unreadable files are recorded, not raised.
    """

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.values: dict[str, tuple[str, str, str]] = {}  # key -> (value, file, line)
        self.unreadable: list[tuple[str, str]] = []
        self.files_read = 0

    def read(self, path: Path, depth: int = 0) -> bool:
        """Process ``path``; returns False once a Match block ends global scope."""
        if self.files_read >= _MAX_SSHD_FILES:
            return True
        self.files_read += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.unreadable.append((str(path), exc.strerror or exc.__class__.__name__))
            return True
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = _DIRECTIVE.match(line)
            if not m:
                continue
            key, value = m.group(1).lower(), m.group(2).strip()
            if key == "match":
                return False
            if key == "include":
                if depth >= _MAX_INCLUDE_DEPTH:
                    continue
                for pattern in value.split():
                    full = pattern if Path(pattern).is_absolute() else str(self.base_dir / pattern)
                    for inc in sorted(glob.glob(full))[:_MAX_SSHD_FILES]:
                        # A Match inside an included file ends at that file.
                        self.read(Path(inc), depth + 1)
                continue
            self.values.setdefault(key, (value, str(path), line))
        return True


def _check_ssh_config(findings: list[Finding]) -> None:
    for candidate in _SSHD_CANDIDATES:
        p = Path(candidate)
        try:
            if not p.is_file():
                continue
        except OSError:
            continue
        reader = _SshdReader(p.parent)
        reader.read(p)
        for path, error in reader.unreadable:
            findings.append(_finding(
                "host.ssh-config-unreadable",
                "SSH server configuration could not be read",
                f"Argus could not read {path} ({error}), so SSH hardening was not checked.",
                "Run the agent with read access to the sshd configuration "
                "(for example as root or via a group with read permission).",
                Severity.INFO,
                path,
                error,
            ))
        root = reader.values.get("permitrootlogin")
        if root and root[0].lower() == "yes":
            findings.append(_finding(
                "host.ssh-root-login",
                "SSH permits root login",
                "Direct root SSH increases blast radius on credential compromise.",
                "Set PermitRootLogin no in sshd_config.",
                Severity.HIGH,
                root[1],
                root[2],
            ))
        pwd = reader.values.get("passwordauthentication")
        if pwd and pwd[0].lower() == "yes":
            findings.append(_finding(
                "host.ssh-password-auth",
                "SSH password authentication enabled",
                "Password auth is weaker than key-based auth for server access.",
                "Prefer PubkeyAuthentication and disable PasswordAuthentication.",
                Severity.MEDIUM,
                pwd[1],
                pwd[2],
            ))
        break


_PASSWD = Path("/etc/passwd")
_SENSITIVE_PORTS = {22, 3389, 445, 3306, 5432, 6379, 27017}
_REMOTE_ADMIN_PORTS = {22, 3389, 445}


def _check_listeners(findings: list[Finding]) -> None:
    # A sensitive service bound only to loopback is not reachable from the
    # network, so it is not reported. Wildcard and specific-interface binds are.
    seen: set[int] = set()
    for port, addr in _listening_ports():
        parsed = split_host_port(addr)
        scope = bind_scope(parsed[0]) if parsed else "interface"
        if scope == "loopback" or port in seen:
            continue
        if port not in _SENSITIVE_PORTS:
            continue
        seen.add(port)
        sev = Severity.HIGH if port in _REMOTE_ADMIN_PORTS else Severity.MEDIUM
        where = "all interfaces" if scope == "wildcard" else "a network interface"
        finding = _finding(
            "host.open-listener",
            f"Service listening on port {port}",
            f"Port {port} is open on {where} ({addr}). Verify exposure is intentional.",
            "Bind to localhost or restrict via firewall if not required externally.",
            sev,
            f"host:port/{port}",
            addr,
        )
        finding.metadata["bind_scope"] = scope
        findings.append(finding)


def _check_local_users(findings: list[Finding]) -> None:
    system = platform.system().lower()
    if system == "windows":
        try:
            out = subprocess.check_output(
                ["net", "user"], text=True, timeout=15, stderr=subprocess.DEVNULL,
            )
            if "Administrator" in out and "Guest" in out:
                findings.append(_finding(
                    "host.local-accounts",
                    "Review local user accounts",
                    "Default or excessive local accounts increase lateral movement risk.",
                    "Disable unused accounts and enforce strong local admin policy.",
                    Severity.LOW,
                    "host:accounts",
                    out.splitlines()[0] if out else "",
                ))
        except (OSError, subprocess.SubprocessError):
            pass
        return
    try:
        passwd = _PASSWD
        if passwd.is_file():
            rows = [ln.split(":") for ln in passwd.read_text(encoding="utf-8", errors="replace").splitlines()
                    if ln and not ln.startswith("#")]
            uid0 = [row[0] for row in rows if len(row) >= 3 and row[2].strip() == "0"]
            if len(uid0) > 1:
                findings.append(_finding(
                    "host.multiple-uid0",
                    "Multiple UID 0 accounts detected",
                    f"Accounts with root privileges: {', '.join(uid0[:5])}",
                    "Limit UID 0 to a single audited root account.",
                    Severity.HIGH,
                    "/etc/passwd",
                    ",".join(uid0[:3]),
                ))
    except OSError:
        pass


def _check_os_packages(findings: list[Finding]) -> None:
    system = platform.system().lower()
    if system != "linux":
        return
    for cmd, label in (
        (["dpkg", "-l"], "dpkg"),
        (["rpm", "-qa"], "rpm"),
    ):
        try:
            out = subprocess.check_output(cmd, text=True, timeout=20, stderr=subprocess.DEVNULL)
            if "openssh-server" in out.lower() and "openssh-client" in out.lower():
                meta = f"{label}: openssh present"
                findings.append(_finding(
                    "host.ssh-packages",
                    "OpenSSH packages installed",
                    "Verify SSH hardening and patch level for installed OpenSSH packages.",
                    "Keep OpenSSH updated and restrict sshd_config.",
                    Severity.LOW,
                    f"host:packages/{label}",
                    meta,
                ))
            break
        except (OSError, subprocess.SubprocessError, FileNotFoundError):
            continue


def assess_host(*, label: str | None = None) -> ScanResult:
    """Collect read-only host posture findings. Never modifies the system."""
    hostname = label or socket.gethostname()
    findings: list[Finding] = []
    meta: dict[str, Any] = {
        "hostname": hostname,
        "platform": platform.platform(),
        "python": platform.python_version(),
    }

    checks: list[tuple[str, Callable[[list[Finding]], None]]] = [
        ("listeners", _check_listeners),
        ("ssh-config", _check_ssh_config),
        ("local-users", _check_local_users),
        ("os-packages", _check_os_packages),
    ]
    for name, check in checks:
        try:
            check(findings)
        except Exception as exc:  # one broken check must not sink the others
            findings.append(_finding(
                "host.check-failed",
                f"Host check '{name}' could not run",
                f"The {name} check failed with {exc.__class__.__name__}: {exc}",
                "Check the agent's permissions and logs on this host.",
                Severity.INFO,
                f"host:check/{name}",
                str(exc),
            ))

    return ScanResult(
        target=f"host:{hostname}",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        findings=findings,
        project_summary=meta,
        scanners_run=["host"],
    )
