"""Read-only host posture assessment (spec §23)."""

from __future__ import annotations

import platform
import socket
import subprocess
from datetime import datetime, timezone
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


def _listening_ports() -> list[tuple[int, str]]:
    ports: list[tuple[int, str]] = []
    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.check_output(
                ["netstat", "-an"], text=True, timeout=15, stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                if "LISTENING" not in line.upper():
                    continue
                parts = line.split()
                if len(parts) >= 2 and ":" in parts[1]:
                    try:
                        port = int(parts[1].rsplit(":", 1)[-1])
                        ports.append((port, parts[1]))
                    except ValueError:
                        continue
        else:
            out = subprocess.check_output(
                ["ss", "-tln"], text=True, timeout=15, stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines()[1:]:
                if "LISTEN" not in line:
                    continue
                addr = line.split()[-1]
                if ":" in addr:
                    try:
                        port = int(addr.rsplit(":", 1)[-1])
                        ports.append((port, addr))
                    except ValueError:
                        continue
    except (OSError, subprocess.SubprocessError, FileNotFoundError):
        try:
            out = subprocess.check_output(
                ["netstat", "-an"], text=True, timeout=15, stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                if "LISTEN" not in line.upper():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    local = parts[1] if system == "windows" else parts[3]
                    if ":" in local:
                        try:
                            port = int(local.rsplit(":", 1)[-1])
                            ports.append((port, local))
                        except ValueError:
                            continue
        except (OSError, subprocess.SubprocessError):
            return []
    return ports


def _check_ssh_config(findings: list[Finding]) -> None:
    candidates = [
        "/etc/ssh/sshd_config",
        "C:/ProgramData/ssh/sshd_config",
    ]
    for path in candidates:
        p = __import__("pathlib").Path(path)
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith("permitrootlogin yes"):
                findings.append(_finding(
                    "host.ssh-root-login",
                    "SSH permits root login",
                    "Direct root SSH increases blast radius on credential compromise.",
                    "Set PermitRootLogin no in sshd_config.",
                    Severity.HIGH,
                    path,
                    stripped,
                ))
            if stripped.startswith("passwordauthentication yes"):
                findings.append(_finding(
                    "host.ssh-password-auth",
                    "SSH password authentication enabled",
                    "Password auth is weaker than key-based auth for server access.",
                    "Prefer PubkeyAuthentication and disable PasswordAuthentication.",
                    Severity.MEDIUM,
                    path,
                    stripped,
                ))
        break


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
        passwd = __import__("pathlib").Path("/etc/passwd")
        if passwd.is_file():
            lines = [ln for ln in passwd.read_text(encoding="utf-8", errors="replace").splitlines()
                     if ln and not ln.startswith("#")]
            uid0 = [ln.split(":")[0] for ln in lines if ln.split(":")[2] == "0"]
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

    sensitive_ports = {22, 3389, 445, 3306, 5432, 6379, 27017}
    seen: set[int] = set()
    for port, addr in _listening_ports():
        if port in seen:
            continue
        seen.add(port)
        if port in sensitive_ports or port == 0:
            sev = Severity.HIGH if port in {22, 3389, 445} else Severity.MEDIUM
            findings.append(_finding(
                "host.open-listener",
                f"Service listening on port {port}",
                f"Port {port} is open ({addr}). Verify exposure is intentional.",
                "Bind to localhost or restrict via firewall if not required externally.",
                sev,
                f"host:port/{port}",
                addr,
            ))

    _check_ssh_config(findings)
    _check_local_users(findings)
    _check_os_packages(findings)

    return ScanResult(
        target=f"host:{hostname}",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        findings=findings,
        project_summary=meta,
        scanners_run=["host"],
    )
