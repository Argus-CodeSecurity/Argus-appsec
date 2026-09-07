"""Scan profiles for common use cases (spec §48)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    name: str
    scanners: list[str]
    description: str
    fail_on_error: bool = False


# Empty scanners list means "all applicable" in ScanEngine.
PROFILES: dict[str, ScanProfile] = {
    "fast": ScanProfile(
        "fast",
        ["secrets", "patterns", "malware", "dependencies"],
        "Quick CI gate: secrets, pattern SAST, direct dependency CVEs.",
    ),
    "standard": ScanProfile(
        "standard",
        [],
        "Default full scan: all applicable scanners.",
    ),
    "deep": ScanProfile(
        "deep",
        [
            "secrets", "patterns", "malware", "ast-python", "ast-python-xfile",
            "ast-js", "lang-sast", "dependencies", "dependency-diff", "supply-chain",
            "provenance", "authz", "api", "business-logic", "git-security",
            "iac", "cicd", "container", "container-image", "cloud", "llm", "dast",
        ],
        "Maximum depth: AST taint, supply chain, authz, API, infra, LLM.",
    ),
    "supply-chain": ScanProfile(
        "supply-chain",
        ["dependencies", "dependency-diff", "supply-chain", "provenance"],
        "Dependency CVEs, malicious packages, provenance, and version diffs.",
    ),
    "ci": ScanProfile(
        "ci",
        ["secrets", "patterns", "dependencies", "cicd", "iac"],
        "Pull-request gate: new risk in code, deps, and pipeline config.",
        fail_on_error=True,
    ),
    "production": ScanProfile(
        "production",
        ["secrets", "dependencies", "supply-chain", "iac", "container", "cloud", "cicd"],
        "Deployment posture: no secrets, safe deps, infra and container config.",
        fail_on_error=True,
    ),
}


def apply_profile(name: str) -> list[str]:
    key = name.strip().lower()
    if key not in PROFILES:
        known = ", ".join(sorted(PROFILES))
        raise ValueError(f"Unknown profile {name!r}. Choose from: {known}")
    return list(PROFILES[key].scanners)
