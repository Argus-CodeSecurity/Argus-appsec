"""Attack-chain analysis: correlate individual findings into breach paths.

A single finding is easy to ignore; a chain is not. When several findings in the
same component compose ("untrusted input reaches a prompt, and model output reaches
a shell" or "an injection sits in the same file as a hardcoded credential"), the
combined impact is materially worse than any part, and the story is concrete
enough to act on. This upgrades Argus's claim from "explains findings" to
"explains risk".

Chains are emitted as their own findings (scanner ``chains``) that reference their
members, so they flow through every reporter without new plumbing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)

_INJECTION_CWES = {"CWE-78", "CWE-89", "CWE-95"}  # command / SQL / code injection


@dataclass
class Chain:
    id: str
    title: str
    severity: Severity
    narrative: str
    members: list[Finding]

    def to_finding(self) -> Finding:
        first = self.members[0]
        refs = "; ".join(f"{m.rule_id} ({m.location.as_ref()})" for m in self.members)
        return Finding(
            id=f"chains:{self.id}:{first.location.path}",
            rule_id=f"chains.{self.id}",
            scanner="chains",
            title=self.title,
            description=f"{self.narrative}\n\nChained findings: {refs}",
            location=Location(path=first.location.path, start_line=first.location.start_line),
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            likelihood=Likelihood.LIKELY,
            cwe=sorted({c for m in self.members for c in m.cwe}),
            owasp=sorted({o for m in self.members for o in m.owasp}),
            why_vulnerable=self.narrative,
            attacker_perspective=(
                "Individually these findings look moderate; chained, each one enables "
                "the next, so an attacker can walk the entire path from untrusted input "
                "to impact."
            ),
            business_impact=(
                "Compounded impact: the chain reaches a materially worse outcome than "
                "any single finding in it."
            ),
            remediation=Remediation(
                summary="Break the chain: fixing any one link stops this path, fix all for defense in depth.",
                guidance=(
                    "Breaking the weakest link is enough to stop this specific path, but "
                    "address every chained finding so a variant cannot re-open it."
                ),
            ),
            tags=["attack-chain", self.id],
            metadata={"chain_members": [m.rule_id for m in self.members]},
        )


def _by_file(findings: list[Finding]) -> dict[str, list[Finding]]:
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.location.path, []).append(f)
    return groups


def find_chains(findings: list[Finding]) -> list[Chain]:
    """Return the attack chains formed by the given findings (may be empty)."""
    chains: list[Chain] = []
    chains.extend(_file_local_chains(findings))
    chains.extend(_cross_file_chains(findings))
    return chains


def _file_local_chains(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for fs in _by_file(findings).values():
        # LLM: untrusted input -> prompt -> model output -> execution/tool.
        prompt_injection = [f for f in fs if f.rule_id.endswith("prompt-injection")]
        # The "execution" link is the LLM insecure-output rule, an excessive-agency
        # tool, or (when the taint tier deduped the LLM rule into its own) any
        # code/command-execution finding in the same component.
        exec_links = [
            f for f in fs
            if not f.rule_id.endswith("prompt-injection")
            and ("insecure-output" in f.rule_id or "agent-shell" in f.rule_id
                 or "unrestricted-tool" in f.rule_id or {"CWE-78", "CWE-95"} & set(f.cwe))
        ]
        if prompt_injection and exec_links:
            chains.append(Chain(
                id="llm-injection-to-execution",
                title="Attack chain: prompt injection reaches code/command execution",
                severity=Severity.CRITICAL,
                narrative=(
                    "This component both accepts untrusted input into a prompt (LLM01) "
                    "and routes model output into a dangerous sink or an "
                    "execution-capable tool (LLM02/LLM08). An attacker who controls the "
                    "input can steer the model to emit a payload that then executes, "
                    "turning prompt injection into remote code or command execution."
                ),
                members=prompt_injection[:1] + exec_links[:1],
            ))

        # Injection foothold sitting beside a hardcoded credential.
        secrets = [f for f in fs if f.scanner == "secrets" and "history" not in f.rule_id]
        injections = [f for f in fs if _INJECTION_CWES & set(f.cwe)]
        if secrets and injections:
            chains.append(Chain(
                id="secret-plus-injection",
                title="Attack chain: injection foothold beside an exposed credential",
                severity=Severity.HIGH,
                narrative=(
                    "This component contains both a hardcoded credential and an "
                    "injection vulnerability. An attacker exploiting the injection gains "
                    "code or query execution in the very component that holds the "
                    "secret, so a single foothold yields both execution and a credential "
                    "for lateral movement."
                ),
                members=secrets[:1] + injections[:1],
            ))
    return chains


_SSRF_CWE = {"CWE-918"}
_CLOUD_SECRET = re.compile(r"(AWS_|AKIA|aws_secret|gcp|azure|metadata\.google)", re.I)


def _cross_file_chains(findings: list[Finding]) -> list[Chain]:
    """Correlate findings across files into multi-step attack paths."""
    chains: list[Chain] = []
    ssrf = [f for f in findings if _SSRF_CWE & set(f.cwe)]
    cloud_secrets = [
        f for f in findings
        if f.scanner == "secrets" and f.location.snippet
        and _CLOUD_SECRET.search(f.location.snippet)
    ]
    if ssrf and cloud_secrets:
        chains.append(Chain(
            id="ssrf-to-cloud-credentials",
            title="Attack chain: SSRF toward cloud credential exposure",
            severity=Severity.CRITICAL,
            narrative=(
                "The project contains SSRF (server-side request forgery) and exposed "
                "cloud credentials. SSRF can reach instance metadata endpoints "
                "(169.254.169.254) to steal IAM tokens, compounding secret exposure."
            ),
            members=ssrf[:1] + cloud_secrets[:1],
        ))

    kev_deps = [
        f for f in findings
        if f.scanner == "dependencies" and f.metadata.get("kev")
    ]
    reachable = [
        f for f in kev_deps
        if f.metadata.get("reachability") == "imported"
    ]
    if kev_deps and reachable:
        chains.append(Chain(
            id="kev-reachable-dependency",
            title="Attack chain: KEV-listed CVE in a reachable dependency",
            severity=Severity.CRITICAL,
            narrative=(
                "A dependency with a CVE on CISA's Known Exploited Vulnerabilities "
                "catalog is imported by first-party code. This combines confirmed "
                "in-the-wild exploitation with likely application reachability."
            ),
            members=reachable[:1],
        ))

    malicious = [f for f in findings if f.rule_id == "supply-chain.known-malicious"]
    dep_diff = [f for f in findings if f.scanner == "dependency-diff"]
    if malicious and dep_diff:
        chains.append(Chain(
            id="malicious-dependency-in-diff",
            title="Attack chain: malicious package introduced in dependency change",
            severity=Severity.CRITICAL,
            narrative=(
                "A dependency change in this revision introduces a package flagged "
                "as malicious. This is a direct supply-chain compromise in the "
                "merge path."
            ),
            members=dep_diff[:1] + malicious[:1],
        ))

    public_iac = [
        f for f in findings
        if f.scanner == "iac" and "public" in f.rule_id.lower()
    ]
    missing_auth = [f for f in findings if f.rule_id == "authz.missing-authentication"]
    if public_iac and missing_auth:
        chains.append(Chain(
            id="exposed-service-unauthenticated",
            title="Attack chain: exposed infrastructure with unauthenticated API",
            severity=Severity.CRITICAL,
            narrative=(
                "Infrastructure misconfiguration exposes a service publicly while "
                "application routes lack authentication, allowing direct "
                "internet-to-privileged-function access."
            ),
            members=public_iac[:1] + missing_auth[:1],
        ))

    return chains
