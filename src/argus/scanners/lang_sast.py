"""Additional SAST rules for Java, PHP, Ruby, Rust, C/C++ (spec §4)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from argus.core.models import Confidence, Finding, Likelihood, Location, Remediation, Severity
from argus.core.plugin import Scanner, ScannerContext, scanner

_RULES: dict[str, list[tuple[str, re.Pattern, str, Severity, str]]] = {
    ".java": [
        ("lang.java.sql-stmt", re.compile(r'Statement\s*\.\s*execute(?:Query|Update)?\s*\(\s*[^)]*\+'),
         "SQL built via string concatenation", Severity.HIGH, "CWE-89"),
        ("lang.java.deser", re.compile(r"ObjectInputStream\s*\("),
         "Java deserialization", Severity.HIGH, "CWE-502"),
    ],
    ".php": [
        ("lang.php.shell", re.compile(r"\b(?:shell_exec|system|passthru|exec)\s*\("),
         "PHP command execution", Severity.HIGH, "CWE-78"),
        ("lang.php.sql", re.compile(r"mysql_query\s*\(\s*[^)]*\."),
         "Legacy mysql_query usage", Severity.HIGH, "CWE-89"),
    ],
    ".rb": [
        ("lang.ruby.eval", re.compile(r"\beval\s*\("),
         "Ruby eval", Severity.HIGH, "CWE-94"),
        ("lang.ruby.system", re.compile(r"\bsystem\s*\("),
         "Ruby system call", Severity.MEDIUM, "CWE-78"),
    ],
    ".rs": [
        ("lang.rust.unwrap", re.compile(r"\.unwrap\s*\(\s*\)"),
         "Rust unwrap may panic", Severity.LOW, "CWE-754"),
        ("lang.rust.unsafe", re.compile(r"\bunsafe\s*\{"),
         "Rust unsafe block", Severity.MEDIUM, "CWE-119"),
    ],
    ".cpp": [
        ("lang.cpp.strcpy", re.compile(r"\bstrcpy\s*\("),
         "Unsafe strcpy", Severity.HIGH, "CWE-120"),
        ("lang.cpp.system", re.compile(r"\bsystem\s*\("),
         "system() call", Severity.HIGH, "CWE-78"),
    ],
    ".c": [
        ("lang.c.gets", re.compile(r"\bgets\s*\("),
         "Unsafe gets()", Severity.CRITICAL, "CWE-120"),
        ("lang.c.sprintf", re.compile(r"\bsprintf\s*\("),
         "Unbounded sprintf", Severity.HIGH, "CWE-120"),
    ],
    ".go": [
        ("lang.go.sql-sprintf", re.compile(r"(?i)\.(Query|Exec)\w*\(\s*fmt\.Sprintf\("),
         "SQL via fmt.Sprintf", Severity.HIGH, "CWE-89"),
        ("lang.go.unsafe", re.compile(r"\bunsafe\.Pointer\b"),
         "Go unsafe pointer", Severity.MEDIUM, "CWE-119"),
    ],
    ".cs": [
        ("lang.csharp.sql-concat", re.compile(r"(?i)SqlCommand\s*\([^)]*\+"),
         "SQL command built with concatenation", Severity.HIGH, "CWE-89"),
        ("lang.csharp.deser", re.compile(r"BinaryFormatter\s*\("),
         "BinaryFormatter deserialization", Severity.HIGH, "CWE-502"),
    ],
    ".kt": [
        ("lang.kotlin.runtime-exec", re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("),
         "Kotlin/Java runtime exec", Severity.HIGH, "CWE-78"),
    ],
    ".swift": [
        ("lang.swift.shell", re.compile(r"Process\s*\(\)\.launch"),
         "Swift Process launch", Severity.MEDIUM, "CWE-78"),
    ],
    ".sh": [
        ("lang.shell.curl-pipe", re.compile(r"(?:curl|wget)\s+[^\n|]+\|\s*(?:ba)?sh\b"),
         "Remote script piped to shell", Severity.HIGH, "CWE-494"),
        ("lang.shell.eval-var", re.compile(r"\beval\s+[\"']?\$"),
         "Shell eval on variable", Severity.HIGH, "CWE-94"),
    ],
    ".ps1": [
        ("lang.ps1.iex", re.compile(r"\bIEX\s*\("),
         "PowerShell Invoke-Expression", Severity.HIGH, "CWE-94"),
        ("lang.ps1.download", re.compile(r"DownloadString\s*\("),
         "PowerShell remote download", Severity.MEDIUM, "CWE-494"),
    ],
}


@scanner
class LangSastScanner(Scanner):
    name = "lang-sast"
    category = "sast"
    description = "Pattern SAST for Java, PHP, Ruby, Rust, C/C++, Go, C#, Kotlin, Swift, and shell scripts."
    file_local = True

    def applies_to(self, project) -> bool:
        exts = set(_RULES)
        return any(f.suffix in exts for f in project.files())

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        for f in ctx.project.files():
            rules = _RULES.get(f.suffix)
            if not rules:
                continue
            for i, line in enumerate(f.text().splitlines(), 1):
                for rule_id, pattern, title, sev, cwe in rules:
                    if pattern.search(line):
                        yield Finding(
                            id=f"lang-sast:{rule_id}:{f.rel_path}:{i}",
                            rule_id=rule_id,
                            scanner="lang-sast",
                            title=title,
                            description=f"Pattern match in {f.rel_path}",
                            location=Location(path=f.rel_path, start_line=i, snippet=line.strip()[:200]),
                            severity=sev,
                            confidence=Confidence.MEDIUM,
                            likelihood=Likelihood.POSSIBLE,
                            cwe=[cwe],
                            why_vulnerable=title,
                            remediation=Remediation(summary="Use safe APIs and parameterized queries."),
                            tags=["sast", f.suffix.lstrip(".")],
                            metadata={"verification": "detected"},
                        )
