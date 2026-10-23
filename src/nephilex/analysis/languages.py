"""Language detection by file extension and a few special filenames.

Deliberately simple and fast: extension-based classification is accurate enough
to route scanners and to populate the project's language breakdown. A plugin can
provide deeper, content-based detection if a project needs it.
"""

from __future__ import annotations

# Extension -> canonical language name.
EXTENSION_MAP: dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".hh": "C++",
    ".c": "C",
    ".h": "C",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".swift": "Swift",
    ".rb": "Ruby",
    ".scala": "Scala",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".tf": "Terraform",
    ".hcl": "HCL",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".sh": "Shell",
    ".bash": "Shell",
    ".sql": "SQL",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
    ".dart": "Dart",
}

# Exact filenames that imply a language/technology regardless of extension.
FILENAME_MAP: dict[str, str] = {
    "Dockerfile": "Docker",
    "Containerfile": "Docker",
    "Makefile": "Make",
    "Gemfile": "Ruby",
    "Rakefile": "Ruby",
    "go.mod": "Go",
    "Cargo.toml": "Rust",
}


def detect_language(filename: str, suffix: str) -> str | None:
    if filename in FILENAME_MAP:
        return FILENAME_MAP[filename]
    if filename.startswith("Dockerfile"):
        return "Docker"
    return EXTENSION_MAP.get(suffix)
