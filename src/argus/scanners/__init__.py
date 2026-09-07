"""Built-in scanners.

Importing this package registers the built-in scanners with the global registry.
Each scanner is small and self-contained; they are the reference implementations
that the plugin guide points contributors at.
"""

from argus.scanners import (  # noqa: F401
    api,
    ast_js,
    ast_python,
    ast_python_interproc,
    authz,
    business_logic,
    cicd,
    cloud,
    container,
    container_image,
    dast,
    dependencies,
    dependency_diff,
    git_security,
    iac,
    lang_sast,
    llm,
    patterns,
    provenance,
    secrets,
    supply_chain,
)

__all__ = [
    "api", "ast_js", "ast_python", "ast_python_interproc", "authz", "business_logic",
    "cicd", "cloud", "container", "container_image", "dast", "dependencies",
    "dependency_diff", "git_security", "iac", "lang_sast", "llm", "patterns",
    "provenance", "secrets", "supply_chain",
]
