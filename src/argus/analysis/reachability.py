"""Import-level reachability analysis for dependency findings (experimental).

Most SCA tools flag every advisory that matches a pinned version, but a large
share of those alerts concern packages the first-party code never even imports,
noise that teaches teams to ignore the scanner. This module implements the
first tier of reachability: an **imported / not imported** verdict for Python
projects, computed from the project's own source (vendored and virtualenv
directories are already excluded by the project walker).

Deliberately heuristic and honest about it:

* It matches *top-level module names*, mapping distribution names to import
  names (``pyyaml`` → ``yaml``) via normalization plus a small alias table.
* "Imported" does **not** prove the vulnerable function is called (that is the
  call-graph tier, planned); "not imported" can be wrong for dynamic imports
  (``importlib``, plugins) or an unmapped import alias. Verdicts therefore
  annotate findings, they never suppress them.

Later tiers (symbol-level matching against OSV affected functions, call-graph
confirmation) build on this same interface.
"""

from __future__ import annotations

import re

from argus.core.project import Project

# Verdict constants (kept as plain strings so they serialize cleanly into
# Finding.metadata and JSON/SARIF reports).
IMPORTED = "imported"
NOT_IMPORTED = "not_imported"
UNKNOWN = "unknown"
POTENTIALLY_AFFECTED = "POTENTIALLY_AFFECTED"
LIKELY_AFFECTED = "LIKELY_AFFECTED"
REACHABLE = "REACHABLE"
VERIFIED = "VERIFIED"

# Distribution name -> import name(s), for the common cases where they differ.
# Only mismatches belong here; identical/normalized names are handled below.
_PYPI_IMPORT_ALIASES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "pillow": ("PIL",),
    "beautifulsoup4": ("bs4",),
    "scikit-learn": ("sklearn",),
    "scikit-image": ("skimage",),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "python-dateutil": ("dateutil",),
    "python-dotenv": ("dotenv",),
    "python-jose": ("jose",),
    "python-multipart": ("multipart",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "pycrypto": ("Crypto",),
    "psycopg2-binary": ("psycopg2",),
    "mysqlclient": ("MySQLdb",),
    "pymongo": ("pymongo", "bson", "gridfs"),
    "protobuf": ("google.protobuf",),
    "google-cloud-storage": ("google.cloud.storage",),
    "attrs": ("attr", "attrs"),
    "setuptools": ("setuptools", "pkg_resources"),
    "pyjwt": ("jwt",),
    "pyopenssl": ("OpenSSL",),
    "pyserial": ("serial",),
    "pysocks": ("socks",),
    "msgpack-python": ("msgpack",),
    "django-cors-headers": ("corsheaders",),
    "djangorestframework": ("rest_framework",),
    "flask-sqlalchemy": ("flask_sqlalchemy",),
    "gitpython": ("git",),
    "grpcio": ("grpc",),
    "ipython": ("IPython",),
    "markupsafe": ("markupsafe",),
    "tensorflow-gpu": ("tensorflow",),
    "torch": ("torch",),
}

# `import a.b.c as x, d.e` / `from a.b import c`, captures the dotted paths.
_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+(.+))", re.MULTILINE
)


def _normalize(name: str) -> str:
    """PEP 503-style normalization, with underscores (import-name flavored)."""
    return re.sub(r"[-_.]+", "_", name.strip().lower())


def collect_python_imports(project: Project) -> set[str]:
    """Top-level module names imported anywhere in first-party Python code.

    Returned names are lowercase (imports are matched case-insensitively:
    ``PIL`` and ``IPython`` should be found regardless of alias-table casing).
    """
    imports: set[str] = set()
    for f in project.files():
        if f.suffix != ".py":
            continue
        for m in _IMPORT_RE.finditer(f.text()):
            if m.group(1):  # from X[.Y] import ...
                imports.add(m.group(1).split(".")[0].lower())
            else:  # import X[.Y] [as z][, W]
                for part in m.group(2).split(","):
                    mod = part.strip().split(" as ")[0].strip()
                    if re.match(r"^[A-Za-z_][\w.]*$", mod):
                        imports.add(mod.split(".")[0].lower())
    return imports


def python_import_verdict(package: str, imports: set[str]) -> str:
    """Classify a PyPI distribution against the project's imported modules."""
    if not imports:
        # No Python source at all (e.g. a requirements.txt used for tooling):
        # an import-level verdict would be meaningless noise.
        return UNKNOWN
    candidates = _PYPI_IMPORT_ALIASES.get(package.strip().lower())
    if candidates is None:
        candidates = (_normalize(package), package.strip().lower())
    for cand in candidates:
        if cand.split(".")[0].lower() in imports:
            return IMPORTED
    return NOT_IMPORTED


def describe(verdict: str) -> str:
    """One-line, report-ready explanation of a verdict."""
    if verdict == IMPORTED:
        return (
            "Reachability (import-level, experimental): this package IS imported "
            "by first-party code, treat the advisory as actionable."
        )
    if verdict == NOT_IMPORTED:
        return (
            "Reachability (import-level, experimental): no first-party import of "
            "this package was found, likely lower priority. This does not prove "
            "safety (dynamic imports and framework hooks are not traced); the "
            "finding is kept, deprioritized rather than suppressed."
        )
    return "Reachability: could not be determined for this package."


# --- npm / JavaScript require/import reachability (experimental) ------------

_REQUIRE_RE = re.compile(
    r"""(?:require\s*\(\s*['"]([^'"]+)['"]|from\s+['"]([^'"]+)['"])""",
)


def collect_npm_imports(project: Project) -> set[str]:
    """Package names required/imported in first-party JS/TS source."""
    imports: set[str] = set()
    for f in project.files():
        if f.suffix not in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            continue
        for m in _REQUIRE_RE.finditer(f.text()):
            mod = m.group(1) or m.group(2) or ""
            if mod.startswith("."):
                continue
            if mod.startswith("@"):
                parts = mod.split("/")
                base = "/".join(parts[:2]) if len(parts) >= 2 else mod
            else:
                base = mod.split("/")[0]
            imports.add(base.lower())
    return imports


def npm_import_verdict(package: str, imports: set[str]) -> str:
    if not imports:
        return UNKNOWN
    pkg = package.strip().lower()
    if pkg in imports:
        return IMPORTED
    return NOT_IMPORTED
