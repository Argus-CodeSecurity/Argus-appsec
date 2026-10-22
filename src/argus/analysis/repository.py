"""Repository analysis: build the architecture map that scanners reason against.

The analyzer performs a single pass over the project to determine:

* languages in use (by file count),
* frameworks and libraries (from manifests and import/usage signals),
* architectural facts, APIs, auth, datastores, third-party services, cloud,
  containers, CI/CD, and dependency manifests.

The result is attached to the :class:`~argus.core.project.Project` so downstream
scanners and agents can consult it instead of re-deriving it.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from argus.analysis.languages import detect_language
from argus.core.project import Project

# Bound how much source text is held for framework/API/auth signal matching.
# Per-file cap stops a few huge files dominating; the aggregate budget stops a
# monorepo of many small files from building an unbounded in-memory blob.
_PER_FILE_SOURCE_CAP = 20_000
_SOURCE_BLOB_BUDGET = 1_500_000  # ~1.5 MB of characters across the project

# --- framework signatures -------------------------------------------------
# Each entry: framework name -> (dependency-name substrings, source regexes).
# A framework is reported if any manifest dependency or any source hit matches.
_FRAMEWORK_SIGNS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "Django": (("django",), (r"\bfrom django\b", r"\bimport django\b")),
    "Flask": (("flask",), (r"\bfrom flask\b", r"Flask\(__name__\)")),
    "FastAPI": (("fastapi",), (r"\bfrom fastapi\b", r"FastAPI\(")),
    "Express": (("express",), (r"require\(['\"]express['\"]\)", r"from ['\"]express['\"]")),
    "NestJS": (("@nestjs/core",), (r"@nestjs/",)),
    "Next.js": (("next",), (r"from ['\"]next/",)),
    "React": (("react",), (r"from ['\"]react['\"]",)),
    "Vue": (("vue",), (r"from ['\"]vue['\"]",)),
    "Angular": (("@angular/core",), (r"@angular/",)),
    "Spring": (("spring-boot", "springframework"), (r"org\.springframework",)),
    "Ruby on Rails": (("rails",), (r"\bRails\b",)),
    "Laravel": (("laravel/framework",), (r"Illuminate\\\\",)),
    "Gin": (("gin-gonic/gin",), (r"gin\.(Default|New)\(",)),
    "ASP.NET": (("Microsoft.AspNetCore",), (r"Microsoft\.AspNetCore",)),
    "Actix": (("actix-web",), (r"actix_web",)),
}

# Dependency-name substrings that indicate a datastore or third-party service.
_DATASTORE_SIGNS: dict[str, tuple[str, ...]] = {
    "PostgreSQL": ("psycopg", "pg", "postgres", "pgx"),
    "MySQL": ("mysql", "mariadb", "pymysql"),
    "MongoDB": ("mongo", "mongoose", "pymongo"),
    "Redis": ("redis", "ioredis"),
    "SQLite": ("sqlite",),
    "Elasticsearch": ("elasticsearch",),
    "Kafka": ("kafka",),
}

_SERVICE_SIGNS: dict[str, tuple[str, ...]] = {
    "AWS": ("boto3", "aws-sdk", "@aws-sdk"),
    "Google Cloud": ("google-cloud", "@google-cloud"),
    "Azure": ("azure-", "@azure/"),
    "Stripe": ("stripe",),
    "Twilio": ("twilio",),
    "SendGrid": ("sendgrid",),
    "Auth0": ("auth0",),
    "Firebase": ("firebase",),
}

# Manifest files we know how to read dependency names out of.
_MANIFESTS = (
    "requirements.txt", "pyproject.toml", "Pipfile", "setup.py",
    "package.json", "go.mod", "Cargo.toml", "pom.xml", "build.gradle",
    "composer.json", "Gemfile",
)

# Common auth signals in source.
_AUTH_PATTERNS = (
    r"\bjwt\b", r"jsonwebtoken", r"passport", r"oauth", r"OAuth",
    r"@login_required", r"authorize", r"Authentication", r"bcrypt",
    r"session\[", r"Bearer ",
)


@lru_cache(maxsize=256)
def _needle_re(needle: str) -> re.Pattern[str]:
    """Match ``needle`` as the start of a dependency-name word.

    The needle must not follow a letter or digit ("pg" must not match "jpg"
    or "upgrade"). Short needles (under 5 characters) must also end the word
    ("pg" matches "pg", "pg-pool" and "pg8000" but not "pgpy"); longer ones
    may be a prefix ("psycopg" matches "psycopg2-binary").
    """
    tail = r"(?![A-Za-z])" if len(needle) < 5 else ""
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(needle) + tail)


def _has_needle(needle: str, text: str) -> bool:
    return _needle_re(needle).search(text) is not None


class RepositoryAnalyzer:
    """Single-pass analyzer that enriches a Project in place."""

    def analyze(self, project: Project) -> Project:
        languages: dict[str, int] = {}
        manifest_deps: set[str] = set()
        source_blob_parts: list[str] = []
        source_blob_used = 0
        arch: dict[str, Any] = {
            "apis": [],
            "auth": [],
            "datastores": [],
            "third_party": [],
            "cloud": [],
            "containers": [],
            "ci_cd": [],
            "dependency_manifests": [],
            "iac": [],
        }

        for f in project.files():
            lang = detect_language(f.name, f.suffix)
            if lang:
                f.language = lang
                languages[lang] = languages.get(lang, 0) + 1

            # Collect a bounded blob of source text for signal matching.
            if (
                lang
                and lang not in {"JSON", "CSS", "HTML"}
                and source_blob_used < _SOURCE_BLOB_BUDGET
            ):
                room = _SOURCE_BLOB_BUDGET - source_blob_used
                chunk = f.text()[: min(_PER_FILE_SOURCE_CAP, room)]
                if chunk:
                    source_blob_parts.append(chunk)
                    source_blob_used += len(chunk)

            self._classify_infra(project, f, arch)

            if f.name in _MANIFESTS:
                arch["dependency_manifests"].append(f.rel_path)
                manifest_deps |= self._read_manifest_deps(f.text())

        source_blob = "\n".join(source_blob_parts)

        project.languages = languages
        project.frameworks = self._detect_frameworks(manifest_deps, source_blob)
        arch["datastores"] = self._match_signs(_DATASTORE_SIGNS, manifest_deps, source_blob)
        arch["third_party"] = self._match_signs(_SERVICE_SIGNS, manifest_deps, source_blob)
        arch["cloud"] = [s for s in ("AWS", "Google Cloud", "Azure")
                         if s in arch["third_party"]]
        arch["apis"] = self._detect_apis(project, source_blob)
        arch["auth"] = self._detect_auth(source_blob)
        project.architecture = arch
        project.metadata["dependency_count"] = len(manifest_deps)
        return project

    # --- helpers ------------------------------------------------------------
    def _classify_infra(self, project: Project, f: Any, arch: dict[str, Any]) -> None:
        rel = f.rel_path
        name = f.name
        low = rel.lower()

        if name.startswith("Dockerfile") or name == "Containerfile" or name in ("docker-compose.yml", "docker-compose.yaml", "compose.yaml"):
            arch["containers"].append(rel)
        if f.suffix in (".tf", ".hcl"):
            arch["iac"].append(rel)
        is_k8s = "k8s" in low or "kubernetes" in low or self._looks_like_k8s(f)
        if is_k8s and rel not in arch["iac"]:
            arch["iac"].append(rel)
        if (".github/workflows/" in low or low.endswith(".gitlab-ci.yml")
                or "azure-pipelines" in low or low.endswith("jenkinsfile")
                or "bitbucket-pipelines" in low):
            arch["ci_cd"].append(rel)

    @staticmethod
    def _looks_like_k8s(f: Any) -> bool:
        if f.suffix not in (".yml", ".yaml"):
            return False
        head = f.text()[:400]
        return "apiVersion:" in head and "kind:" in head

    @staticmethod
    def _read_manifest_deps(text: str) -> set[str]:
        """Extract dependency-ish tokens from a manifest without a full parser.

        We only need substrings to match against signatures, so a tolerant token
        sweep across manifest formats is sufficient and avoids per-format parsers.
        """
        deps: set[str] = set()
        for match in re.finditer(r"[A-Za-z0-9_@./\-]{2,}", text):
            token = match.group(0).strip().lower()
            if token:
                deps.add(token)
        return deps

    @staticmethod
    def _match_signs(signs: dict[str, tuple[str, ...]], deps: set[str],
                     source: str) -> list[str]:
        found: list[str] = []
        deps_joined = " ".join(deps)
        for label, needles in signs.items():
            if any(_has_needle(n.lower(), deps_joined) for n in needles) or \
               any(_has_needle(n, source) for n in needles):
                found.append(label)
        return found

    @staticmethod
    def _detect_frameworks(deps: set[str], source: str) -> list[str]:
        found: list[str] = []
        deps_joined = " ".join(deps)
        for name, (dep_needles, src_regexes) in _FRAMEWORK_SIGNS.items():
            if any(_has_needle(n.lower(), deps_joined) for n in dep_needles) or \
               any(re.search(rx, source) for rx in src_regexes):
                found.append(name)
        return found

    @staticmethod
    def _detect_apis(project: Project, source: str) -> list[str]:
        apis: list[str] = []
        if re.search(r"@app\.(route|get|post|put|delete)|@router\.|app\.(get|post|put|delete)\(",
                     source):
            apis.append("REST/HTTP")
        if "graphql" in source.lower() or project.find_file("schema.graphql"):
            apis.append("GraphQL")
        if re.search(r"\bgrpc\b|\.proto\b", source) or project.files_matching("*.proto"):
            apis.append("gRPC")
        if re.search(r"websocket|socket\.io", source, re.IGNORECASE):
            apis.append("WebSocket")
        return apis

    @staticmethod
    def _detect_auth(source: str) -> list[str]:
        hits: list[str] = []
        mapping = {
            "JWT": (r"\bjwt\b", r"jsonwebtoken"),
            "OAuth": (r"oauth", r"OAuth"),
            "Session-based": (r"session\[", r"express-session"),
            "Password hashing": (r"bcrypt", r"argon2", r"scrypt", r"pbkdf2"),
            "Passport.js": (r"passport",),
        }
        for label, patterns in mapping.items():
            if any(re.search(p, source) for p in patterns):
                hits.append(label)
        return hits
