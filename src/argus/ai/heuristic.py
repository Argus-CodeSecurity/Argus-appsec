"""The heuristic (offline) provider.

This is the default so that ``argus scan`` produces useful, self-contained output
with no API key and no network. Instead of calling a model, it fills the
AI-authored fields of a finding from templates keyed on the finding's taxonomy
(CWE / OWASP / category). It is intentionally deterministic, good for tests and
for air-gapped environments, and is transparently weaker than a real model.
"""

from __future__ import annotations

from argus.ai.base import AIProvider
from argus.core.plugin import ai_provider

# Short, honest explanations keyed by CWE. Extended freely; unknown CWEs fall back
# to a generic template built from the finding's own description.
_CWE_NOTES: dict[str, dict[str, str]] = {
    "CWE-89": {
        "why": "User-controlled input is concatenated into a SQL statement, so an "
        "attacker can change the query's structure rather than just its data.",
        "attack": "Supply input such as `' OR '1'='1` (or a UNION/stacked query) in "
        "the affected parameter to read, modify, or destroy data the "
        "application should not expose.",
        "impact": "Full read/write access to the database, credential theft, data "
        "exfiltration, and in some configurations remote code execution.",
    },
    "CWE-78": {
        "why": "Untrusted input reaches a shell/command execution sink, letting an "
        "attacker inject additional commands.",
        "attack": "Append shell metacharacters (`; rm -rf`, `$(...)`, backticks) to a "
        "parameter that flows into the command to run arbitrary code.",
        "impact": "Remote code execution on the host with the privileges of the "
        "application process.",
    },
    "CWE-79": {
        "why": "Untrusted input is reflected into HTML/JS without contextual encoding, "
        "so the browser executes attacker-supplied script.",
        "attack": "Get a victim to load a URL containing a `<script>` payload; the "
        "script runs in their session.",
        "impact": "Session hijacking, credential theft, and actions performed as the victim.",
    },
    "CWE-798": {
        "why": "A credential is committed in source, so anyone with repository access "
        "(or a leaked copy) obtains it.",
        "attack": "Read the value straight from version control history and use it "
        "directly against the corresponding service.",
        "impact": "Unauthorized access to the associated account or service, and any "
        "data or spend it controls.",
    },
    "CWE-327": {
        "why": "A broken or weak cryptographic primitive is used where a strong one is "
        "required, undermining the guarantee it was meant to provide.",
        "attack": "Exploit the known weakness (collision, small keyspace, or fast "
        "brute force) to forge or recover protected values.",
        "impact": "Loss of confidentiality or integrity for data that was assumed protected.",
    },
    "CWE-502": {
        "why": "Untrusted data is deserialized into live objects, which can trigger "
        "code execution during object construction.",
        "attack": "Craft a serialized payload that instantiates dangerous gadget "
        "chains when the application deserializes it.",
        "impact": "Remote code execution or denial of service.",
    },
    "CWE-22": {
        "why": "User input is used to build a filesystem path without normalization, "
        "so `../` sequences escape the intended directory.",
        "attack": "Request a path like `../../etc/passwd` to read or write files "
        "outside the intended location.",
        "impact": "Disclosure of sensitive files or overwrite of application files.",
    },
    "CWE-1104": {
        "why": "A dependency version with a known published vulnerability is in use.",
        "attack": "Use the public exploit or advisory details for the known CVE "
        "against the running application.",
        "impact": "Whatever the upstream advisory describes, ranges from information "
        "disclosure to remote code execution.",
    },
}


@ai_provider
class HeuristicProvider(AIProvider):
    name = "heuristic"
    is_remote = False
    default_model = "template-v1"

    def complete(self, system: str, user: str) -> str:  # pragma: no cover - unused path
        # The heuristic provider is normally driven through the enrichment helpers
        # below rather than free-form completion. If called directly, echo a note.
        return (
            "[heuristic provider] No language model is configured. "
            "Configure an AI provider for narrative analysis."
        )

    # The agents look for these richer, structured helpers when the provider is
    # heuristic, so they can bypass free-form prompting.
    @staticmethod
    def notes_for_cwe(cwe: str) -> dict[str, str] | None:
        return _CWE_NOTES.get(cwe)
