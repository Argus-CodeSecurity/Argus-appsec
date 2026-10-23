"""What makes a package install script suspicious, defined once.

The malware scanner (lines of a local package.json), the supply-chain scanner
(parsed package.json scripts) and the behavioral fingerprint (registry metadata
for a dependency) all judge npm lifecycle scripts. They share this definition so
the three cannot drift apart.
"""

from __future__ import annotations

import re

#: npm lifecycle hooks that run automatically on `npm install`.
LIFECYCLE_HOOKS: tuple[str, ...] = ("preinstall", "install", "postinstall", "prepare")

#: Downloads, shells, code evaluation, credential paths and environment access.
#: Word boundaries keep ordinary commands such as "npm run publish" from
#: matching on a substring ("sh ").
SUSPICIOUS_INSTALL_SCRIPT = re.compile(
    r"\b(?:curl|wget|bash|powershell|certutil|child_process)\b"
    r"|\bsh\s|\bInvoke-|\b(?:eval|exec)\b|\bchmod\s"
    r"|https?://|\.exe\b|/dev/tcp|/etc/passwd|~/\.ssh|\bprocess\.env\b",
    re.IGNORECASE,
)
