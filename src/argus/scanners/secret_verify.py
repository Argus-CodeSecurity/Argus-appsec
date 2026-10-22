"""Opt-in live verification of detected secrets.

Detecting a string that *looks* like a credential is useful; confirming it is
**live** turns a theoretical finding into a critical one (and clears format
false positives). This module makes minimal, read-only validation calls to the
issuing provider for a few well-known token types.

Strong safety contract, this feature makes network requests *with the
candidate credential*, so it is deliberately constrained:

* **Opt-in only** (`--verify-secrets` / `verify: true`); never on by default
  and never in the shipped CI templates.
* **Local targets only.** The CLI refuses to verify secrets found in a cloned
  *remote* repository, making authenticated calls with credentials pulled
  from someone else's code is out of scope by design.
* **Read-only endpoints** (identity / balance lookups), one attempt, short
  timeout, no retries.
* The secret value is used only for the request and is **never** stored in a
  finding, cache, or report (findings remain redacted).

Results: ``"live"`` (confirmed valid), ``"invalid"`` (provider rejected it), or
``"unknown"`` (network error, or no verifier for this token type).
"""

from __future__ import annotations

import logging

log = logging.getLogger("argus.scanners.secret_verify")

LIVE = "live"
INVALID = "invalid"
UNKNOWN = "unknown"

_TIMEOUT = 6.0


def _get(url: str, headers: dict[str, str]) -> int | None:
    """Single read-only GET; return the HTTP status, or None on any error."""
    try:
        import httpx

        resp = httpx.get(url, headers=headers, timeout=_TIMEOUT)
        return resp.status_code
    except Exception as exc:  # network/DNS/TLS/import, never raise to the caller
        log.debug("secret verification request failed: %s", exc)
        return None


def _status_verdict(status: int | None, *, live=(200,), invalid=(401,)) -> str:
    # Only 401 (Unauthorized) definitively means the credential is bad. 403 is
    # commonly rate-limiting (GitHub) or a valid-but-forbidden token, so mapping
    # it to INVALID would wrongly downgrade a live secret -- the dangerous
    # direction for a security tool. 403 (and anything else) falls through to
    # UNKNOWN so the finding is neither dismissed nor over-claimed.
    if status is None:
        return UNKNOWN
    if status in live:
        return LIVE
    if status in invalid:
        return INVALID
    return UNKNOWN


def _verify_github(secret: str) -> str:
    return _status_verdict(
        _get(
            "https://api.github.com/user",
            {"Authorization": f"Bearer {secret}", "User-Agent": "argus-secret-verify"},
        )
    )


def _verify_openai(secret: str) -> str:
    return _status_verdict(
        _get("https://api.openai.com/v1/models", {"Authorization": f"Bearer {secret}"})
    )


def _verify_stripe(secret: str) -> str:
    # Basic auth with the key as the username; balance is read-only.
    import base64

    token = base64.b64encode(f"{secret}:".encode()).decode()
    return _status_verdict(
        _get("https://api.stripe.com/v1/balance", {"Authorization": f"Basic {token}"})
    )


def _verify_slack(secret: str) -> str:
    # auth.test returns 200 with {"ok": false} for a bad token, so inspect body.
    try:
        import httpx

        resp = httpx.get(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {secret}"},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            return LIVE if resp.json().get("ok") is True else INVALID
        return UNKNOWN
    except Exception as exc:
        log.debug("slack verification failed: %s", exc)
        return UNKNOWN


def _verify_google_api_key(secret: str) -> str:
    # Google keys are scoped per API, so there is no universal validity check.
    # Only a clean 200 proves the key works. Everything else is ambiguous and
    # must not be reported as live or as invalid: a 400 can mean a valid key is
    # missing the search-engine id, and a 403 can be a restriction on an
    # otherwise real key. Report UNKNOWN rather than overstate either way.
    status = _get(
        "https://www.googleapis.com/customsearch/v1?key=" + secret + "&q=argus",
        {},
    )
    return LIVE if status == 200 else UNKNOWN


# secrets-scanner rule_id -> verifier. Types without a safe read-only check
# (e.g. AWS, which needs SigV4 request signing) are intentionally absent and
# report as "unknown" so we never overstate what was verified.
_VERIFIERS = {
    "github-token": _verify_github,
    "stripe-secret-key": _verify_stripe,
    "slack-token": _verify_slack,
    "google-api-key": _verify_google_api_key,
}


def supported() -> frozenset[str]:
    return frozenset(_VERIFIERS)


def verify(rule_id: str, secret: str) -> str:
    """Return LIVE / INVALID / UNKNOWN for a detected secret. Never raises."""
    verifier = _VERIFIERS.get(rule_id)
    if verifier is None:
        # Try OpenAI-style keys by shape (sk-...) regardless of the matching rule.
        if secret.startswith("sk-") and not secret.startswith("sk_live_"):
            return _verify_openai(secret)
        return UNKNOWN
    try:
        return verifier(secret)
    except Exception as exc:  # a verifier bug must not break the scan
        log.debug("verifier for %s errored: %s", rule_id, exc)
        return UNKNOWN
