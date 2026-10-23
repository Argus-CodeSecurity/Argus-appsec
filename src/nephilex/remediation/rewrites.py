"""Deterministic, line-level fix rewrites.

A rewrite maps a finding's ``rule_id`` to a function that transforms the offending
source line into a fixed one, preserving surrounding syntax and indentation (the
function operates on the real line, so whitespace is kept automatically). These
are the fixes Nephilex can apply and verify locally without a model:

* ``fix_line`` applies the rewrite for a rule to a line.
* ``verify_line_fixed`` confirms the rewrite actually removes the detection, a
  fast, local proxy for "the fix resolves the issue".

Both the :class:`~nephilex.agents.patch.PatchAgent` (which proposes patches) and the
:mod:`~nephilex.remediation.applier` (which writes them to disk) use this module, so
proposal and application can never drift apart.
"""

from __future__ import annotations

import re
from collections.abc import Callable


def _fix_yaml_load(ln: str) -> str | None:
    if "yaml.load(" not in ln or "Safe" in ln:
        return None
    # `yaml.safe_load` takes no Loader= argument, so blindly rewriting
    # `yaml.load(x, Loader=...)` would raise TypeError at runtime. Only the plain
    # form is safely fixable on a single line; leave the Loader= form for a human
    # (it falls through to "no deterministic fix").
    if re.search(r"\bLoader\s*=", ln):
        return None
    return ln.replace("yaml.load(", "yaml.safe_load(")


def _fix_weak_hash(ln: str) -> str | None:
    """Upgrade weak hashes to SHA-256, but only at the actual call sites.

    A blanket string replace would corrupt identifiers or strings that merely
    contain ``md5``/``sha1`` (e.g. a variable named ``md5_util``), so each
    substitution is anchored to the recognized construction pattern.
    """
    replacements = (
        (r"hashlib\.md5\(", "hashlib.sha256("),
        (r"hashlib\.sha1\(", "hashlib.sha256("),
        (r"(createHash\(\s*['\"])md5", r"\1sha256"),
        (r"(createHash\(\s*['\"])sha1", r"\1sha256"),
        (r"(MessageDigest\.getInstance\(\s*['\"])MD5", r"\1SHA-256"),
        (r"(MessageDigest\.getInstance\(\s*['\"])SHA-?1", r"\1SHA-256"),
    )
    fixed = ln
    for pattern, repl in replacements:
        fixed = re.sub(pattern, repl, fixed, flags=re.IGNORECASE)
    return fixed if fixed != ln else None


def _fix_shell_true(ln: str) -> str | None:
    """Set ``shell=False`` rather than deleting the argument.

    Removing ``shell=True`` outright can silently change behavior (and break call
    sites that pass a command string). Flipping the value keeps the call shape and
    still clears the detection; the developer reviews the PR before merging.
    """
    fixed = re.sub(r"shell\s*=\s*True", "shell=False", ln)
    return fixed if fixed != ln else None


def _fix_tls_verify(ln: str) -> str | None:
    fixed = (
        re.sub(r"verify\s*=\s*False", "verify=True", ln)
        .replace("rejectUnauthorized: false", "rejectUnauthorized: true")
        .replace("rejectUnauthorized:false", "rejectUnauthorized:true")
        .replace("InsecureSkipVerify: true", "InsecureSkipVerify: false")
        .replace("InsecureSkipVerify:true", "InsecureSkipVerify:false")
    )
    return fixed if fixed != ln else None


def _fix_flask_debug(ln: str) -> str | None:
    fixed = re.sub(r"debug\s*=\s*True", "debug=False", ln)
    return fixed if fixed != ln else None


def _fix_trust_remote_code(ln: str) -> str | None:
    fixed = re.sub(r"trust_remote_code\s*=\s*True", "trust_remote_code=False", ln)
    return fixed if fixed != ln else None


def _fix_torch_load(ln: str) -> str | None:
    """Add ``weights_only=True`` to a ``torch.load(...)`` call that lacks it.

    Inserts the keyword before the *matching* close paren of the ``torch.load``
    call, found by balancing parentheses. A naive ``[^)]*?`` regex would stop at
    the first inner ``)`` and corrupt nested calls like
    ``torch.load(f, map_location=torch.device("cpu"))``. If the call does not
    close on this single line, we leave it alone rather than risk a broken write.
    """
    if "torch.load(" not in ln or "weights_only" in ln:
        return None
    open_idx = ln.index("torch.load(") + len("torch.load(")
    depth = 1
    i = open_idx
    while i < len(ln) and depth:
        if ln[i] == "(":
            depth += 1
        elif ln[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    if depth != 0:  # call does not close on this line; don't risk a broken rewrite
        return None
    if not ln[open_idx:i].strip():  # torch.load() with no argument: nothing to fix
        return None
    return f"{ln[:i].rstrip()}, weights_only=True{ln[i:]}"


# rule_id -> function(line) -> fixed_line | None (None = no change / not applicable).
REWRITES: dict[str, Callable[[str], str | None]] = {
    "patterns.python-yaml-load": _fix_yaml_load,
    "patterns.weak-hash-md5-sha1": _fix_weak_hash,
    "patterns.python-shell-true": _fix_shell_true,
    "patterns.tls-verify-disabled": _fix_tls_verify,
    "patterns.flask-debug-true": _fix_flask_debug,
    "llm.trust-remote-code": _fix_trust_remote_code,
    "llm.torch-load-pickle": _fix_torch_load,
}


# Autonomy ladder (Rung 3): rule ids whose fix is safe to apply *automatically*
# (unattended), because the rewrite is high-confidence, self-verifies, and its
# only behavior change IS the security intent. Everything else stays propose-only
# for human review. Auto fixes still land on a branch/PR, never a direct push, so
# they are always trivially revertible. This starter set is deliberately tiny;
# teams graduate more rules via `autofix.graduate` in config once they trust them.
#
# Deliberately NOT auto by default (they can change runtime behavior): weak-hash
# (changes digests), shell=True->False (breaks string commands), tls-verify
# (breaks self-signed), torch.load / trust_remote_code (can break model loading).
AUTO_APPLY: frozenset[str] = frozenset(
    {
        "patterns.python-yaml-load",  # yaml.load -> safe_load: the recommended default
        "patterns.flask-debug-true",  # debug=True -> False: never ship debug on
    }
)


def auto_apply_rules(config: object | None = None) -> set[str]:
    """Rule ids eligible for automatic application, honoring config graduate/demote.

    Starts from the conservative built-in :data:`AUTO_APPLY`, then adds any
    ``autofix.graduate`` rule ids and removes any ``autofix.demote`` ones from the
    project config, so autonomy is opt-in and reversible per rule.
    """
    rules = set(AUTO_APPLY)
    autofix = getattr(config, "autofix", None) or {}
    if isinstance(autofix, dict):
        for r in autofix.get("graduate") or []:
            rules.add(str(r))
        for r in autofix.get("demote") or []:
            rules.discard(str(r))
    return rules


def has_rewrite(rule_id: str) -> bool:
    return rule_id in REWRITES


def fix_line(rule_id: str, line: str) -> str | None:
    """Return the fixed version of ``line`` for ``rule_id``, or None if not fixable."""
    fn = REWRITES.get(rule_id)
    if fn is None or not line:
        return None
    try:
        return fn(line)
    except Exception:
        return None


def _detection_rule(rule_id: str):
    """The scanner rule that produced this finding, for self-verification.

    Searches both the ``patterns`` and ``llm`` rule sets (loaded lazily to avoid
    an import cycle with the scanners package). Returns the rule object, which
    carries both the detection ``pattern`` and any ``suppress`` idiom.
    """
    short = rule_id.split(".", 1)[-1]
    from nephilex.scanners.llm import RULES as LLM_RULES
    from nephilex.scanners.patterns import RULES as PATTERN_RULES

    # Separate loops (not a merged tuple) so each element keeps its concrete type
    # (Rule / LLMRule); both expose .id/.pattern/.suppress.
    for prule in PATTERN_RULES:
        if prule.id == short:
            return prule
    for lrule in LLM_RULES:
        if lrule.id == short:
            return lrule
    return None


def detection_pattern(rule_id: str) -> re.Pattern[str] | None:
    """The scanner regex that produced this rule (kept for callers/tests)."""
    rule = _detection_rule(rule_id)
    return rule.pattern if rule is not None else None


def verify_line_fixed(rule_id: str, fixed_line: str) -> bool:
    """True if the scanner would no longer flag the fixed line.

    Honors the rule's ``suppress`` idiom as well as its ``pattern`` (the same
    logic the scanners use), so a rewrite that adds a recognized safe form (e.g.
    ``weights_only=True``) verifies even when the raw pattern still matches. This
    is the local proxy for a fix "resolving" the finding; the applier separately
    gates the whole file on still parsing before any fix is reported.
    """
    rule = _detection_rule(rule_id)
    if rule is None:
        return False
    suppress = getattr(rule, "suppress", None)
    if suppress is not None and suppress.search(fixed_line):
        return True
    return not rule.pattern.search(fixed_line)
