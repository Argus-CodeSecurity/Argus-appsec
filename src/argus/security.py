"""Security output constants (spec §2, §68)."""

SECURITY_DISCLAIMER = (
    "Argus identifies known security risks using static analysis, configuration review, "
    "and optional authorized checks. Results are evidence-based signals, not proof that "
    "a system is secure. Always validate findings in context and never treat a clean "
    "scan as a guarantee of safety."
)

VERIFICATION_STATES = frozenset({
    "detected", "likely", "confirmed", "verified", "fixed", "accepted", "false_positive",
})
