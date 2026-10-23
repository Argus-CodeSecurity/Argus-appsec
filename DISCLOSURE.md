# Responsible disclosure protocol (outbound)

This document governs how the Nephilex maintainers handle vulnerabilities we discover
in **other people's** software, for example while researching the security of
open-source AI applications. (To report a vulnerability **in Nephilex itself**, see
[SECURITY.md](SECURITY.md).)

Running a scanner across the ecosystem will surface real, unfixed vulnerabilities
in real projects. Handling that well builds trust; handling it badly is harmful and
can be legally costly. We hold ourselves to the following.

## Principles

- **Report privately first.** We contact the project's maintainers or security
  contact before telling anyone else, and never open a public issue that describes
  an exploitable, unpatched flaw.
- **Coordinate, with a standard window.** We propose a **90-day** coordinated
  disclosure window from first contact, extendable by mutual agreement, and shorter
  only if the issue is already public or being actively exploited.
- **Minimize harm.** We never publish live secrets, working exploit code, or
  precise reproduction details for an unpatched issue. Proof of concept is shared
  privately with the maintainer, not publicly.
- **Good faith and authorization.** We only analyze code and artifacts that are
  publicly available or that we are authorized to test. We do not attack running
  systems, exfiltrate data, or access anything we are not permitted to. Static
  analysis of published source is not authorization to test a live deployment.
- **Credit and honesty.** We credit maintainers and reporters as they prefer, and
  we describe findings accurately, without inflating severity for attention.

## Process

1. **Verify.** Confirm the finding is real and reproducible before contacting
   anyone. No spray-and-pray reports.
2. **Find the contact.** Use `SECURITY.md`, a security advisory channel, a
   `security.txt`, or a maintainer email. If none exists, use a private issue or a
   direct message, not a public one.
3. **Report privately.** Send a clear description, affected versions, impact, and
   private reproduction steps, plus a suggested remediation.
4. **Coordinate the timeline.** Agree on the disclosure date. Stay reachable and
   help validate the fix.
5. **Disclose.** After the fix ships (or the agreed window elapses), publish a
   factual advisory. Request a CVE where appropriate.

## Secrets found in third-party code

If a scan surfaces a live credential in someone else's repository, we treat it as
an urgent private report: notify the owner to **rotate** it immediately, never
publish or use it, and never verify a third-party credential against its provider
without explicit authorization.

## For studies and aggregate reporting

When we publish aggregate research (for example, "the state of LLM application
security in open source"), we report **statistics and patterns**, not a public
list of unfixed, exploitable, named projects. Individual issues follow the private
coordinated process above before anything about them appears in aggregate.
