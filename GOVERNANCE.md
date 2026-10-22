# Governance

This document describes how the Argus project is run: who makes decisions, how
they are made, and how contributors gain responsibility.

## Roles

**Users** run Argus and report problems. Their feedback drives the roadmap.

**Contributors** submit issues, pull requests, documentation, rules, or reviews.
Anyone can be a contributor; no prior approval is needed.

**Maintainers** review and merge pull requests, triage issues, cut releases, and
handle security reports. They are listed in [MAINTAINERS.md](MAINTAINERS.md),
and code ownership is recorded in [.github/CODEOWNERS](.github/CODEOWNERS).

**Lead maintainer** has the final say when consensus cannot be reached, and
manages repository settings, release credentials, and the PyPI project.

## Decision making

Most decisions are made through **lazy consensus** on the pull request or issue:
a proposal that receives no objection from a maintainer within a reasonable time
(normally 5 business days for non-trivial changes) is accepted.

The following changes need explicit approval from at least one maintainer who
did not author the change, recorded as a pull request review:

- any change to code under `src/`, `action.yml`, or `.github/workflows/`;
- changes to the plugin API, the CLI interface, exit codes, report schemas, or
  default configuration (these are compatibility-relevant, see
  [COMPATIBILITY.md](COMPATIBILITY.md));
- new runtime dependencies.

Changes to this document, the license, or the security policy need approval
from the lead maintainer.

If maintainers disagree, the discussion continues on the issue until consensus
is reached. If it cannot be, the lead maintainer decides and records the
reasoning on the issue.

## Becoming a maintainer

Contributors who have made sustained, high-quality contributions (code, review,
triage, or documentation) over several months may be nominated by an existing
maintainer. The nomination is accepted if no maintainer objects within 10
business days. New maintainers are added to MAINTAINERS.md and CODEOWNERS.

Maintainers who are inactive for 12 months may be moved to emeritus status, and
can return by asking.

## Security issues

Security reports are handled privately by the maintainers as described in
[SECURITY.md](SECURITY.md), outside the public decision process, until a fix is
released.

## Code of conduct

All participants are expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Maintainers are responsible for
enforcing it.

## Changes to governance

This document can be changed by pull request, with approval from the lead
maintainer and no objection from other maintainers within 10 business days.
