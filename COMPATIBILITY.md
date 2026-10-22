# Compatibility and versioning policy

Teams wire Argus into merge gates and parse its output in pipelines, so stability
is a feature. This document states what we promise not to break without a major
version bump, and what may change at any time. Argus follows
[Semantic Versioning](https://semver.org/).

> **0.x note.** Argus is in early alpha (0.x). Under SemVer, 0.x makes no strong
> stability guarantees, so during 0.x a *minor* bump (0.x to 0.(x+1)) may include a
> breaking change. We still document breaks in the [CHANGELOG](CHANGELOG.md) and
> avoid them where we can, and we apply the policy below as if it were already 1.0
> so the transition to 1.0 is boring.

## What is a public interface (stable)

These are contracts other systems depend on. A backward-incompatible change to any
of them is a **major** version change (after 1.0), and is always called out in the
changelog:

- **CLI surface.** Existing command names, flags, and their meanings. Exit codes
  (`0` clean/under threshold, `1` findings at/above `--fail-on`, `2` usage/target
  error). New flags and new commands are additive (minor).
- **Configuration keys.** The `.argus.yml` keys that exist today (`scanners`,
  `exclude_scanners`, `exclude_paths`, `min_severity`, `scanner_options`, `allow`,
  and the documented per-scanner options). Renaming or removing a key is breaking.
- **Machine-readable output schemas.** The **JSON** reporter's field names and
  shapes, the **SARIF** structure (2.1.0), and the **VEX** and **badge** document
  shapes. CI parses these, so a field rename is a breaking change; adding a new
  field is additive.
- **The severity model.** How a rule's severity is assigned. Because teams gate on
  `--fail-on high`, moving a rule's severity is a behavioral break: it is treated
  as breaking and always noted in the changelog with the rule id and the old/new
  severity.
- **The plugin API.** The names exported from `argus.plugin_api` (the `Scanner`,
  `Reporter`, and `AIProvider` base classes, `ScannerContext`, the registration
  decorators, and the finding model), and the `argus.plugins` and
  `argus.commands` entry-point groups that third-party code registers through.
  The contract carries its own version, `PLUGIN_API_VERSION`: a change that would
  break existing plugins raises it, and Argus skips (with a logged warning) any
  plugin whose `api_version` does not match instead of loading it. Additive
  changes keep the version. See
  [docs/plugins.md](docs/plugins.md#stability-and-versioning) for the full list
  and the rules.

## What may change at any time (not stable)

- **Which findings a scan produces**, and their exact wording, ordering, line
  attribution, and heuristics. Detection improves continuously; new true positives
  and fewer false positives are the point, and are not "breaking" even though they
  change output. Pin a version and use `--baseline` if you need reproducibility
  across upgrades.
- **Internal modules and private names** (anything underscored, and anything not
  named above). Import from the documented surfaces only; for plugins that is
  `argus.plugin_api`, not `argus.core.*` or other modules.
- **Bundled data** (the offline advisory seed, rule contents) refreshes freely.

## Deprecation

When a stable interface must change, we deprecate rather than break abruptly:

1. Keep the old form working and add the new one.
2. Emit a deprecation notice (to stderr, never to the machine-readable output on
   stdout) and document it in the changelog.
3. Remove the old form no sooner than the next major version, with an upgrade note.

## Supported Python versions

Argus supports the CPython versions that are not end-of-life, following the
[CPython release calendar](https://devguide.python.org/versions/) (broadly aligned
with NEP 29). Dropping a Python version is a minor-version change and is announced
in the changelog. The CI matrix reflects the currently supported set.
