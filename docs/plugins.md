# Writing plugins

Argus has three extension points, **scanners**, **reporters**, and **AI
providers**, and adding any of them requires no change to the core. Packages can
also add **CLI commands**. This guide walks through each, then describes what the
plugin API promises to keep stable (see
[Stability and versioning](#stability-and-versioning)).

Import everything a plugin needs from `argus.plugin_api`. Other modules in the
`argus` package are internal and can change in any release.

## Scanners

A scanner analyzes a `Project` and yields `Finding` objects. Subclass `Scanner`,
set the class attributes, and implement `scan`.

```python
from collections.abc import Iterable

from argus.plugin_api import (
    Confidence,
    Finding,
    Location,
    Remediation,
    Scanner,
    ScannerContext,
    Severity,
    scanner,
)


@scanner  # registers the scanner with the global registry
class TodoScanner(Scanner):
    name = "todo"  # unique id (used in config and finding ids)
    category = "hygiene"  # grouping shown in `argus scanners`
    description = "Flags TODO/FIXME markers left in code."

    def applies_to(self, project) -> bool:
        # Cheap opt-out so the engine can skip irrelevant scanners.
        return bool(project.files())

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if f.language is None:  # skip non-source files
                continue
            for lineno, line in enumerate(f.lines(), start=1):
                if "TODO" in line or "FIXME" in line:
                    counter += 1
                    yield Finding(
                        id=f"{self.name}:marker:{counter}",
                        rule_id=f"{self.name}.marker",
                        scanner=self.name,
                        title="Unresolved TODO/FIXME",
                        description="A TODO or FIXME marker remains in the code.",
                        location=Location(path=f.rel_path, start_line=lineno, snippet=line.strip()),
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        remediation=Remediation(summary="Resolve or ticket the item."),
                    )
```

### What the context gives you

`ScannerContext` is a dataclass that carries:

- `ctx.project`, the analyzed `Project` (languages, frameworks, architecture, and
  `files()` for iteration).
- `ctx.config`, the active `Config`. Read per-scanner options with
  `ctx.config.options_for(self.name)`.
- `ctx.ai`, the selected `AIProvider`, if a scanner wants to use a model directly
  (most don't; enrichment is the agents' job).

### Good scanner behavior

- **Be cheap when you don't apply.** Use `applies_to` to bail early.
- **Fill the taxonomy.** Set `cwe` and `owasp`; reporters and SARIF consumers rely
  on them.
- **Provide reasoning where you can.** If your rule knows why it's a vulnerability,
  set `why_vulnerable`/`attacker_perspective`/`business_impact` so findings are
  useful even with the offline provider.
- **Never crash the scan.** The engine isolates exceptions, but a scanner that
  guards its own edge cases produces better results.

## Reporters

A reporter turns a `ScanResult` into a string.

```python
from argus.plugin_api import Reporter, ScanResult, reporter


@reporter
class OneLineReporter(Reporter):
    name = "oneline"
    extension = "txt"
    description = "One line per finding."

    def render(self, result: ScanResult) -> str:
        return "\n".join(
            f"{f.severity.label}\t{f.location.as_ref()}\t{f.title}"
            for f in result.sorted_findings()
        )
```

The new format is immediately available as `argus scan ... -f oneline`.

## AI providers

Wrap any chat-style model by subclassing `AIProvider`.

```python
from argus.plugin_api import AIProvider, ai_provider


@ai_provider
class MyProvider(AIProvider):
    name = "myprovider"
    is_remote = True  # does this send code off the machine?
    default_model = "my-model-v1"

    @classmethod
    def is_available(cls) -> bool:
        # Return True only if the SDK and credentials are present.
        return True

    def complete(self, system: str, user: str) -> str:
        # Call your model and return the text completion.
        ...
```

Set `is_remote` honestly, the `argus providers` command surfaces it so users can
choose a local provider when source confidentiality matters.

## Community rules (YAML, no Python)

The `patterns` scanner is rule-driven, and you can extend it with a **YAML file**,
no code, which is the easiest way to contribute a check. Argus loads rules
from any path in `scanner_options.patterns.rules` (a string or list, globs
allowed) and from the convention directory `.argus/rules/*.yml` in your project.

```yaml
# .argus/rules/team.yml
rules:
  - id: hardcoded-internal-ip
    title: Hardcoded internal IP address
    pattern: '\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    severity: low            # info | low | medium | high | critical
    languages: [Python, Go]  # optional; omit for all languages
    cwe: [CWE-1188]          # optional
    owasp: ["A05:2021-Security Misconfiguration"]   # optional
    confidence: low          # optional: low | medium | high
    why: An internal IP is baked into source.
    fix: Move host addresses into configuration.
    suppress: 'argus:allow-internal-ip'   # optional: a regex that clears a match
```

Findings from a custom rule are reported as `patterns.<id>`. A malformed rule is
skipped with a warning rather than aborting the scan. A ready-to-copy example
lives in [`examples/custom-rules/`](../examples/custom-rules/). This is the
recommended path for language- or org-specific rules; reach for a Python scanner
plugin (below) only when a rule needs logic a regex can't express.

## Packaging a plugin

Ship your plugins in a normal Python package and declare a registration callable
under the `argus.plugins` entry-point group:

```toml
# your_plugin/pyproject.toml
[project.entry-points."argus.plugins"]
my_plugin = "your_plugin:register"
```

```python
# your_plugin/__init__.py
def register() -> None:
    # Importing the modules runs the @scanner/@reporter/@ai_provider decorators.
    from your_plugin import scanners, reporters  # noqa: F401
```

Once the package is installed alongside Argus, its plugins are discovered
automatically, no configuration required.

## Stability and versioning

### What `argus.plugin_api` guarantees

`argus.plugin_api` is the public plugin contract. These names are stable:

| Name | What it is |
| --- | --- |
| `PLUGIN_API_VERSION` | The version of this contract (currently `1`). |
| `Scanner`, `ScannerContext` | Scanner base class and the context passed to `Scanner.scan`. |
| `Reporter` | Report format base class. |
| `AIProvider`, `ChatMessage` | Model backend base class and the message type `AIProvider.chat` takes. |
| `scanner`, `reporter`, `ai_provider` | Registration decorators. |
| `Finding`, `Location`, `Remediation` | The finding model a scanner yields. |
| `Severity`, `Confidence`, `Likelihood` | The rating enums used on a finding. |
| `ScanResult` | What a reporter renders. |
| `Project`, `FileRef`, `Config` | Types reachable from `ScannerContext`. |
| `PluginVersionError` | Raised by the version check (see below). |

For the types a plugin reads rather than subclasses, the stable part is what a
plugin needs to do its job: `Project.root`, `Project.name`, `Project.files()`,
`Project.languages`, `Project.frameworks`; `FileRef.path`, `FileRef.rel_path`,
`FileRef.language`, `FileRef.size`, `FileRef.text()`, `FileRef.lines()`; and
`Config.options_for(name)`. The `Finding` and `ScanResult` fields follow the JSON
report schema, which is stable on its own terms (see
[COMPATIBILITY.md](https://github.com/Argus-CodeSecurity/Argus-appsec/blob/main/COMPATIBILITY.md)).

Within one plugin API version, Argus only makes additive changes: new optional
fields, new keyword arguments with defaults, new methods with default
implementations on the base classes, new exported names. Removing or renaming any
name above, or changing a method signature in a way that breaks existing
subclasses or callers, raises `PLUGIN_API_VERSION`.

Everything not exported from `argus.plugin_api` (including `argus.core.*`,
`argus.scanners.*` and any underscored name) is internal. It can change in any
release without notice, even when the plugin API version does not.

### How `api_version` works

`Scanner`, `Reporter` and `AIProvider` each have a class attribute
`api_version`, which defaults to `PLUGIN_API_VERSION` of the Argus the plugin was
written against. Plugins should not set it themselves; inheriting the default
records the version they were built for.

When a plugin class is registered, the registry compares its `api_version` with
the running Argus's `PLUGIN_API_VERSION`. On a mismatch the class is not
registered: the registry logs a warning on the `argus.plugins` logger naming the
plugin, its class and both versions, and the rest of the plugin package and the
scan carry on. Selecting a skipped scanner by name then fails with a message that
says it was skipped and why, rather than "unknown scanner". An integer
`api_version` is expected; a string such as `"1"` is read as its major number.

When `PLUGIN_API_VERSION` is raised, the changelog lists what changed and how to
port a plugin. Publish a plugin release built against the new version; users on
older Argus releases keep the previous plugin release.

### Entry-point groups

Argus loads third-party code from two entry-point groups. Both go through the
same trust controls: `ARGUS_PLUGIN_ALLOWLIST`, `ARGUS_PLUGIN_BLOCKLIST` and the
`ARGUS_TRUSTED_PLUGINS` pins (see `argus.plugins.signing`).

**`argus.plugins`** registers scanners, reporters and AI providers. The entry
point is a callable that takes no arguments and registers plugins as a side
effect, normally by importing modules that use the decorators:

```toml
[project.entry-points."argus.plugins"]
acme = "acme_argus:register"
```

```python
# acme_argus/__init__.py
def register() -> None:
    from acme_argus import scanners  # noqa: F401  (runs the @scanner decorators)
```

**`argus.commands`** adds subcommands to the `argus` CLI. The entry point is a
callable that receives the Typer application and registers commands on it. A
command plugin that fails to load is skipped with a warning; it never breaks the
built-in commands.

```toml
[project.entry-points."argus.commands"]
acme = "acme_argus.cli:register_commands"
```

```python
# acme_argus/cli.py
import typer


def register_commands(app: typer.Typer) -> None:
    @app.command("acme-audit")
    def acme_audit(target: str = typer.Argument(".")) -> None:
        """Run the ACME audit."""
        typer.echo(f"auditing {target}")
```

The Typer application object passed to command plugins is not part of
`argus.plugin_api`; command plugins depend on Typer's public API and should pin
the Typer versions they support.
