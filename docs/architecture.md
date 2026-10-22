# Architecture

Argus is built as a small, strict core with everything domain-specific pushed out
to plugins. This document describes the core, the data flow, and where the seams
are.

## The pipeline

A scan is a linear pipeline. Each stage has a single responsibility and passes a
well-defined object to the next.

```
              targets.resolve
 target ───────────────────────▶ Project (or WebTarget)
                                    │
        RepositoryAnalyzer.analyze  │  languages, frameworks, architecture
                                    ▼
                             enriched Project
                                    │
             ScanEngine.scan        │  select applicable scanners
                                    ▼
                         [ Scanner.scan(ctx) ]*   ──▶  Finding[]
                                    │
              agents (per finding)  │  EnrichmentAgent → AttackSimulationAgent → PatchAgent
                                    ▼
                              ScanResult
                                    │
             Reporter.render        │  json | sarif | markdown | html | csv | badge | vex
                                    ▼
                             report string(s)
```

The engine (`argus.core.engine.ScanEngine`) owns orchestration. It is synchronous
and free of side effects on the *target*: `scan()` returns a `ScanResult` and
never modifies scanned source. Its only write is to Argus's own scan-cache
directory (disable with `--no-cache` / `cache: false`). It also leaves the
caller's `Project` object alone: config such as `exclude_paths` and the
analyzer's results are applied to a copy, so one `Project` can be scanned by
several engines with different configs. Writing reports and creating pull
requests are separate, explicit actions performed by the CLI or an integration.

## Core modules

| Module | Responsibility |
|--------|----------------|
| `argus.core.models` | The `Finding`, `ScanResult`, `Severity`, `Remediation`, and `ExploitScenario` data types. Everything speaks these. |
| `argus.core.project` | `Project` and `FileRef`: a normalized, lazily-read view of the target. Scanners consume this, never the filesystem directly. |
| `argus.core.plugin` | The `Scanner`/`Reporter` contracts, `ScannerContext`, `PLUGIN_API_VERSION` and the global `Registry`. |
| `argus.plugin_api` | The public, versioned plugin surface: re-exports the names plugins may depend on. |
| `argus.core.config` | `Config` loading and defaults. |
| `argus.core.engine` | The `ScanEngine` orchestrator. |
| `argus.core.gitexec` | The only place Argus runs `git`; see [Running git](#running-git). |
| `argus.analysis.repository` | `RepositoryAnalyzer`: language, framework, and architecture detection. |
| `argus.ai` | The `AIProvider` contract and the heuristic/Anthropic/OpenAI/Ollama providers, plus the selection `factory`. |
| `argus.agents` | Finding-processing agents: enrichment, attack simulation, patch generation. |
| `argus.scanners` | Built-in scanners. |
| `argus.reporting` | Built-in reporters. |
| `argus.targets` | Resolves a target string into a `Project` or `WebTarget`. |
| `argus.cli` | The Typer command-line interface; see [The CLI package](#the-cli-package). |

## The Finding contract

`Finding` is the load-bearing type. A scanner is responsible for identity,
location, severity, and taxonomy (CWE/OWASP). The reasoning fields
(`why_vulnerable`, `attacker_perspective`, `business_impact`), the
`ExploitScenario`, and the `Remediation.patch` may be filled by the scanner or
completed later by an agent. This split is what lets a simple regex scanner and a
sophisticated AI agent contribute to the same finding without coupling.

`risk_score()` blends severity, confidence, and likelihood into a 0–100 number;
`ScanResult.aggregate_risk()` rolls findings up into a single target score that is
dominated by the worst finding rather than averaged.

## The CLI package

`argus.cli` is split so that a change to one command touches one file:

| Module | Contents |
|--------|----------|
| `cli/app.py` | Builds the Typer `app`: root callback and `--version`, the handler that turns any `ConfigError` into exit status 2, built-in plugin registration, then the built-in and third-party commands. |
| `cli/commands/` | One module per command family: `scan`, `focused` (`secrets`, `iac`, `api`, `cicd`, `container`, `cloud`, `infrastructure`), `supply_chain` (`sbom`, `dependencies`, `supply-chain`), `inventory` (`inventory`, `drift`), `monitor` (`watch`, `agent`, `server`), `baseline`, `policy`, `remediate` (`fix`, `review`, `learn`), `service` (`push`, `dashboard`, `mcp`) and `meta` (`scanners`, `reporters`, `providers`, `version`, `init`). |
| `cli/commands/__init__.py` | `register_commands(app)`, the single, ordered list of commands. Typer shows commands in `argus --help` in registration order, so new commands are added there. |
| `cli/_common.py` | Helpers the commands share: severity and list parsing, target resolution (exit 2 on failure), the progress printer, config assembly from flags, baseline and diff filtering, and the gate that fails a run when scanners crashed. |
| `cli/output.py` | Report emission through the reporter registry, the console table and posture panel, the fix summary, and verbatim stdout writes for machine-readable output. |
| `cli/_console.py` | The stdout and stderr Rich consoles, with UTF-8 forced on Windows. |
| `cli/plugins.py` | Loads `argus.commands` entry points through the plugin allowlist. |
| `cli/main.py` | The console-script target (`argus.cli.main:app`); it only re-exports `app`. |
| `cli/starter_config.yml` | The `.argus.yml` written by `argus init`. |

Command functions are plain functions that take Typer options; they call into
`argus.core` and the domain packages and keep presentation in `output.py`.
Exit codes follow the CLI contract in `COMPATIBILITY.md`: 0 for a pass, 1 for
findings at the `--fail-on` threshold or crashed scanners in a gating run, 2 for
usage, target and configuration errors.

## Plugin discovery

Two registration paths feed the same global `Registry`:

1. **In-process**, importing a scanner/reporter/provider module runs its
   `@scanner`/`@reporter`/`@ai_provider` decorator, registering the class. The
   built-ins use this via `argus.plugins.register_builtins`.
2. **Entry points**, third-party packages declare a callable under the
   `argus.plugins` entry-point group in their `pyproject.toml`. The registry
   loads these lazily on first lookup. A failure in one plugin is isolated and
   never aborts discovery of the others.

Third-party code imports from `argus.plugin_api`, which re-exports the stable
contract and `PLUGIN_API_VERSION`. Every `Scanner`, `Reporter` and `AIProvider`
class carries an `api_version`; the registry skips a class whose version does
not match, logs which plugin was skipped, and leaves the scan running without
it. The separate `argus.commands` entry-point group lets packages add CLI
subcommands; it is loaded by `cli/plugins.py` under the same allowlist.

See [plugins.md](plugins.md) for how to write one and for the stability rules.

## Running git

Every git invocation goes through `argus.core.gitexec`. It builds an argument
list (never a shell), pins repository config keys that would make git launch a
program (`core.fsmonitor`, `diff.external`, textconv, `core.pager`, signature
display) with `-c`, adds `--no-textconv`/`--no-ext-diff`/`--no-show-signature`
where the subcommand accepts them, disables terminal prompts, applies a
timeout, caps stdout and decodes it with invalid bytes replaced, and provides
`is_safe_ref` for refs that come from flags or config.

It has two profiles:

- `UNTRUSTED` for reading a repository that is being scanned. On top of the
  shared pins it disables hooks, credential helpers, SSH and proxy commands,
  every transport (`protocol.allow=never`, no lazy fetch) and the system git
  config, and strips environment variables that could redirect git or inject
  helpers. `argus.scanners._git` (`run_git`, used by the git-security and
  history scanners), the dependency diff in `argus.inventory` and
  `--config-from-ref` in `argus.core.config` use it.
- `WORKTREE` for the operator's own checkout, where `argus fix` and
  `argus review` create branches, commit and push. Hooks, commit signing and
  credentials stay available because those steps need them.
  `argus.remediation.git_ops` uses it.

Cloning a remote target is the one exception: `argus.targets` runs
`git clone` itself with its own transport allowlist and hardening.

## AI providers and the offline default

Agents talk to models through the `AIProvider` interface. The default provider is
`heuristic`: it requires no key and no network and fills findings from templates
keyed on CWE. This keeps a base scan fully offline and deterministic, important
for tests and air-gapped environments. Cloud (`anthropic`, `openai`) and local
(`ollama`) providers are drop-in alternatives. If a requested provider is
unavailable, the factory falls back to `heuristic` with a warning rather than
failing the scan.

## Error handling philosophy

A scan should be robust to a single broken component. A scanner that raises is
recorded in `ScanResult.errors` and the scan continues. An agent that fails on a
finding falls back to heuristic enrichment for that finding. The goal is that
`argus scan` always produces a usable report.
