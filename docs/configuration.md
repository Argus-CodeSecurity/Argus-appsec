# Configuration

Argus reads configuration from, in increasing precedence:

1. Built-in defaults.
2. `.argus.yml` (or `.argus.yaml`) in the project root.
3. A file passed with `--config`.
4. Command-line flags.

Generate a starter file with `argus init`.

## Full reference

```yaml
# Scanners to run. Empty = every scanner that applies to the project.
scanners: []            # e.g. ["secrets", "patterns"]

# Scanners to skip (applied after the list above).
exclude_scanners: []    # e.g. ["iac"]

# Extra path globs to ignore, added to the built-in ignore list
# (.git, node_modules, venv, build artifacts, etc.).
exclude_paths: []       # e.g. ["tests/fixtures/*", "*.min.js"]

# Minimum severity to report: info | low | medium | high | critical
min_severity: info

# Exit non-zero if any finding is at/above this severity. Empty = never fail.
# Use this to gate CI.
fail_on: ""             # e.g. high

# Attack Simulation Mode: safe, sandboxed exploit demonstrations per finding.
attack_simulation: false

# Generate fix patches (and verify the deterministic ones).
generate_patches: false

# Reuse cached findings for unchanged files (content-hash keyed; file-local
# scanners only). CLI: --no-cache. See docs/performance.md.
cache: true

# Run scanners concurrently. Reports are deterministic either way.
parallel: true

ai:
  # heuristic (offline, default) | anthropic | openai | ollama (local)
  provider: heuristic
  model: ""             # provider-specific; empty uses the provider default
  enabled: true         # false disables all AI enrichment
  temperature: 0.0
  max_tokens: 1500

# Per-scanner options, keyed by scanner name.
scanner_options:
  secrets:
    entropy: true             # enable high-entropy string detection
    entropy_threshold: 4.0    # bits; raise to reduce false positives
    verify: false             # opt-in live check (CLI: --verify-secrets)
  dependencies:
    online: true              # query the OSV database for real, current CVEs
    timeout: 15               # seconds for OSV lookups
    cache: true               # cache OSV records on disk to speed repeat scans
    reachability: false       # experimental: imported/not-imported (Python + npm)
    symbol_reachability: false  # tier-2: Python symbol usage vs OSV hints
  supply-chain:
    online_intel: true        # merge bundled + remote malicious-package feeds
  dependency-diff:
    ref: ""                   # git ref for PR diff (set by --diff / supply-chain)
    behavior: true            # npm registry metadata anomaly checks
    sandbox: auto             # auto | host | docker for metadata fetch
  provenance:
    require_for_releases: false

# Security policies - see docs/policy.md
policies: []
```

## Secret verification (opt-in)

`--verify-secrets` (or `scanner_options.secrets.verify: true`) makes a **single,
read-only** call per detected secret to confirm whether it is actually live,
GitHub, Stripe, Slack, OpenAI, and Google keys are supported; others report as
unverified. A confirmed-live credential is escalated to Critical; a rejected one
is downgraded. This makes authenticated network requests with the candidate
credential, so it is **off by default, restricted to local targets** (never a
cloned remote repo), and deliberately absent from the shipped CI templates. The
secret value is used only for the request, it is never written to a finding,
the cache, or a report.

## Runtime posture checks (`--live-target`)

`--live-target <url>` runs a safe, read-only posture pass against a deployed URL
alongside the static scan (or scan a URL directly with `argus scan <url>`): it
checks security headers, cookie flags, HTTP-vs-HTTPS transport, version
disclosure, and a short allowlist of exposed sensitive paths. It is
non-intrusive, only GETs, no payloads or exploitation, but still: **only point
it at systems you are authorized to assess.** It is a pre-DAST layer, not a
crawler or fuzzer.

## Dependency scanning and OSV

The dependency scanner checks your declared packages against the public
[OSV database](https://osv.dev), which covers thousands of advisories across
ecosystems. Only **package names and versions** are sent to OSV, never your
source code, so this preserves Argus's offline-first stance. Set
`scanner_options.dependencies.online: false` to use only the small bundled seed
(fully offline); Argus also falls back to the seed automatically if OSV is
unreachable.

Lookups are batched (no dependency is silently dropped), retried with backoff on
transient failures, and cached on disk so repeat scans are fast. The cache lives
under `~/.cache/argus/osv` by default; override it with the `ARGUS_CACHE_DIR`
environment variable, or disable it with `scanner_options.dependencies.cache: false`.

### Reachability (experimental)

Most dependency alerts concern packages your code never even imports. With
`--reachability` (or `scanner_options.dependencies.reachability: true`), Argus
annotates each PyPI dependency finding with an **import-level verdict**:
*imported* (first-party code imports the package, treat as actionable) or
*not imported* (no import found, deprioritized to an unlikely likelihood, but
**never suppressed**, since dynamic imports and framework hooks are not traced).
The verdict appears in the finding description and as `reachability` in finding
metadata in JSON/SARIF reports. Supported for **Python and npm** at import level;
add `--symbol-reachability` for Python symbol-level hints when OSV provides them.

See also [policy.md](policy.md) for the policy engine.

## Code scanning: two tiers

Argus scans source code with two complementary scanners:

- **`patterns`** (always on), a fast, regex-based pass with a lightweight
  single-hop taint check. Broad language coverage, catches the common cases.
- **`ast-python`** and **`ast-js`** (optional), tree-sitter data-flow analyzers
  for **Python** and **JavaScript/TypeScript** that track tainted values through
  *multiple* variable hops, so they catch injection the regex tier misses
  (e.g. `x = req.query.id` → `y = x` → `db.query('... ' + y)`). They also avoid
  the regex tier's common false positives: a **parameterized query**
  (`db.query('... WHERE id = ?', [id])`) and **sanitized** values
  (`DOMPurify.sanitize(...)`, `Number(...)`, `secure_filename(...)`) are treated
  as safe. Enable with:

  ```bash
  pip install "argus-appsec[ast]"
  ```

  Without the extra, the AST scanners report as not-applicable and Argus uses the
  regex tier, nothing breaks. When both tiers run, findings for the same weakness
  are de-duplicated (the higher-confidence AST finding wins), so you never see one
  issue reported twice.

## Common recipes

**Fast secrets-and-deps check, fail the build on High+:**

```yaml
scanners: [secrets, dependencies]
fail_on: high
```

**Everything, with the flagship features, using a local model:**

```yaml
attack_simulation: true
generate_patches: true
ai:
  provider: ollama
  model: llama3.1
```

**Quiet down a noisy entropy scanner:**

```yaml
scanner_options:
  secrets:
    entropy_threshold: 4.5
```

## Environment variables

Credentials for cloud providers and git hosts are read from the environment (see
`.env.example`):

| Variable | Used by |
|----------|---------|
| `ANTHROPIC_API_KEY` | `anthropic` provider |
| `OPENAI_API_KEY` | `openai` provider |
| `OLLAMA_HOST` | `ollama` provider (default `http://localhost:11434`) |
| `GITHUB_TOKEN` / `GITLAB_TOKEN` | opening pull requests with `argus fix --open-pr` |

## CLI flags

Every relevant config field has a flag, which overrides the file:

```
argus scan TARGET
  -c, --config PATH         path to an .argus.yml config file
  -s, --scanners a,b        run only these scanners
      --exclude a,b         skip these scanners
  -f, --format FMT          output format (repeatable): table json sarif markdown html csv
  -o, --output PATH         write reports (a directory writes one file per format)
      --baseline PATH       report only findings not present in a saved JSON report
      --ai-provider NAME    heuristic | anthropic | openai | ollama
      --ai-model ID         model override
      --no-ai               disable AI enrichment
      --attack-sim          enable Attack Simulation Mode
      --patches             generate/verify fix patches
      --min-severity SEV    report findings at/above this severity
      --fail-on SEV         non-zero exit if any finding is at/above this severity
  -b, --branch NAME         branch to clone for remote targets
      --trust-remote-config load .argus.yml from a cloned remote repo (off by default)
  -q, --quiet               suppress progress output
```
