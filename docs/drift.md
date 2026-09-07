# Configuration drift

Compare two point-in-time snapshots to see what changed in security posture or
project composition.

## Scan drift

Save two Argus JSON reports, then diff them:

```bash
argus scan . -f json -o baseline.json
# ... changes land in the repo ...
argus scan . -f json -o current.json
argus drift baseline.json current.json
argus drift baseline.json current.json --fail-on high -o drift.json
```

Drift uses stable finding **fingerprints** (rule + path + snippet hash), so line
number shifts alone do not look like new vulnerabilities.

Output categories:

- **added** - new findings since the baseline
- **removed** - findings that disappeared (fixed or no longer detected)
- **severity_changed** - same finding, higher or lower severity

## Inventory drift

Compare two `argus inventory` exports for dependency and architecture changes:

```bash
argus inventory . -o inv-before.json
argus inventory . -o inv-after.json
argus drift inv-before.json inv-after.json --inventory
```

Reports:

- dependency adds, removes, and version changes
- new or removed CI/CD, container, and IaC files

## CI usage

Gate deployments on posture regressions:

```yaml
- run: argus scan . -f json -o current.json
- run: argus drift baseline.json current.json --fail-on high --quiet
```

Store `baseline.json` from the last known-good release tag or scheduled scan.

## Continuous monitoring (`argus watch`)

Run periodic scans locally, keep snapshots under `.argus/watch/`, and detect drift
between cycles:

```bash
argus watch . --interval 300          # scan every 5 minutes
argus watch . --once                  # single cycle (cron-friendly)
argus watch . --push                  # upload each scan to Argus Cloud
argus watch . --fail-on-drift high    # exit non-zero on new High+ findings
```

Pair with `argus push` and the Argus Cloud dashboard for hosted history and
scan-to-scan drift in the UI.

## Server agent (`argus agent`)

For hosts that monitor **multiple paths**, use the server agent with a config file:

```bash
argus agent --init
argus agent --once
```

See [agent.md](agent.md) for systemd and cron deployment examples.
