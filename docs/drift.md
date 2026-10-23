# Configuration drift

Compare two point-in-time snapshots to see what changed in security posture or
project composition.

## Scan drift

Save two Nephilex JSON reports, then diff them:

```bash
nephilex scan . -f json -o baseline.json
# ... changes land in the repo ...
nephilex scan . -f json -o current.json
nephilex drift baseline.json current.json
nephilex drift baseline.json current.json --fail-on high -o drift.json
```

Drift uses stable finding **fingerprints** (rule + path + snippet hash), so line
number shifts alone do not look like new vulnerabilities.

Output categories:

- **added** - new findings since the baseline
- **removed** - findings that disappeared (fixed or no longer detected)
- **severity_changed** - same finding, higher or lower severity

## Inventory drift

Compare two `nephilex inventory` exports for dependency and architecture changes:

```bash
nephilex inventory . -o inv-before.json
nephilex inventory . -o inv-after.json
nephilex drift inv-before.json inv-after.json --inventory
```

Reports:

- dependency adds, removes, and version changes
- new or removed CI/CD, container, and IaC files

## CI usage

Gate deployments on posture regressions:

```yaml
- run: nephilex scan . -f json -o current.json
- run: nephilex drift baseline.json current.json --fail-on high --quiet
```

Store `baseline.json` from the last known-good release tag or scheduled scan.

## Continuous monitoring (`nephilex watch`)

Run periodic scans locally, keep snapshots under `.nephilex/watch/`, and detect drift
between cycles:

```bash
nephilex watch . --interval 300          # scan every 5 minutes
nephilex watch . --once                  # single cycle (cron-friendly)
nephilex watch . --push                  # upload each scan to Nephilex Cloud
nephilex watch . --fail-on-drift high    # exit non-zero on new High+ findings
```

Pair with `nephilex push` and the Nephilex Cloud dashboard for hosted history and
scan-to-scan drift in the UI.

## Server agent (`nephilex agent`)

For hosts that monitor **multiple paths**, use the server agent with a config file:

```bash
nephilex agent --init
nephilex agent --once
```

See [agent.md](agent.md) for systemd and cron deployment examples.
