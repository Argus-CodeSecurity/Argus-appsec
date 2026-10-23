# Continuous monitoring (the watchtower pattern)

A vulnerability scan is a snapshot. But your risk changes even when your code does
not: a new CVE is published against a dependency you already ship, or a CVE you
carry lands on the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog. Catching that is a *monitoring* problem, not a one-off scan.

You do not need a new tool for it. Nephilex already has the pieces:

- **Fresh data every run.** The dependency scanner queries live OSV data (cached
  with a TTL) and enriches with EPSS and KEV on every scan, so a newly-published
  advisory or a new KEV entry appears the next time you scan, with no code change.
- **New-since-last-time.** `--baseline` makes a scan report only findings that are
  **new** relative to a saved baseline, matched by a stable fingerprint.
- **Gate on new risk.** Combine it with `--fail-on` to alert only when something
  new crosses a severity you care about.

## Schedule it

Run a periodic job (cron, or a scheduled CI pipeline) that re-scans against a
committed baseline:

```bash
# once, to capture the current state
nephilex scan . -f json -o .nephilex-baseline.json

# on a schedule (e.g. daily): fail only if a NEW high+ finding appeared,
# which includes a dependency that became vulnerable since the baseline
nephilex scan . --baseline .nephilex-baseline.json --fail-on high
```

A daily scheduled run that exits non-zero when a new critical or high appears is a
working watchtower: the day a CVE you ship is added to KEV, the next run flags it.

## The hosted version

Doing this **automatically across many repositories**, on a schedule you do not
maintain, with **Slack/email alerts** on new criticals and a history of when each
finding appeared and cleared, is the retention feature of the hosted
[Nephilex Cloud](https://github.com/nephilex/nephilex) offering. The
open-source core gives you the same detection; the hosted product runs and alerts
on it for you.
