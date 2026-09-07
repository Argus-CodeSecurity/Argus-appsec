# Web dashboard

The dashboard is an **optional** local web app for teams who want scan history and
trends instead of one-off CLI reports. It stores every scan you send it in a small
SQLite database and shows projects, risk over time, and findings.

For Argus Cloud (hosted) and how users interpret risk scores and drift, see
[Understanding scan results](understanding-results.md).

It never runs by default and the base `argus` install stays lightweight, the
dashboard and its dependencies live behind the `dashboard` extra.

## Install & run

```bash
pip install "argus-appsec[dashboard]"
argus dashboard            # serves http://127.0.0.1:8000
```

Options: `argus dashboard --host 0.0.0.0 --port 9000`.

The database lives at `~/.argus/dashboard.db` by default; override with the
`ARGUS_DASHBOARD_DB` environment variable.

## Getting scans in

The dashboard reads Argus's normal JSON report, there are two ways to send one.

**Upload in the browser:**

```bash
argus scan . -f json -o report.json
# then open http://127.0.0.1:8000/upload and pick report.json
```

**Pipe it straight from the CLI (great for CI):**

```bash
argus scan . -f json | curl -s -X POST --data-binary @- \
  http://127.0.0.1:8000/api/scans
```

Each scan is grouped into a **project** by name, so scanning the same project over
time builds its history and trend automatically.

## What you see

- **Projects**, every project with its latest risk score, severity mix, and when
  it was last scanned; worst risk first.
- **Project detail**, a **risk-over-time** line chart and the full scan history.
- **Scan detail**, the aggregate risk, a severity breakdown, and a filterable /
  searchable list of findings, each expandable to its reasoning and remediation.

## Design & data handling

- **No re-computation.** Ingestion parses the report back into Argus's own
  `ScanResult`, so the dashboard's risk scores and severity counts are computed by
  the same code as the CLI and can never disagree with it.
- **Local and private.** It's a local app over SQLite, your findings stay on your
  machine. It has no authentication, so run it locally or behind your own access
  control; don't expose it to the public internet as-is.
- **Colors** come from a validated, colorblind-safe palette, and severity is always
  shown with its label, never by color alone.
