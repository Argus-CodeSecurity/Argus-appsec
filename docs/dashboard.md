# Web dashboard

The dashboard is an **optional** local web app for teams who want scan history and
trends instead of one-off CLI reports. It stores every scan you send it in a small
SQLite database and shows projects, risk over time, and findings.

For Nephilex Cloud (hosted) and how users interpret risk scores and drift, see
[Understanding scan results](understanding-results.md).

It never runs by default and the base `nephilex` install stays lightweight, the
dashboard and its dependencies live behind the `dashboard` extra.

## Install & run

```bash
pip install "nephilex[dashboard]"
nephilex dashboard            # serves http://127.0.0.1:8000
```

Options: `--host` (default `127.0.0.1`) and `--port` (default `8000`).

The database lives at `~/.nephilex/dashboard.db` by default; override with the
`NEPHILEX_DASHBOARD_DB` environment variable. On Linux and macOS the database is
created readable by your user only.

## Access and security

The dashboard holds code snippets and a list of your vulnerabilities, so it is
locked down by default:

- It binds to `127.0.0.1` and only answers requests whose `Host` header is a
  loopback name, which blocks DNS-rebinding attacks from web pages you visit.
  Add further names with `NEPHILEX_DASHBOARD_ALLOWED_HOSTS` (comma-separated).
- Binding to any other address requires a token. Set `NEPHILEX_DASHBOARD_TOKEN`
  and the dashboard accepts it as a bearer token, or once through a login link
  (`http://HOST:PORT/?token=...`). Without a token, a non-loopback `--host` is
  refused with exit code 2. Serve it behind TLS when it leaves your machine.
- Uploads and the API reject cross-site requests, and every page is sent with a
  restrictive Content Security Policy.
- Only the newest `NEPHILEX_DASHBOARD_MAX_SCANS` scans are kept (default 1000).

```bash
export NEPHILEX_DASHBOARD_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
nephilex dashboard --host 0.0.0.0 --port 9000
```

## Getting scans in

The dashboard reads Nephilex's normal JSON report, there are two ways to send one.

**Upload in the browser:**

```bash
nephilex scan . -f json -o report.json
# then open http://127.0.0.1:8000/upload and pick report.json
```

**Pipe it straight from the CLI (great for CI):**

```bash
nephilex scan . -f json | curl -s -X POST --data-binary @- \
  -H "Content-Type: application/json" \
  http://127.0.0.1:8000/api/scans
```

The `Content-Type` header is required; other content types are rejected with
HTTP 415. Add `-H "Authorization: Bearer $NEPHILEX_DASHBOARD_TOKEN"` when a token
is set.

Each scan is grouped into a **project** by name, so scanning the same project over
time builds its history and trend automatically.

## What you see

- **Projects**, every project with its latest risk score, severity mix, and when
  it was last scanned; worst risk first.
- **Project detail**, a **risk-over-time** line chart and the full scan history.
- **Scan detail**, the aggregate risk, a severity breakdown, and a filterable /
  searchable list of findings, each expandable to its reasoning and remediation.

## Design & data handling

- **No re-computation.** Ingestion parses the report back into Nephilex's own
  `ScanResult`, so the dashboard's risk scores and severity counts are computed by
  the same code as the CLI and can never disagree with it.
- **Local and private.** It's a local app over SQLite, your findings stay on your
  machine. It has no authentication, so run it locally or behind your own access
  control; don't expose it to the public internet as-is.
- **Colors** come from a validated, colorblind-safe palette, and severity is always
  shown with its label, never by color alone.
