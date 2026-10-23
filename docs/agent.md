# Server agent

The Nephilex server agent monitors one or more paths on a host on a schedule. It is
the deployment-friendly form of continuous monitoring: run under **systemd**, in
**cron**, or as a long-lived process.

For a single repository, `nephilex watch` is enough. Use the agent when you need to
monitor **multiple paths** on a server (application code, config directories,
etc.) with one config file.

## Quick start

```bash
nephilex agent --init
# edit .nephilex/agent.yml, then:
nephilex agent --once
nephilex agent              # run until Ctrl+C
```

## Configuration

See [examples/agent.yml](https://github.com/nephilex/nephilex/blob/main/examples/agent.yml):

```yaml
interval: 600
state_dir: .nephilex/agent
push: true
cloud_url: ${NEPHILEX_CLOUD_URL}
cloud_token: ${NEPHILEX_CLOUD_TOKEN}
fail_on_drift: high
host_label: prod-web-01

targets:
  - path: /var/www/my-app
    scanners: secrets, patterns, sca, iac
  - path: /etc/nginx
    scanners: patterns
```

Each target is scanned every cycle. Snapshots and drift history are stored under
`state_dir` (per target). When `push` is enabled, results are sent to Nephilex Cloud
with the host label prefixed on the target name.

## systemd example

```ini
[Unit]
Description=Nephilex security agent
After=network.target

[Service]
Type=simple
User=nephilex
WorkingDirectory=/opt/my-app
Environment=NEPHILEX_CLOUD_URL=https://cloud.example.com
Environment=NEPHILEX_CLOUD_TOKEN=...
ExecStart=/usr/local/bin/nephilex agent --config /opt/my-app/.nephilex/agent.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Cron example

```cron
*/15 * * * * /usr/local/bin/nephilex agent --config /opt/my-app/.nephilex/agent.yml --once -q
```

## Related

- [drift.md](drift.md) - compare snapshots and gate on regressions
- [configuration.md](configuration.md) - per-target `.nephilex.yml` via the `config` key
