# Server agent

The Argus server agent monitors one or more paths on a host on a schedule. It is
the deployment-friendly form of continuous monitoring: run under **systemd**, in
**cron**, or as a long-lived process.

For a single repository, `argus watch` is enough. Use the agent when you need to
monitor **multiple paths** on a server (application code, config directories,
etc.) with one config file.

## Quick start

```bash
argus agent --init
# edit .argus/agent.yml, then:
argus agent --once
argus agent              # run until Ctrl+C
```

## Configuration

See [examples/agent.yml](../examples/agent.yml):

```yaml
interval: 600
state_dir: .argus/agent
push: true
cloud_url: ${ARGUS_CLOUD_URL}
cloud_token: ${ARGUS_CLOUD_TOKEN}
fail_on_drift: high
host_label: prod-web-01

targets:
  - path: /var/www/my-app
    scanners: secrets, patterns, sca, iac
  - path: /etc/nginx
    scanners: patterns
```

Each target is scanned every cycle. Snapshots and drift history are stored under
`state_dir` (per target). When `push` is enabled, results are sent to Argus Cloud
with the host label prefixed on the target name.

## systemd example

```ini
[Unit]
Description=Argus security agent
After=network.target

[Service]
Type=simple
User=argus
WorkingDirectory=/opt/my-app
Environment=ARGUS_CLOUD_URL=https://cloud.example.com
Environment=ARGUS_CLOUD_TOKEN=...
ExecStart=/usr/local/bin/argus agent --config /opt/my-app/.argus/agent.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Cron example

```cron
*/15 * * * * /usr/local/bin/argus agent --config /opt/my-app/.argus/agent.yml --once -q
```

## Related

- [drift.md](drift.md) - compare snapshots and gate on regressions
- [configuration.md](configuration.md) - per-target `.argus.yml` via the `config` key
