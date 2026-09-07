# Enterprise policy packs

Copy `enterprise.yml` into your repo or merge its `policies:` block into `.argus.yml`.

```bash
argus policy check . --config examples/policies/enterprise.yml
```

Policies are deterministic: they match finding attributes (severity, scanner, rule, tags)
and never depend on LLM output. Customize the pack for your organization's risk appetite.

| Policy | Action | Matches |
|--------|--------|---------|
| `block-critical` | block | Any critical finding |
| `block-secrets` | block | Secrets scanner |
| `block-live-secrets` | block | Verified live credentials |
| `block-supply-chain-critical` | block | Critical dependency CVEs |
| `warn-container-root` | warn | Docker running as root |
| `warn-public-cloud` | warn | Public exposure tag |
| `warn-authz-bypass` | warn | Authorization scanner |
| `block-reachable-critical-cve` | block | High+ reachable dependency CVEs |

See [configuration.md](../docs/configuration.md) for the full policy syntax.
