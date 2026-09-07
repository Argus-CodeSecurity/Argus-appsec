# Publishing checklist

Use this before the first public push of `argus-appsec` and the first private
push of `argus-commercial`.

## Public repo: `argus-appsec`

### Pre-push

- [ ] Run `pytest` (expect 350+ passing)
- [ ] Run `ruff check .`
- [ ] Version in `pyproject.toml` matches `CHANGELOG.md`
- [ ] No files from `argus-commercial/` in the tree
- [ ] No `.env`, API keys, or license signing keys
- [ ] `README.md`, `LICENSE`, `CONTRIBUTING.md`, `THREAT_MODEL.md` present

### Initialize git (first time)

```bash
cd argus-appsec
git init
git add .
git commit -m "Initial public release of argus-appsec"
git remote add origin git@github.com:Argus-CodeSecurity/Argus-appsec.git
git push -u origin main
```

### Release tag

```bash
git tag v0.8.0
git push origin v0.8.0
```

CI should publish to PyPI and attach release artifacts.

## Private repo: `argus-commercial`

### Pre-push

- [ ] Public `argus-appsec` version is released (add-ons need `argus.commands` from 0.8.0+)
- [ ] `keys/signing_private_key.pem` is gitignored and not staged
- [ ] `.env` files are gitignored
- [ ] Stripe live keys only in host secrets, not in git

### Initialize git (first time)

```bash
cd argus-commercial
git init
git add .
git commit -m "Initial commercial Argus products"
git remote add origin <your-private-remote-url>
git push -u origin main
```

### Deploy order

1. PyPI: `argus-appsec`
2. Private bundle or index: `argus-k8s`
3. Host deploy: `argus-cloud` (run `npm run db:migrate` once)

## Customer install paths

**Open source:**

```bash
pip install argus-appsec
argus scan .
```

**With commercial K8s add-on:**

```bash
pip install argus-appsec argus-k8s
export ARGUS_LICENSE="<from argus-cloud dashboard>"
argus cluster
```
