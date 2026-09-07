# Contributing to Argus

Thanks for considering a contribution. Argus is designed so that most
additions, new scanners, languages, compliance rules, report formats, land as
plugins and never touch the core. That keeps the barrier low and the core stable.

This public repository is **Apache-2.0 only**. Commercial packages (`argus-k8s`,
`argus-cloud`) live in a separate private repo. See
[docs/repository-split.md](docs/repository-split.md) for what belongs here vs
what must never be committed to this tree.

## Getting set up

```bash
git clone https://github.com/Argus-CodeSecurity/Argus-appsec
cd argus-appsec
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Run the checks:

```bash
pytest              # tests
ruff check .        # lint
mypy                # type check (advisory during alpha)
```

All three run in CI on every pull request; please make sure they pass locally
first.

## What makes a good contribution

- **New scanners and rules.** The highest-value contributions. See
  [docs/plugins.md](docs/plugins.md). New rules for the built-in `patterns` and
  `iac` scanners are just entries in a list.
- **Language support.** Extend `argus/analysis/languages.py` and add
  language-specific rules or a dedicated scanner.
- **Report formats.** Subclass `Reporter`.
- **AI providers.** Wrap another model backend behind `AIProvider`.

## Standards

- **Tests are required** for new behavior. Put fixtures in `tests/conftest.py` and
  keep tests deterministic, the default offline provider makes this easy.
- **Every finding must carry a CWE and OWASP mapping** and, ideally, the reasoning
  fields so it is useful without a model.
- **Keep the core dependency-light.** New heavy dependencies belong behind an
  optional extra (`pip install argus-appsec[...]`), like the cloud providers.
- **Match the house style.** Ruff enforces formatting and imports; follow the
  patterns in the existing scanners.

## Security rules of the road

Argus is a security tool; contributions should reflect that.

- The Attack Simulation feature is **educational and non-executing** by design. Do
  not add anything that runs generated exploits or sends traffic to live targets
  without an explicit, opt-in, sandboxed design discussed in an issue first.
- If you find a vulnerability *in Argus itself*, please report it privately (see
  [SECURITY.md](SECURITY.md)) rather than opening a public issue.

## Pull request process

1. Open an issue for anything non-trivial so we can agree on the approach.
2. Branch from `main`, keep the change focused.
3. Add tests and docs.
4. Ensure `pytest`, `ruff check .`, and `mypy` pass.
5. Describe the change and its motivation in the PR.

By contributing you agree that your contributions are licensed under the project's
Apache-2.0 license.
