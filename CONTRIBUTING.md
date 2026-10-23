# Contributing to Nephilex

Thanks for considering a contribution. Nephilex is designed so that most
additions (new scanners, languages, compliance rules, report formats) land as
plugins and never touch the core. That keeps the barrier low and the core
stable.

Everything in this repository is licensed under Apache-2.0, and every
contribution is accepted under the same terms. Please read the
[Code of Conduct](CODE_OF_CONDUCT.md) before participating, and see
[GOVERNANCE.md](GOVERNANCE.md) for how decisions are made.

## Development setup

Requirements: Python 3.10 or newer and git.

```bash
git clone https://github.com/nephilex/nephilex
cd nephilex
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev,ast]"
```

## Checks

CI runs all of these on every pull request. Run them locally first:

```bash
ruff check .                  # lint
ruff format --check .         # formatting
mypy src/nephilex                # type check
pytest                        # tests
python benchmarks/accuracy.py # detection accuracy regression gate
```

`make fmt` applies formatting and safe lint fixes. `make check` runs everything
above.

The accuracy benchmark must stay at its current precision and recall. If your
change intentionally alters what a rule detects, update the labeled corpus in
`benchmarks/accuracy.py` in the same pull request and explain why.

## Branches

Branch from `main` and name the branch `<type>/<short-description>`, lower case,
words separated by hyphens:

| Prefix | Use for |
|---|---|
| `feat/` | New functionality (`feat/go-taint-analysis`) |
| `fix/` | Bug fixes (`fix/sarif-uri-encoding`) |
| `rules/` | New or changed detection rules (`rules/django-raw-sql`) |
| `docs/` | Documentation only (`docs/gitlab-ci-guide`) |
| `refactor/` | Code changes with no behaviour change |
| `test/` | Tests only |
| `ci/` | Workflows, build, and release tooling |
| `chore/` | Dependency bumps and housekeeping |
| `release/` | Release preparation by maintainers (`release/v0.9.0`) |

Security fixes for undisclosed vulnerabilities are developed in a private fork
through a GitHub Security Advisory, not in a public branch. See
[SECURITY.md](SECURITY.md).

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
fix(sarif): percent-encode artifact URIs

Paths with spaces produced invalid SARIF that GitHub Code Scanning rejected.
Encode the path component with urllib.parse.quote.

Signed-off-by: Jane Developer <jane@example.com>
```

- Subject in the imperative mood, at most 72 characters, no trailing period.
- Types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`,
  `chore`. Mark breaking changes with `!` (`feat(cli)!: ...`) and a
  `BREAKING CHANGE:` paragraph in the body.
- The body explains what was wrong and why the change is correct.

### Developer Certificate of Origin

Every commit must be signed off to certify the
[Developer Certificate of Origin](https://developercertificate.org/), which
states that you wrote the change or otherwise have the right to submit it under
the project's license. Add the sign-off with `git commit -s`. Commits without
it cannot be merged.

## What makes a good contribution

- **New scanners and rules.** The highest-value contributions. See
  [docs/plugins.md](docs/plugins.md). Simple rules can be written in YAML
  without any Python.
- **Language support.** Extend `nephilex/analysis/languages.py` and add
  language-specific rules or a dedicated scanner.
- **Report formats.** Subclass `Reporter`.
- **AI providers.** Wrap another model backend behind `AIProvider`.

## Standards

- **Tests are required** for new behaviour. Keep tests deterministic and
  offline; the default heuristic AI provider makes this easy. Tests must not
  write into the repository; use pytest's `tmp_path`.
- **Every finding carries a CWE and OWASP mapping** and, ideally, the reasoning
  fields so it is useful without a model.
- **Treat the scanned repository as hostile.** Nephilex runs on untrusted pull
  requests. Bound regex work and file sizes, never execute or import code from
  the target, pass subprocess arguments as lists, and make sure a crash or
  misconfiguration fails the gate rather than producing a clean result. See
  [THREAT_MODEL.md](THREAT_MODEL.md).
- **Keep the core dependency-light.** New heavy dependencies belong behind an
  optional extra (`pip install nephilex[...]`).
- **Follow the house style.** Ruff enforces formatting and imports; follow the
  patterns in the existing scanners. Write plain technical English in code,
  comments, and docs.

## Security rules of the road

- Attack Simulation is **educational and non-executing** by design. Do not add
  anything that runs generated exploits or sends traffic to live targets
  without an explicit, opt-in design agreed in an issue first.
- If you find a vulnerability *in Nephilex itself*, report it privately as
  described in [SECURITY.md](SECURITY.md) rather than opening a public issue.

## Pull request process

1. Open an issue for anything non-trivial so the approach can be agreed first.
2. Keep each pull request focused on one change.
3. Add tests, docs, and a line under `## [Unreleased]` in
   [CHANGELOG.md](CHANGELOG.md) for user-visible changes.
4. Make sure all checks above pass and every commit is signed off.
5. A maintainer reviews the change. At least one approving review from a
   maintainer other than the author is required to merge.
