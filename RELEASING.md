# Releasing Nephilex

This is the maintainer runbook for cutting a release. A release produces, from
one git tag, all of the following with the same version number:

| Artifact | Where | Version form |
|---|---|---|
| Python package `nephilex` | PyPI (final) or TestPyPI (release candidate) | `0.12.0`, `0.12.0rc1` |
| Git tag and GitHub Release | GitHub | `v0.12.0`, `v0.12.0rc1` |
| Container image | `ghcr.io/nephilex/nephilex` | `0.12.0`, `0.12`, `latest`; or `0.12.0rc1`, `rc` |
| GitHub Action | `nephilex/nephilex@v0.12.0` | `v0.12.0` |
| pre-commit hooks | `rev: v0.12.0` | `v0.12.0` |
| SBOM and provenance | Release assets, Sigstore | tied to the built files |

## Three phases

| Phase | Where | Who installs it | How it gets there |
|---|---|---|---|
| **Development** | feature branches and `main` | contributors | pull requests; CI on every change. `main` may change daily: nobody installs from it |
| **Staging** | TestPyPI, image tags `0.12.0rcN` and `rc` | the maintainers and testers | a GitHub pre-release with version `0.12.0rcN` |
| **Production** | PyPI, image tags `0.12.0`, `0.12`, `latest`, the Marketplace | everyone | a GitHub release with version `0.12.0`, after the release candidate held up |

The version decides the phase. `publish.yml` and `docker.yml` treat `X.Y.Z` as
production and `X.Y.Z{a,b,rc}N` as staging, and refuse the release when the
GitHub release's "pre-release" box disagrees with the version. A release
candidate therefore cannot reach PyPI or `:latest`, and a final version cannot
be hidden as a pre-release. A manual run of the Docker workflow builds a
development image (`edge`, `sha-<commit>`) and never touches a release tag.

## Release rhythm

- **Feature releases** (`0.12.0`, `0.13.0`) about every four weeks. Each one goes
  through at least one release candidate on staging, used for about a week on
  real projects before the final version.
- **Patch releases** (`0.12.1`) only for a real bug or a security fix. They may
  skip staging when the fix is small and urgent; say so in the release notes.
- **No other releases.** Merging to `main` is not a release. Routine dependency
  updates arrive monthly and wait for the next feature release.

## How the version stays consistent

- **One source of truth.** The version lives only in `src/nephilex/__init__.py`
  (`__version__`). `pyproject.toml` reads it from there
  (`[tool.hatch.version]`), so the package metadata cannot drift.
- **The tag must match.** The release workflows refuse to release when the tag
  (`v0.12.0`) does not equal `v` + `__version__`. A mismatched release fails
  before anything is uploaded.
- **Versions are permanent.** PyPI and TestPyPI accept a version number only
  once, even if the release is later deleted. Never reuse a number; if a
  release candidate is broken, publish `rc2`; if a final release is broken,
  publish the next patch version.
- **Tags are immutable.** Never move or delete a published tag. Users pin to
  them (the Action, pre-commit, Docker).

## Version numbers

Nephilex follows [Semantic Versioning](https://semver.org/) and PEP 440:

- **Patch** (`0.12.1`): bug fixes only, no behaviour change.
- **Minor** (`0.13.0`): new features. While Nephilex is pre-1.0, a minor release may
  also contain breaking changes, which must be listed under a **Breaking
  changes** heading in the changelog.
- **Major** (`1.0.0`): from 1.0 onward, breaking changes to the CLI, exit codes,
  report schemas, configuration, or plugin API require a major version. See
  [COMPATIBILITY.md](COMPATIBILITY.md).
- **Release candidates**: `0.12.0rc1`, `0.12.0rc2` (tags `v0.12.0rc1`, ...).
  Alpha and beta (`0.12.0a1`, `0.12.0b1`) are allowed and also go to staging.

## One-time setup

1. **PyPI trusted publisher.** On <https://pypi.org/manage/project/nephilex/settings/publishing/>
   add a GitHub publisher: owner `Nephilex`, repository `nephilex`, workflow
   `publish.yml`, environment `pypi`. No API token is stored anywhere.
2. **TestPyPI trusted publisher.** Create an account on <https://test.pypi.org>
   (separate from PyPI), then under Account settings, Publishing, add a pending
   publisher: project `nephilex`, owner `Nephilex`, repository `nephilex`,
   workflow `publish.yml`, environment `testpypi`.
3. **GitHub environments.** Settings, Environments: create `pypi` and
   `testpypi`. For each, add a required reviewer, and limit deployment to tags
   matching `v*`.
4. **Branch protection on `main`.** Require pull requests, at least one
   approving review from a code owner, passing status checks, signed-off
   commits, and no force pushes or deletion.
5. **Tag protection.** A ruleset for tags matching `v*` so only maintainers can
   create them and nobody can update or delete them.

## Staging: a release candidate

1. Create a branch `release/vX.Y.ZrcN` from an up-to-date `main`.
2. Set `__version__ = "X.Y.ZrcN"` in `src/nephilex/__init__.py`. Leave the
   changelog's `## [Unreleased]` heading as it is.
3. Open a pull request titled `release: vX.Y.ZrcN` and merge it.
4. On GitHub, **Releases, Draft a new release**: tag `vX.Y.ZrcN` on `main`,
   title `vX.Y.ZrcN`, paste the Unreleased changelog section, and **tick "Set as
   a pre-release"**. Publish.
5. Approve the `testpypi` deployment. The image is pushed as `X.Y.ZrcN` and
   `rc`.
6. Install it as a user would and run it on real projects for about a week:

   ```bash
   pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ "nephilex[ast]==X.Y.ZrcN"
   docker run --rm ghcr.io/nephilex/nephilex:rc --version
   ```

   Also try the VS Code extension `.vsix` against it. Fix what you find on
   `main` and cut `rc2` if needed.

## Production: the final release

1. Create a branch `release/vX.Y.Z` from an up-to-date `main`.
2. Set `__version__ = "X.Y.Z"` in `src/nephilex/__init__.py`.
3. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add
   a new empty `## [Unreleased]` above it, and update the link references at
   the bottom of the file.
4. Update the version shown in usage examples: `action.yml` (header comment),
   `.pre-commit-hooks.yaml` (header comment), `README.md`, `docs/ci-cd.md`,
   `docs/understanding-results.md` and `docs/quickstart.md`.
5. Open a pull request titled `release: vX.Y.Z`, get it reviewed, and merge.
   **Do not create the release until this PR is merged.** The tag is made from
   `main` as it is at that moment; tagged early, it captures the previous
   version. The release workflows refuse a tag that does not match
   `__version__`, but the tag itself is protected and cannot be moved, so a
   mistaken tag costs a version number.
6. On GitHub, **Releases, Draft a new release**: tag `vX.Y.Z` on `main`, title
   `vX.Y.Z`, paste the changelog section as the description, and leave "Set as
   a pre-release" unticked. Publish.
7. Publishing the release triggers:
   - **Publish to PyPI**: verifies the tag and the channel, runs the tests,
     builds, attests provenance and the SBOM, attaches both to the release,
     waits for `pypi` environment approval, and uploads.
   - **Publish Docker image**: builds multi-arch images and pushes them with
     SBOM and provenance attestations.
8. Verify:

   ```bash
   pip install "nephilex==X.Y.Z" && nephilex --version
   docker run --rm ghcr.io/nephilex/nephilex:X.Y.Z --version
   gh attestation verify oci://ghcr.io/nephilex/nephilex:X.Y.Z --owner Nephilex
   ```

Manual uploads from a laptop are not part of the process: they bypass the
tests, the provenance attestation, and the second-person approval.
