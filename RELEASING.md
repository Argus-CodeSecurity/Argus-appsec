# Releasing Nephilex

This is the maintainer runbook for cutting a release. A release produces, from
one git tag, all of the following with the same version number:

| Artifact | Where | Version form |
|---|---|---|
| Python package `nephilex` | PyPI | `0.9.0` |
| Git tag and GitHub Release | GitHub | `v0.9.0` |
| Container image | `ghcr.io/nephilex/nephilex` | `0.9.0`, `0.9`, `latest` |
| GitHub Action | `nephilex/nephilex@v0.9.0` | `v0.9.0` |
| pre-commit hooks | `rev: v0.9.0` | `v0.9.0` |
| SBOM and attestations | Release assets, Sigstore | tied to the built files |

## How the version stays consistent

- **One source of truth.** The version lives only in `src/nephilex/__init__.py`
  (`__version__`). `pyproject.toml` reads it from there
  (`[tool.hatch.version]`), so the package metadata cannot drift.
- **The tag must match.** The publish workflow refuses to release when the tag
  (`v0.9.0`) does not equal `v` + `__version__`. A mismatched release fails
  before anything is uploaded.
- **PyPI versions are permanent.** A version number can be uploaded only once,
  even if the release is later deleted. Never reuse a number; if a release is
  broken, publish the next patch version.
- **Tags are immutable.** Never move or delete a published tag. Users pin to
  them (the Action, pre-commit, Docker).

## Version numbers

Nephilex follows [Semantic Versioning](https://semver.org/) and PEP 440:

- **Patch** (`0.9.1`): bug fixes only, no behaviour change.
- **Minor** (`0.10.0`): new features. While Nephilex is pre-1.0, a minor release may
  also contain breaking changes, which must be listed under a **Breaking
  changes** heading in the changelog.
- **Major** (`1.0.0`): from 1.0 onward, breaking changes to the CLI, exit codes,
  report schemas, configuration, or plugin API require a major version. See
  [COMPATIBILITY.md](COMPATIBILITY.md).
- **Pre-releases**: `0.9.0rc1` (tag `v0.9.0rc1`). PyPI does not install
  pre-releases unless asked (`pip install --pre`), so they are safe for testing.

## One-time setup

1. **PyPI trusted publisher.** On <https://pypi.org/manage/project/nephilex/settings/publishing/>
   add a GitHub publisher: owner `nephilex`, repository
   `nephilex`, workflow `publish.yml`, environment `pypi`. No API token is
   stored anywhere.
2. **GitHub environment.** Settings, Environments, create `pypi`. Add required
   reviewers so a release needs a second person's approval before upload.
3. **Branch protection on `main`.** Require pull requests, at least one
   approving review from a code owner, passing status checks (CI, CodeQL,
   Dependency review, Docs), signed-off commits (DCO app), and linear history.
   Disallow force pushes and deletion.
4. **Tag protection.** Add a ruleset for tags matching `v*` so only maintainers
   can create them and nobody can update or delete them.

## Cutting a release

1. Create a branch `release/vX.Y.Z` from an up-to-date `main`.
2. Set `__version__ = "X.Y.Z"` in `src/nephilex/__init__.py`.
3. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add
   a new empty `## [Unreleased]` above it, and update the link references at
   the bottom of the file.
4. Update the version shown in usage examples: `action.yml` (header comment),
   `.pre-commit-hooks.yaml` (header comment), and `docs/ci-cd.md`.
5. Open a pull request titled `release: vX.Y.Z`, get it reviewed, and merge.
   **Do not create the release until this PR is merged.** The tag is made from
   `main` as it is at that moment; tagged early, it captures the previous
   version. Both release workflows refuse a tag that does not match
   `__version__`, but the tag itself is protected and cannot be moved, so a
   mistaken tag costs a version number.
6. On GitHub, **Releases, Draft a new release**: tag `vX.Y.Z` on `main`, title
   `vX.Y.Z`, and paste the changelog section as the description. Mark
   pre-releases as such. Publish.
7. Publishing the release triggers:
   - **Publish to PyPI**: verifies the tag, runs the tests, builds, attests
     provenance and the SBOM, waits for `pypi` environment approval, uploads,
     and attaches the SBOM to the release.
   - **Publish Docker image**: builds multi-arch images, pushes them with SBOM
     and provenance attestations.
8. Verify:

   ```bash
   pip install "nephilex==X.Y.Z" && nephilex --version
   docker run --rm ghcr.io/nephilex/nephilex:X.Y.Z --version
   gh attestation verify oci://ghcr.io/nephilex/nephilex:X.Y.Z --owner nephilex
   ```

## Rehearsing on TestPyPI

Register the same trusted publisher on <https://test.pypi.org>, temporarily add
`repository-url: https://test.pypi.org/legacy/` to the publish step on a branch,
publish a pre-release such as `vX.Y.Zrc1`, then install it with
`pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ nephilex==X.Y.Zrc1`.

Manual uploads from a laptop are not part of the process: they bypass the
tests, the provenance attestation, and the second-person approval.
