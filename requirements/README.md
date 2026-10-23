# Hash-locked requirements for CI and builds

Every install in CI, the release workflow, the Docker image and the fuzzing
build uses `pip install --require-hashes` against these files. A package that
changes upstream, or a look-alike that a typo would pull in, fails the install.
Nephilex itself is then built with `--no-build-isolation` (so pip fetches no
build backend) and installed with `--no-deps`.

| Lock file | Used by | Generated from |
|---|---|---|
| `dev.txt` | CI lint, type check and tests; release tests | `pyproject.toml` extras `dev` and `ast`, plus `backend.in` |
| `scan.txt` | the self-scan workflow | `pyproject.toml` runtime dependencies and the `ast` extra |
| `docs.txt` | the docs build and deploy | `docs.in` |
| `build.txt` | building and checking the sdist and wheel | `build.in` |
| `backend.txt` | building the wheel in Docker, ClusterFuzzLite and the self-scan | `backend.in` |
| `sbom.txt` | generating the release SBOM | `sbom.in` |

The runtime lock for the published image is `../requirements.lock`.

## Regenerating

Each file starts with the exact command that produced it. They are universal
locks (Python 3.10 and later on Linux, macOS and Windows), made with
[uv](https://docs.astral.sh/uv/). From the repository root:

```bash
uv pip compile pyproject.toml requirements/backend.in --extra dev --extra ast --universal --python-version 3.10 --generate-hashes -o requirements/dev.txt
uv pip compile pyproject.toml --extra ast --universal --python-version 3.10 --generate-hashes -o requirements/scan.txt
uv pip compile requirements/docs.in --universal --python-version 3.10 --generate-hashes -o requirements/docs.txt
uv pip compile requirements/build.in --universal --python-version 3.10 --generate-hashes -o requirements/build.txt
uv pip compile requirements/backend.in --universal --python-version 3.10 --generate-hashes -o requirements/backend.txt
uv pip compile requirements/sbom.in --universal --python-version 3.10 --generate-hashes -o requirements/sbom.txt
```

Regenerate `dev.txt` and `scan.txt` after changing dependencies in
`pyproject.toml`, and `docs.in` must follow the `docs` extra.
