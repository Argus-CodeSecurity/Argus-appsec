#!/bin/bash -eu
# Install Nephilex the same way the release does: runtime dependencies and the
# build backend from hash locks, then the wheel without re-resolving anything.
pip3 install --require-hashes -r requirements.lock -r requirements/backend.txt
pip3 wheel --no-deps --no-build-isolation --wheel-dir /tmp/wheel .
pip3 install --no-deps /tmp/wheel/*.whl

for fuzzer in "$SRC"/nephilex/fuzz/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
done
