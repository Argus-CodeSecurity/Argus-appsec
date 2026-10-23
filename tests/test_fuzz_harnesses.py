"""The fuzz harnesses in fuzz/ stay importable and hold on seeds and mutations.

ClusterFuzzLite runs them with atheris on Linux. Here they run in every CI job
with a stand-in for atheris, over real seed files plus a fixed set of
deterministic mutations, so a harness that rots or a parser that starts raising
an unexpected exception fails the normal test suite.
"""

from __future__ import annotations

import contextlib
import importlib.util
import random
import sys
import types
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FUZZ = ROOT / "fuzz"


@pytest.fixture
def fake_atheris(monkeypatch: pytest.MonkeyPatch) -> None:
    stub = types.ModuleType("atheris")
    stub.instrument_imports = contextlib.nullcontext  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "atheris", stub)


def _harness(name: str) -> Callable[[bytes], None]:
    spec = importlib.util.spec_from_file_location(f"_fuzz_{name}", FUZZ / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.TestOneInput


def _mutations(seed: bytes, count: int, rng: random.Random) -> Iterator[bytes]:
    yield seed
    for _ in range(count):
        data = bytearray(seed)
        for _ in range(rng.randint(1, 8)):
            op = rng.randrange(4)
            if op == 0 and data:
                del data[rng.randrange(len(data)) :]
            elif op == 1 and data:
                data[rng.randrange(len(data))] = rng.randrange(256)
            elif op == 2:
                pos = rng.randrange(len(data) + 1)
                data[pos:pos] = rng.choice(
                    [b"{", b"[", b'"', b":", b"\x00", b"&a", b"*a", b"- "]
                ) * rng.randint(1, 64)
            elif data:
                start = rng.randrange(len(data))
                data[start:start] = data[start : start + rng.randint(1, 32)]
        yield bytes(data)


SARIF_SEEDS = sorted((ROOT / "tests" / "fixtures" / "sarif").glob("*.sarif"))
YAML_SEEDS = [
    (ROOT / ".nephilex.yml").read_bytes(),
    b"scanners: [secrets, patterns]\nexclude_paths: ['dist/**']\nfail_on: high\n",
    b"sanitizers:\n  - name: app.clean\n    language: python\n",
    b"",
]
EDGE_CASES = [b"", b"\xff\xfe", b"null", b"[]", b"{}", b"[" * 5000, b"- " * 5000, b"&a [*a, *a]"]


@pytest.mark.usefixtures("fake_atheris")
def test_sarif_harness_holds() -> None:
    run = _harness("fuzz_sarif")
    rng = random.Random(20261023)
    assert SARIF_SEEDS
    for path in SARIF_SEEDS:
        for data in _mutations(path.read_bytes(), 40, rng):
            run(data)
    for data in EDGE_CASES:
        run(data)


@pytest.mark.usefixtures("fake_atheris")
@pytest.mark.parametrize("name", ["fuzz_config", "fuzz_context"])
def test_yaml_harnesses_hold(name: str) -> None:
    run = _harness(name)
    rng = random.Random(20261023)
    for seed in YAML_SEEDS:
        for data in _mutations(seed, 60, rng):
            run(data)
    for data in EDGE_CASES:
        run(data)
