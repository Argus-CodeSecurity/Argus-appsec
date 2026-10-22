"""Pinned public datasets: download, extract and label loading.

Each dataset is fetched as a GitHub source archive of one pinned commit, so the
numbers are attributable to an exact dataset state. Archives and extracted
trees live in ``benchmarks/.corpora/`` (git-ignored) and are never committed.
The archive's SHA-256 is recorded in the results; GitHub does not guarantee
byte-stable archives, so a mismatch is reported as a warning, while the commit
pin is what fixes the content.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import shutil
import urllib.request
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from benchmarks.public.scoring import LabeledSample, OwaspCase, parse_cwe

# Marker written after a complete extraction; a partial tree is re-extracted.
_COMPLETE = ".argus-bench-complete"


@dataclass(frozen=True)
class DatasetSpec:
    name: str
    title: str
    repo: str
    commit: str
    archive_sha256: str  # observed when the pin was set; see module docstring
    labels: str  # file inside the archive holding the ground truth
    has_negatives: bool

    @property
    def archive_url(self) -> str:
        owner_repo = self.repo.removeprefix("https://github.com/")
        return f"https://codeload.github.com/{owner_repo}/zip/{self.commit}"


DATASETS: dict[str, DatasetSpec] = {
    "owasp-python": DatasetSpec(
        name="owasp-python",
        title="OWASP Benchmark for Python v0.1",
        repo="https://github.com/OWASP-Benchmark/BenchmarkPython",
        commit="f1291485808b66e20ddb6b01b10dc71b3df8c8ba",
        archive_sha256="97761539307e95911be4b56d4227bc20b7b9ed479456a7a7a83a334c8f597ec4",
        labels="expectedresults-0.1.csv",
        has_negatives=True,
    ),
    "securityeval": DatasetSpec(
        name="securityeval",
        title="SecurityEval v2.1 (dataset.jsonl, Insecure_code)",
        repo="https://github.com/s2e-lab/SecurityEval",
        commit="6f4fb70f782c6d47b02ea24341e8ef8c1eb04a6a",
        archive_sha256="1bc64370f069a92b4ad60cdeba5df17de28ce785ba83b5e2fb052197564120aa",
        labels="dataset.jsonl",
        has_negatives=False,
    ),
}


@dataclass(frozen=True)
class Checkout:
    spec: DatasetSpec
    root: Path  # extracted archive root
    scan_root: Path  # directory the tools scan
    archive_sha256: str


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_extract(archive: Path, dest: Path) -> None:
    """Extract a GitHub archive, dropping its top-level directory.

    Members with absolute paths or ``..`` components are rejected rather than
    trusted, since the archive is third-party data.
    """
    # Extract in place and mark completion last, instead of renaming a temp dir:
    # on Windows a directory rename right after writing is often refused while
    # an antivirus scanner still holds the new files.
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            parts = PurePosixPath(info.filename).parts
            if not parts or info.filename.startswith("/") or ".." in parts:
                raise ValueError(f"unsafe archive member: {info.filename!r}")
            rel = parts[1:]  # strip "<repo>-<commit>/"
            if not rel:
                continue
            target = dest.joinpath(*rel)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out)
    (dest / _COMPLETE).write_text("ok\n", encoding="utf-8")


def fetch(spec: DatasetSpec, corpora: Path, offline: bool) -> Checkout:
    """Return the extracted dataset, downloading the pinned archive if needed."""
    base = corpora / spec.name
    archive = base / f"{spec.commit}.zip"
    root = base / spec.commit
    if not archive.is_file():
        if offline:
            raise FileNotFoundError(
                f"{spec.name}: no cached archive at {archive}; run once without --offline "
                "(or with --fetch-only) to download it"
            )
        base.mkdir(parents=True, exist_ok=True)
        print(f"  downloading {spec.archive_url}")
        part = archive.with_suffix(".zip.partial")
        with urllib.request.urlopen(spec.archive_url, timeout=300) as resp, part.open("wb") as fh:
            shutil.copyfileobj(resp, fh)
        part.replace(archive)
    digest = _sha256(archive)
    if digest != spec.archive_sha256:
        print(
            f"  WARNING: {spec.name} archive sha256 {digest} differs from the recorded "
            f"{spec.archive_sha256}; the commit pin still fixes the source, but compare "
            "the trees before trusting a diff in the numbers"
        )
    if not (root / _COMPLETE).is_file():
        _safe_extract(archive, root)
    scan_root = root
    if spec.name == "securityeval":
        scan_root = _materialize_securityeval(root)
    return Checkout(spec=spec, root=root, scan_root=scan_root, archive_sha256=digest)


# --- OWASP BenchmarkPython ---------------------------------------------------


def load_owasp_cases(checkout: Checkout) -> list[OwaspCase]:
    """Parse ``expectedresults-*.csv``: test name, category, real vuln, cwe."""
    text = (checkout.root / checkout.spec.labels).read_text(encoding="utf-8")
    return parse_owasp_expected(text)


def parse_owasp_expected(text: str) -> list[OwaspCase]:
    cases: list[OwaspCase] = []
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].lstrip().startswith("#"):
            continue
        name, category, real, cwe = (c.strip() for c in row[:4])
        parsed = parse_cwe(cwe)
        if parsed is None:
            raise ValueError(f"bad CWE in expected results row: {row!r}")
        if real.lower() not in ("true", "false"):
            raise ValueError(f"bad vulnerability flag in expected results row: {row!r}")
        cases.append(OwaspCase(name, category, parsed, real.lower() == "true"))
    return cases


# --- SecurityEval -----------------------------------------------------------


def _materialize_securityeval(root: Path) -> Path:
    """Write each ``dataset.jsonl`` sample's ``Insecure_code`` to its own file.

    ``dataset.jsonl`` is the current (v2.1) dataset: 121 samples. The
    ``Testcases_Insecure_Code`` folder still holds older samples that the
    authors removed from the dataset, so it is not scanned.
    """
    out = root / "_argus_bench_samples"
    if (out / _COMPLETE).is_file():
        return out
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir()
    for rec in _securityeval_records(root):
        sample_id = rec["ID"]
        if "/" in sample_id or "\\" in sample_id or sample_id.startswith("."):
            raise ValueError(f"unsafe SecurityEval sample id: {sample_id!r}")
        (out / sample_id).write_text(rec["Insecure_code"], encoding="utf-8", newline="\n")
    (out / _COMPLETE).write_text("ok\n", encoding="utf-8")
    return out


def _securityeval_records(root: Path) -> list[dict[str, str]]:
    records = []
    for line in (root / "dataset.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def load_securityeval_samples(checkout: Checkout) -> list[LabeledSample]:
    return parse_securityeval_ids(r["ID"] for r in _securityeval_records(checkout.root))


def parse_securityeval_ids(ids: Iterable[str]) -> list[LabeledSample]:
    """``CWE-020_author_1.py`` -> LabeledSample("CWE-020_author_1.py", 20)."""
    samples = []
    for sample_id in ids:
        cwe = parse_cwe(sample_id.split("_", 1)[0])
        if cwe is None:
            raise ValueError(f"SecurityEval id without a CWE prefix: {sample_id!r}")
        samples.append(LabeledSample(sample_id, cwe))
    return samples
