"""The append-only, hash-chained audit log at ``.nephilex/audit.log``.

Format: JSON Lines, one record per line, ASCII only. Every record carries the
same keys (``None`` where a field does not apply)::

    {"v": 1, "seq": 7, "ts": "2026-10-22T09:14:03.120Z",
     "actor": "Jane Developer <jane@example.com>", "action": "suppression.matched",
     "kind": "inline", "fingerprint": "ast-python.ast-sql-injection|app.py|1a2b3c4d5e6f",
     "rule": "ast-python.ast-sql-injection", "path": "app.py",
     "reason": "query text is a constant", "details": {"line": 12},
     "prev_hash": "<hash of record 6>", "hash": "<sha256 of this record>"}

``hash`` is the SHA-256 of the record's canonical JSON (sorted keys, no
whitespace, ASCII, without the ``hash`` key). ``prev_hash`` links each record
to the one before it (64 zeros for the first record) and ``seq`` counts from 1,
so editing, deleting, inserting or reordering records breaks the chain at the
first affected record. Removing records from the end does not, and neither
does rewriting the whole file with a freshly computed chain: the log is
tamper-evident, not tamper-proof, unless the head hash is kept somewhere the
writer cannot change (see ``nephilex audit verify --anchor``).

Writes take an exclusive lock on the file (``fcntl.flock`` on POSIX, a byte-
range lock far past the end of the file on Windows, so readers are never
blocked), read the current head under the lock, and append all new records in
one write. Concurrent writers therefore serialise instead of forking the chain.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: Project-relative location of the log.
AUDIT_PATH = ".nephilex/audit.log"
FORMAT_VERSION = 1
GENESIS_HASH = "0" * 64

ACTIONS = (
    "fix.applied",
    "fix.pr_opened",
    "suppression.added",
    "suppression.matched",
)
SUPPRESSION_KINDS = ("allowlist", "exception", "inline", "baseline")

FIELDS = (
    "v",
    "seq",
    "ts",
    "actor",
    "action",
    "kind",
    "fingerprint",
    "rule",
    "path",
    "reason",
    "details",
    "prev_hash",
    "hash",
)

# Lengths are capped so a hostile or careless suppression comment cannot grow
# the log without bound.
_MAX_FIELD = 500
_MAX_DETAIL_ITEMS = 50
# Reading the whole log (for de-duplication) is capped; a log past this size is
# still appended to, but de-duplicated events are skipped with a warning.
MAX_READ_BYTES = 64 * 1024 * 1024
_LOCK_TIMEOUT = 15.0
# Windows locks byte ranges, and a locked range cannot be read by other
# handles. Locking one byte far past the end of any real log keeps readers
# (nephilex audit verify, show) unblocked. It must fit a signed 32-bit offset.
_LOCK_OFFSET = 0x7FFFFFF0


class AuditLogError(RuntimeError):
    """The audit log could not be written or read."""


@dataclass
class AuditEvent:
    """One thing that happened, before it is sealed into a record."""

    action: str
    kind: str | None = None
    fingerprint: str | None = None
    rule: str | None = None
    path: str | None = None
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    #: Record only if no record with the same content is already in the log.
    once: bool = False

    def fields(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "kind": self.kind,
            "fingerprint": self.fingerprint,
            "rule": self.rule,
            "path": self.path,
            "reason": self.reason,
            "details": dict(self.details),
        }


def dedupe_key(record: dict[str, Any]) -> str:
    """The content identity used to record a suppression only once.

    Suppression-matched events are keyed by kind, finding fingerprint and
    reason; suppression-added events by kind, selector and reason. A changed
    reason is a new suppression and is recorded again.
    """
    details = record.get("details") if isinstance(record.get("details"), dict) else {}
    return json.dumps(
        [
            record.get("action"),
            record.get("kind"),
            record.get("fingerprint"),
            record.get("rule"),
            record.get("path"),
            record.get("reason"),
            (details or {}).get("selector"),
        ],
        sort_keys=True,
    )


def canonical(record: dict[str, Any]) -> bytes:
    """The bytes the record hash is computed over (everything but ``hash``)."""
    body = {k: v for k, v in record.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(record)).hexdigest()


# --- redaction -----------------------------------------------------------------
def redact(value: str) -> str:
    """Mask secret-looking values and URL credentials, then cap the length.

    The log is meant to be committed, so nothing that looks like a credential
    may reach it, even inside a suppression reason someone typed.
    """
    from nephilex.remediation.hosting import redact_credentials
    from nephilex.scanners.secrets import redact_line

    text = " ".join(str(value).split())  # one line, no control characters
    text = redact_credentials(redact_line(text[: _MAX_FIELD * 4]))
    if len(text) > _MAX_FIELD:
        text = text[: _MAX_FIELD - 3] + "..."
    return text


def _clean(value: Any, depth: int = 0) -> Any:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return str(value)
    if isinstance(value, str):
        return redact(value)
    if depth >= 3:
        return redact(str(value))
    if isinstance(value, dict):
        items = list(value.items())[:_MAX_DETAIL_ITEMS]
        return {redact(str(k))[:80]: _clean(v, depth + 1) for k, v in items}
    if isinstance(value, list | tuple | set | frozenset):
        seq = sorted(value, key=str) if isinstance(value, set | frozenset) else list(value)
        return [_clean(v, depth + 1) for v in seq[:_MAX_DETAIL_ITEMS]]
    return redact(str(value))


# --- actor ---------------------------------------------------------------------
_ACTORS: dict[str, str] = {}


def resolve_actor(root: Path) -> str:
    """Who is acting: ``git config user.name/user.email``, else the environment.

    This is a claim, not an authenticated identity: anyone can set their git
    identity. It is read with the hardened git profile because the repository
    being scanned may be hostile.
    """
    key = str(root)
    if key in _ACTORS:
        return _ACTORS[key]
    name = email = ""
    try:
        from nephilex.core import gitexec

        for cfg_key in ("user.name", "user.email"):
            res = gitexec.run(
                root,
                "config",
                "--get",
                cfg_key,
                profile=gitexec.UNTRUSTED,
                timeout=10,
                max_output=4096,
            )
            value = res.stdout.strip() if res.returncode == 0 else ""
            if cfg_key == "user.name":
                name = value
            else:
                email = value
    except Exception:  # git missing or broken: fall back to the environment
        pass
    name = name or os.environ.get("GIT_AUTHOR_NAME", "")
    email = email or os.environ.get("GIT_AUTHOR_EMAIL", "")
    if not name and not email:
        try:
            import getpass

            name = getpass.getuser()
        except Exception:
            name = "unknown"
    actor = f"{name} <{email}>" if email else name
    actor = redact(actor)[:200]
    _ACTORS[key] = actor
    return actor


def _timestamp(now: datetime | None = None) -> str:
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


# --- locking -------------------------------------------------------------------
def _lock(fd: int, timeout: float = _LOCK_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    delay = 0.005
    while True:
        try:
            if sys.platform == "win32":
                import msvcrt

                os.lseek(fd, _LOCK_OFFSET, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as exc:
            if time.monotonic() >= deadline:
                raise AuditLogError(f"could not lock the audit log within {timeout:g}s") from exc
            time.sleep(delay)
            delay = min(delay * 2, 0.1)


def _unlock(fd: int) -> None:
    try:
        if sys.platform == "win32":
            import msvcrt

            os.lseek(fd, _LOCK_OFFSET, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:  # closing the descriptor releases the lock anyway
        pass


# --- reading -------------------------------------------------------------------
def _read_range(fd: int, start: int, end: int) -> bytes:
    os.lseek(fd, start, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = end - start
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 1 << 20))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _last_line(fd: int, size: int) -> bytes:
    """The last non-empty line of the file, read from the end."""
    window = 64 * 1024
    while True:
        start = max(0, size - window)
        data = _read_range(fd, start, size)
        lines = data.split(b"\n")
        if start > 0:
            lines = lines[1:]  # the first piece may be a partial line
        for line in reversed(lines):
            if line.strip():
                return line.strip()
        if start == 0 or window >= MAX_READ_BYTES:
            return b""
        window *= 8


def _parse(line: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


@dataclass
class AppendResult:
    written: int = 0
    duplicates: int = 0
    warning: str | None = None
    path: str = AUDIT_PATH


def _log_path(root: Path) -> Path:
    """The log path under ``root``, refusing anything that escapes it.

    The scanned tree may be hostile: ``.nephilex`` or the log itself could be a
    symlink pointing at a file elsewhere that an append would then corrupt.
    """
    root_resolved = root.resolve()
    folder = root / ".nephilex"
    if folder.is_symlink():
        raise AuditLogError(".nephilex is a symlink; refusing to write the audit log through it")
    log = folder / "audit.log"
    if log.is_symlink():
        raise AuditLogError(f"{AUDIT_PATH} is a symlink; refusing to write through it")
    folder.mkdir(exist_ok=True)
    if not folder.resolve().is_relative_to(root_resolved):
        raise AuditLogError(".nephilex resolves outside the project; refusing to write")
    if log.exists() and not log.is_file():
        raise AuditLogError(f"{AUDIT_PATH} is not a regular file")
    return log


def append_events(
    root: str | Path,
    events: list[AuditEvent],
    *,
    actor: str | None = None,
    now: datetime | None = None,
) -> AppendResult:
    """Seal ``events`` into records and append them to ``root/.nephilex/audit.log``.

    Never raises: any problem (unwritable directory, lock timeout, symlinked
    path) comes back as ``AppendResult.warning`` so a scan or fix is never
    failed by its audit trail. Events with ``once`` set are skipped when an
    identical record is already in the log.
    """
    result = AppendResult()
    if not events:
        return result
    root = Path(root)
    try:
        path = _log_path(root)
        flags = (
            os.O_RDWR
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(path, flags, 0o644)
    except (OSError, AuditLogError) as exc:
        result.warning = f"audit log not written: {exc}"
        return result
    try:
        _lock(fd)
        try:
            _append_locked(fd, root, events, actor, now, result)
        finally:
            _unlock(fd)
    except (OSError, AuditLogError) as exc:
        result.warning = f"audit log not written: {exc}"
    finally:
        os.close(fd)
    return result


def _append_locked(
    fd: int,
    root: Path,
    events: list[AuditEvent],
    actor: str | None,
    now: datetime | None,
    result: AppendResult,
) -> None:
    size = os.fstat(fd).st_size
    seen: set[str] = set()
    wants_dedupe = any(e.once for e in events)
    last: dict[str, Any] | None = None
    last_raw = b""
    skip_once = False
    if wants_dedupe and size <= MAX_READ_BYTES:
        data = _read_range(fd, 0, size)
        for raw in data.split(b"\n"):
            if not raw.strip():
                continue
            last_raw = raw.strip()
            rec = _parse(last_raw)
            last = rec
            if rec is not None and str(rec.get("action", "")).startswith("suppression."):
                seen.add(dedupe_key(rec))
    else:
        if wants_dedupe:
            skip_once = True
            result.warning = (
                f"audit log is larger than {MAX_READ_BYTES} bytes; "
                "suppression events were not recorded"
            )
        last_raw = _last_line(fd, size) if size else b""
        last = _parse(last_raw) if last_raw else None

    if last_raw and (last is None or not isinstance(last.get("hash"), str)):
        # A damaged tail: keep appending (losing events is worse) but chain to
        # the raw bytes so the damage stays visible to `nephilex audit verify`.
        prev_hash = hashlib.sha256(last_raw).hexdigest()
        prev_seq = _count_lines(fd, size)
        result.warning = "audit log tail is malformed; run `nephilex audit verify`"
    elif last is not None:
        prev_hash = str(last["hash"])
        seq_value = last.get("seq")
        prev_seq = (
            seq_value
            if isinstance(seq_value, int) and not isinstance(seq_value, bool)
            else _count_lines(fd, size)
        )
    else:
        prev_hash, prev_seq = GENESIS_HASH, 0

    who = actor if actor is not None else resolve_actor(root)
    ts = _timestamp(now)
    lines: list[bytes] = []
    for event in events:
        if event.action not in ACTIONS:
            raise AuditLogError(f"unknown audit action {event.action!r}")
        body = {k: _clean(v) for k, v in event.fields().items()}
        if event.once:
            if skip_once:
                continue
            key = dedupe_key(body)
            if key in seen:
                result.duplicates += 1
                continue
            seen.add(key)
        prev_seq += 1
        record: dict[str, Any] = {
            "v": FORMAT_VERSION,
            "seq": prev_seq,
            "ts": ts,
            "actor": who,
            **body,
            "prev_hash": prev_hash,
        }
        record["hash"] = record_hash(record)
        prev_hash = record["hash"]
        lines.append(
            json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "ascii"
            )
        )
    if not lines:
        return
    payload = b"\n".join(lines) + b"\n"
    if size and _read_range(fd, size - 1, size) != b"\n":
        payload = b"\n" + payload  # never glue a record onto a partial line
    os.lseek(fd, 0, os.SEEK_END)
    view = memoryview(payload)
    while view:
        n = os.write(fd, view)
        view = view[n:]
    os.fsync(fd)
    result.written = len(lines)


def _count_lines(fd: int, size: int) -> int:
    count = 0
    pos = 0
    while pos < size:
        chunk = _read_range(fd, pos, min(size, pos + (1 << 20)))
        if not chunk:
            break
        count += sum(1 for line in chunk.split(b"\n") if line.strip())
        pos += len(chunk)
    return count


def iter_records(path: str | Path) -> Iterator[tuple[int, dict[str, Any] | None, bytes]]:
    """Yield ``(line_number, record_or_None, raw_line)`` for each non-blank line."""
    with open(path, "rb") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            yield lineno, _parse(line), line


# --- verification --------------------------------------------------------------
@dataclass
class VerifyResult:
    ok: bool
    records: int = 0
    #: Hash of the last record that verified (the chain head when ``ok``).
    head: str = GENESIS_HASH
    line: int | None = None
    seq: int | None = None
    reason: str | None = None


def verify_log(path: str | Path, *, anchor: str | None = None) -> VerifyResult:
    """Check every record's hash, link and sequence number.

    Stops at the first broken record. ``anchor`` is a record hash (or a prefix
    of at least 12 hex characters) obtained earlier from a trusted place, such
    as a CI artifact; it must still be in the chain, which catches truncation
    and wholesale rewrites that the chain alone cannot.
    """
    p = Path(path)
    if not p.is_file():
        return VerifyResult(ok=False, reason=f"no audit log at {p}")
    prev = GENESIS_HASH
    expected_seq = 1
    count = 0
    anchor_found = anchor is None
    anchor_norm = (anchor or "").strip().lower()
    try:
        for lineno, rec, _raw in iter_records(p):
            fail = _check_record(rec, prev, expected_seq)
            if fail is not None:
                seq = rec.get("seq") if isinstance(rec, dict) else None
                return VerifyResult(
                    ok=False,
                    records=count,
                    head=prev,
                    line=lineno,
                    seq=seq if isinstance(seq, int) else None,
                    reason=fail,
                )
            assert rec is not None
            prev = str(rec["hash"])
            expected_seq += 1
            count += 1
            if not anchor_found and prev.startswith(anchor_norm):
                anchor_found = True
    except OSError as exc:
        return VerifyResult(ok=False, records=count, head=prev, reason=f"cannot read log: {exc}")
    if not anchor_found:
        return VerifyResult(
            ok=False,
            records=count,
            head=prev,
            reason=(
                f"anchor {anchor_norm[:16]} is not in the chain: records were removed "
                "from the end or the log was rewritten"
            ),
        )
    return VerifyResult(ok=True, records=count, head=prev)


def _check_record(rec: dict[str, Any] | None, prev: str, expected_seq: int) -> str | None:
    if rec is None:
        return "not a JSON object; the line was edited or truncated"
    missing = [k for k in FIELDS if k not in rec]
    if missing:
        return f"missing field(s) {', '.join(missing)}"
    extra = sorted(k for k in rec if k not in FIELDS)
    if extra:
        return f"unexpected field(s) {', '.join(extra)}"
    if rec.get("v") != FORMAT_VERSION:
        return f"unsupported record version {rec.get('v')!r}"
    if not isinstance(rec.get("hash"), str) or record_hash(rec) != rec["hash"]:
        return "hash mismatch: the record's content was edited"
    seq = rec.get("seq")
    if rec.get("prev_hash") != prev:
        if isinstance(seq, int) and seq > expected_seq:
            return (
                f"prev_hash does not match the previous record and seq is {seq}, "
                f"expected {expected_seq}: records before it were deleted"
            )
        return (
            "prev_hash does not match the previous record: records were deleted, "
            "inserted or reordered, or the previous record was edited and re-hashed"
        )
    if seq != expected_seq:
        return f"seq is {seq!r}, expected {expected_seq}: records were reordered or renumbered"
    return None
