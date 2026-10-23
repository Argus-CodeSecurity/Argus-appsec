"""Orchestrate the fix-and-PR workflow.

Given a scan's findings and a local git repository, this:

1. (optionally) verifies the fixes with the project's tests in a temporary
   worktree and keeps only the ones that pass,
2. applies deterministic fixes to a fresh branch,
3. commits them, and
4. (optionally) pushes the branch and opens a pull request.

Every step is guarded and reported so the CLI can explain exactly what happened
or why it stopped. Nothing is pushed or opened unless explicitly requested.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from nephilex.audit import AUDIT_PATH
from nephilex.core.models import Finding
from nephilex.core.project import Project
from nephilex.remediation import git_ops
from nephilex.remediation.applier import APPLIED_KEY, ApplyReport, apply_fixes, record_fix_events
from nephilex.remediation.hosting import (
    HostingError,
    PullRequest,
    open_pull_request,
    parse_remote,
    redact_credentials,
)
from nephilex.remediation.testverify import (
    TEST_STATUS_LABELS,
    TESTS_PASSED,
    TestVerification,
    VerificationReport,
    content_digest,
    verify_fixes_with_tests,
)
from nephilex.reporting.md_escape import md_code, md_fence

DEFAULT_BRANCH_NAME = "nephilex/security-fixes"


@dataclass
class FixOptions:
    branch: str = DEFAULT_BRANCH_NAME
    base: str | None = None  # None -> detect the repo's default branch
    open_pr: bool = False
    include_unverified: bool = False
    dry_run: bool = False
    force_branch: bool = False  # overwrite the branch if it already exists
    annotate: bool = False  # post inline review comments on the opened PR
    # Autonomy ladder: when set, apply only these rule ids (auto-tier fixes).
    only_rules: set[str] | None = None
    # Skip commit hooks (git commit --no-verify). Off by default: hooks such as
    # DCO sign-off or secret scanning must run unless the user opts out.
    no_verify: bool = False
    # Append fix.applied / fix.pr_opened records to .nephilex/audit.log. The
    # CLI passes the config's audit_log setting; NEPHILEX_AUDIT_LOG=off also
    # turns them off.
    audit: bool = True
    # Run the project's tests in a temporary worktree before committing and
    # keep only the fixes that pass (`nephilex fix --verify-with-tests`).
    verify_tests: TestVerification | None = None


@dataclass
class FixOutcome:
    applied: ApplyReport
    committed: bool = False
    commit_sha: str | None = None
    branch: str | None = None
    pushed: bool = False
    pull_request: PullRequest | None = None
    messages: list[str] = field(default_factory=list)  # human-readable notes
    error: str | None = None
    # Per-fix test results when the fixes were verified with tests.
    verification: VerificationReport | None = None

    def note(self, msg: str) -> None:
        self.messages.append(msg)


def run_fix_workflow(project: Project, findings: list[Finding], options: FixOptions) -> FixOutcome:
    root = Path(project.root)

    # Dry run: preview the file changes only, touch nothing.
    if options.dry_run and options.verify_tests is not None:
        return FixOutcome(
            applied=ApplyReport(),
            error="Test verification cannot be combined with a dry run.",
        )
    if options.dry_run:
        report = apply_fixes(
            project,
            findings,
            include_unverified=options.include_unverified,
            dry_run=True,
            only_rules=options.only_rules,
        )
        outcome = FixOutcome(applied=report)
        if options.only_rules is not None:
            outcome.note(
                f"Auto-tier: only {len(options.only_rules)} auto-approved rule(s) considered."
            )
        outcome.note(report.summary() + " (dry run, no files written)")
        return outcome

    if not git_ops.git_available():
        return FixOutcome(applied=ApplyReport(), error="git is not installed.")
    if not git_ops.is_git_repo(root):
        return FixOutcome(
            applied=ApplyReport(),
            error=(
                "Target is not a git repository. `nephilex fix` needs a local git "
                "repo to create a branch and commit fixes."
            ),
        )

    # Safety: refuse to operate on a dirty working tree. `nephilex fix` creates a
    # branch and commits; on a dirty tree that would sweep the developer's own
    # uncommitted work into the fix commit (and, with --open-pr, into a public
    # pull request). Require a clean tree so the fixes land isolated. The audit
    # log is the one exception: the scan that produced these findings may have
    # just appended to it, and it is committed together with the fixes.
    if _has_changes_besides_audit_log(root):
        return FixOutcome(
            applied=ApplyReport(),
            error=(
                "Working tree has uncommitted changes. Commit, stash, or discard "
                "them first so Nephilex's fixes land in a clean, isolated commit."
            ),
        )

    base = options.base or git_ops.default_branch(root)
    outcome = FixOutcome(applied=ApplyReport(), branch=options.branch)

    # The findings (and their line numbers) come from the checked-out HEAD, but
    # the fix branch starts at base. If the two differ, fixes would be applied
    # to different code than was scanned, so refuse rather than guess.
    head_sha = git_ops.rev_parse(root, "HEAD")
    base_sha = git_ops.rev_parse(root, base)
    if base_sha is None:
        return FixOutcome(
            applied=ApplyReport(), error=f"Base '{base}' does not resolve to a commit."
        )
    if head_sha != base_sha:
        current = git_ops.current_branch(root)
        return FixOutcome(
            applied=ApplyReport(),
            error=(
                f"The scanned checkout ('{current}' at {(head_sha or '?')[:8]}) is "
                f"not the base '{base}' ({base_sha[:8]}), so the findings do not "
                f"match the code the fix branch would start from. Check out "
                f"'{base}' and re-run, or pass --base {current} to target the "
                f"current branch."
            ),
        )

    # Where to return to if anything fails: the branch (or detached commit) the
    # user was on.
    original = git_ops.current_branch(root)
    if original == "HEAD":
        original = head_sha or base
    existed = git_ops.branch_exists(root, options.branch)
    if existed and not options.force_branch:
        return FixOutcome(
            applied=ApplyReport(),
            error=(
                f"Branch '{options.branch}' already exists. Delete it, pick "
                f"another with --branch, or pass --force-branch."
            ),
        )

    # With --verify-with-tests, decide which fixes may land before touching
    # the operator's checkout: everything runs in a temporary worktree.
    to_fix = findings
    verification: VerificationReport | None = None
    if options.verify_tests is not None:
        try:
            verification = verify_fixes_with_tests(
                project,
                findings,
                options.verify_tests,
                commit=head_sha or base_sha,
                include_unverified=options.include_unverified,
                only_rules=options.only_rules,
            )
        except Exception as exc:
            return FixOutcome(
                applied=ApplyReport(),
                error=f"Test verification failed: {exc}. Nothing was committed.",
            )
        stop = _verification_outcome(verification, options)
        if stop is not None:
            return stop
        passed = verification.passed_ids()
        to_fix = [f for f in findings if f.id in passed]

    audit_snapshot = _snapshot_audit_log(root)

    # Create (or, with --force-branch, reset) the working branch at base.
    try:
        git_ops.create_branch(root, options.branch, base=base, reset=existed)
        verb = "Reset" if existed else "Created"
        if verification is not None:
            outcome.verification = verification
            _note_verification(outcome, verification)
        outcome.note(f"{verb} branch '{options.branch}' at '{base}'.")
    except git_ops.GitError as exc:
        return FixOutcome(applied=ApplyReport(), error=str(exc), verification=verification)

    try:
        # Apply the fixes on the branch.
        report = apply_fixes(
            project,
            to_fix,
            include_unverified=options.include_unverified,
            dry_run=False,
            only_rules=options.only_rules,
            # With test verification the records are written below, once
            # each fix carries its test result.
            audit=options.audit and verification is None,
        )
        outcome.applied = report
        if verification is not None:
            _match_tested_fixes(root, report, verification)
            if options.audit:
                record_fix_events(root, "fix.applied", report.fixes, report)
        if options.only_rules is not None:
            outcome.note(
                f"Auto-tier: only {len(options.only_rules)} auto-approved rule(s) considered."
            )
        if not report.any_changes:
            outcome.note("No deterministic fixes could be applied; nothing to commit.")
            # Return to where the user was so an empty branch is not left checked out.
            _rollback(root, original, options.branch, delete=not existed, outcome=outcome)
            return outcome

        # Commit. Stage only the files Nephilex rewrote, never `git add -A`, so
        # nothing outside the fix set can be swept into the commit. The audit
        # log goes in the same commit, so the record of each fix travels with
        # it, unless the project ignores .nephilex/ in git.
        to_stage = list(report.changed_files)
        audit_state = _audit_log_state(root)
        if audit_state == "committable":
            to_stage.append(AUDIT_PATH)
        elif audit_state == "ignored":
            outcome.note(f"{AUDIT_PATH} is ignored by git, so it was not committed.")
        git_ops.stage_paths(root, to_stage)
        message = _commit_message(report, verification)
        outcome.commit_sha = git_ops.commit(root, message, no_verify=options.no_verify)
        outcome.committed = True
        outcome.note(f"Committed {len(report.fixes)} fix(es) as {outcome.commit_sha[:8]}.")
    except Exception as exc:
        # Never leave rewritten files or a half-made branch behind: discard the
        # changes (the tree was verified clean above) and go back.
        outcome.error = f"Fix failed: {exc}"
        for finding in findings:
            finding.metadata.pop(APPLIED_KEY, None)
            if finding.metadata.get("verification") == "fixed":
                finding.metadata.pop("verification")
        _rollback(root, original, options.branch, delete=not existed, outcome=outcome, discard=True)
        # The fixes never landed, so neither do their fix.applied records: put
        # the log back exactly as it was before this run (reset --hard does
        # not touch an untracked log, and discards an uncommitted one).
        _restore_audit_log(root, audit_snapshot)
        return outcome

    if outcome.applied.audit_warning:
        outcome.note(f"Audit log: {outcome.applied.audit_warning}")

    if not options.open_pr:
        outcome.note(
            "Branch committed locally. Re-run with --open-pr to push and open a pull request."
        )
        return outcome

    # Push and open the PR.
    _push_and_open_pr(root, base, options, report, outcome)
    return outcome


def _push_and_open_pr(
    root: Path, base: str, options: FixOptions, report: ApplyReport, outcome: FixOutcome
) -> None:
    remote = git_ops.remote_url(root)
    if not remote:
        outcome.error = (
            "No git remote configured, so the branch cannot be pushed. "
            "Add a remote (git remote add origin <url>) and retry."
        )
        return
    ref = parse_remote(remote)
    if ref is None:
        outcome.error = f"Unsupported or unrecognized git remote: {redact_credentials(remote)}"
        return
    try:
        git_ops.push(root, options.branch, set_upstream=True, force=options.force_branch)
        outcome.pushed = True
        outcome.note(f"Pushed '{options.branch}' to {ref.slug}.")
    except git_ops.GitError as exc:
        outcome.error = f"Push failed: {redact_credentials(str(exc))}"
        return

    try:
        pr = open_pull_request(
            ref,
            head=options.branch,
            base=base,
            title=_pr_title(report),
            body=_pr_body(report, outcome.verification),
        )
        outcome.pull_request = pr
        outcome.note(f"Opened pull request: {pr.url}")
        # Appended after the push, so this record is in the working tree of
        # the fix branch, not in the pull request itself.
        if options.audit:
            record_fix_events(
                root,
                "fix.pr_opened",
                report.fixes,
                branch=options.branch,
                base=base,
                commit=outcome.commit_sha,
                pr_url=redact_credentials(pr.url or ""),
                pr_number=pr.number,
            )
    except HostingError as exc:
        outcome.error = str(exc)
        return

    if options.annotate and pr.number is not None:
        from nephilex.remediation.annotations import build_fix_comments
        from nephilex.remediation.hosting import post_pr_review

        comments = build_fix_comments(report)
        try:
            post_pr_review(
                ref, pr.number, comments, summary="Nephilex applied these security fixes inline."
            )
            outcome.note(f"Posted {len(comments)} inline annotation(s) on the pull request.")
        except HostingError as exc:  # annotation failure must not fail the whole run
            outcome.note(f"Could not post inline annotations: {exc}")


def _verification_outcome(
    verification: VerificationReport, options: FixOptions
) -> FixOutcome | None:
    """The outcome to return when test verification leaves nothing to commit."""
    if verification.error:
        outcome = FixOutcome(
            applied=ApplyReport(), error=verification.error, verification=verification
        )
        _note_verification(outcome, verification)
        return outcome
    if verification.passed_ids():
        return None
    outcome = FixOutcome(applied=ApplyReport(), verification=verification)
    _note_verification(outcome, verification)
    if options.only_rules is not None:
        outcome.note(f"Auto-tier: only {len(options.only_rules)} auto-approved rule(s) considered.")
    if verification.fixes:
        outcome.note("No fix passed test verification; nothing was committed.")
    else:
        outcome.note("No deterministic fixes could be applied; nothing to commit.")
    return outcome


def _note_verification(outcome: FixOutcome, verification: VerificationReport) -> None:
    """Explain the test runs in the outcome's notes (shown to the operator only)."""
    v = verification
    if v.removed_env:
        shown = ", ".join(v.removed_env[:8]) + (" ..." if len(v.removed_env) > 8 else "")
        outcome.note(
            f"Test environment: removed {len(v.removed_env)} variable(s) that look "
            f"like credentials ({shown})."
        )
    if v.baseline is not None:
        outcome.note(f"Tests before the fixes ({v.command}): {v.baseline.describe(v.timeout)}.")
    if v.after is not None:
        outcome.note(f"Tests with the fixes applied: {v.after.describe(v.timeout)}.")
    for run in (v.baseline, v.after):
        if run is not None and not run.passed and run.output.strip():
            outcome.note("Last lines of the test output:\n" + run.tail())
            break
    for msg in v.notes:
        outcome.note(msg)


def _match_tested_fixes(root: Path, report: ApplyReport, verification: VerificationReport) -> None:
    """Carry the test results over, and refuse to commit anything that was not tested.

    The fixes are applied a second time, now on the branch; the applier is
    deterministic, so the files must equal the ones the tests ran against.
    """
    by_id = {fix.finding_id: fix for fix in verification.fixes}
    for fix in report.fixes:
        tested = by_id.get(fix.finding_id)
        if tested is None or tested.tests != TESTS_PASSED:
            raise RuntimeError(f"{fix.path}:{fix.line} was not verified with tests")
        fix.tests, fix.tests_reason = tested.tests, tested.tests_reason
    if set(report.changed_files) != set(verification.tested_files):
        raise RuntimeError("the fixed files differ from the ones the tests ran against")
    for rel in report.changed_files:
        if content_digest((root / rel).read_bytes()) != verification.tested_files[rel]:
            raise RuntimeError(f"{rel} differs from the version the tests ran against")


def _has_changes_besides_audit_log(root: Path) -> bool:
    """Like ``git_ops.has_uncommitted_changes``, ignoring ``.nephilex/audit.log``."""
    # ":/" is the whole working tree (not just root, which may be a
    # subdirectory); the exclude pathspec is relative to root.
    # Untracked files are listed one by one so that a new, untracked log is
    # excluded too (by default git would report the whole ".nephilex/" folder).
    proc = git_ops._run(
        root,
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        ":/",
        f":(exclude){AUDIT_PATH}",
        check=False,
    )
    if proc.returncode != 0:  # be conservative: an unknown state counts as dirty
        return git_ops.has_uncommitted_changes(root)
    return bool(proc.stdout.strip())


@dataclass
class _AuditSnapshot:
    folder_existed: bool
    content: bytes | None  # None: the log did not exist


def _snapshot_audit_log(root: Path) -> _AuditSnapshot:
    log = root / AUDIT_PATH
    try:
        content = log.read_bytes() if log.is_file() and not log.is_symlink() else None
    except OSError:
        content = None
    return _AuditSnapshot(folder_existed=log.parent.is_dir(), content=content)


def _restore_audit_log(root: Path, snapshot: _AuditSnapshot) -> None:
    """Undo this run's appends to the audit log after a failed fix (best effort)."""
    log = root / AUDIT_PATH
    try:
        if log.is_symlink():
            return
        if snapshot.content is None:
            log.unlink(missing_ok=True)
            if not snapshot.folder_existed and log.parent.is_dir():
                log.parent.rmdir()  # only succeeds if this run created it empty
        elif not log.is_file() or log.read_bytes() != snapshot.content:
            log.write_bytes(snapshot.content)
    except OSError:
        pass


def _audit_log_state(root: Path) -> str:
    """``absent``, ``ignored`` (by .gitignore) or ``committable``."""
    if not (root / AUDIT_PATH).is_file():
        return "absent"
    proc = git_ops._run(root, "check-ignore", "-q", "--", AUDIT_PATH, check=False)
    # check-ignore exits 1 when the path is not ignored (0: ignored, 128:
    # error). Only a clear "not ignored" stages it: a failed `git add` would
    # roll the whole fix back.
    return "committable" if proc.returncode == 1 else "ignored"


def _rollback(
    root: Path,
    original: str,
    branch: str,
    *,
    delete: bool,
    outcome: FixOutcome,
    discard: bool = False,
) -> None:
    """Return the repo to ``original``, optionally discarding Nephilex's edits.

    With ``discard``, uncommitted changes are thrown away; this is only safe
    because the workflow refuses to start on a dirty tree. ``delete`` removes
    the fix branch when this run created it.
    """
    try:
        if discard:
            git_ops.reset_hard(root)
        git_ops.checkout(root, original)
        if delete:
            git_ops.delete_branch(root, branch)
    except git_ops.GitError as exc:
        outcome.note(f"Could not restore '{original}': {exc}")


# --- message/body builders -------------------------------------------------
def _commit_message(report: ApplyReport, verification: VerificationReport | None = None) -> str:
    n = len(report.fixes)
    rules = sorted({f.rule_id for f in report.fixes})
    header = f"fix(security): apply {n} Nephilex fix{'es' if n != 1 else ''}"
    lines = [header, "", "Applied automated security fixes:"]
    for fix in report.fixes:
        mark = "verified" if fix.verified else "unverified"
        if fix.tests:
            mark += f", tests {TEST_STATUS_LABELS.get(fix.tests, fix.tests)}"
        lines.append(f"- {fix.path}:{fix.line} {fix.rule_id} ({mark})")
    lines += ["", f"Rules: {', '.join(rules)}"]
    if verification is not None:
        lines += ["", _verification_sentence(verification)]
    lines += [
        "",
        "Generated by Nephilex (https://github.com/nephilex/nephilex).",
    ]
    return "\n".join(lines)


def _verification_sentence(verification: VerificationReport) -> str:
    counts = verification.counts()
    left_out = counts["failed"] + counts["not_verified"]
    text = (
        "The project's test command passed before and after these fixes in a "
        "clean temporary worktree, and a rescan of the fixed files found neither "
        "the original findings nor any new High or Critical finding."
    )
    if left_out:
        text += (
            f" {left_out} other fix(es) were left out: {counts['failed']} failed "
            f"and {counts['not_verified']} could not be verified."
        )
    return text


def _pr_title(report: ApplyReport) -> str:
    n = len(report.fixes)
    return f"Nephilex: fix {n} security finding{'s' if n != 1 else ''}"


def _pr_body(report: ApplyReport, verification: VerificationReport | None = None) -> str:
    tested = verification is not None
    lines = [
        "## Automated security fixes by Nephilex",
        "",
        f"This pull request applies **{len(report.fixes)}** deterministic security "
        f"fix(es) across **{len(report.changed_files)}** file(s). Each change is a "
        "minimal, line-level rewrite that removes the detected weakness.",
        "",
        "| File | Line | Rule | Verified |" + (" Tests |" if tested else ""),
        "|------|------|------|----------|" + ("-------|" if tested else ""),
    ]
    for f in report.fixes:
        tests = f" {TEST_STATUS_LABELS.get(f.tests or '', 'not run')} |" if tested else ""
        lines.append(
            f"| {md_code(f.path, in_table=True)} | {f.line} | "
            f"{md_code(f.rule_id, in_table=True)} | "
            f"{'yes' if f.verified else 'no'} |" + tests
        )
    if verification is not None:
        lines += ["", "### Test verification", "", _verification_sentence(verification)]
    lines += [
        "",
        "<details><summary>Diffs</summary>",
        "",
    ]
    for f in report.fixes:
        lines += [*md_fence(f.unified_diff().rstrip(), "diff"), ""]
    lines += [
        "</details>",
        "",
        "**Verified** fixes are ones where Nephilex re-checked the rewritten line and "
        "confirmed the detection no longer fires."
        + (
            " **Tests** is the result of the project's own test command with the "
            "fixes applied; a passing run is evidence, not proof, that behavior is "
            "unchanged."
            if tested
            else ""
        )
        + " Please review before merging.",
        "",
        "_Generated by [Nephilex](https://github.com/nephilex/nephilex)._",
    ]
    return "\n".join(lines)
