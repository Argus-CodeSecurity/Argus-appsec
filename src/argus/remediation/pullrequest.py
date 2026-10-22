"""Orchestrate the fix-and-PR workflow.

Given a scan's findings and a local git repository, this:

1. applies deterministic fixes to a fresh branch,
2. commits them, and
3. (optionally) pushes the branch and opens a pull request.

Every step is guarded and reported so the CLI can explain exactly what happened
or why it stopped. Nothing is pushed or opened unless explicitly requested.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from argus.core.models import Finding
from argus.core.project import Project
from argus.remediation import git_ops
from argus.remediation.applier import ApplyReport, apply_fixes
from argus.remediation.hosting import (
    HostingError,
    PullRequest,
    open_pull_request,
    parse_remote,
)
from argus.reporting.md_escape import md_code, md_fence

DEFAULT_BRANCH_NAME = "argus/security-fixes"


@dataclass
class FixOptions:
    branch: str = DEFAULT_BRANCH_NAME
    base: str | None = None            # None -> detect the repo's default branch
    open_pr: bool = False
    include_unverified: bool = False
    dry_run: bool = False
    force_branch: bool = False         # overwrite the branch if it already exists
    annotate: bool = False             # post inline review comments on the opened PR
    # Autonomy ladder: when set, apply only these rule ids (auto-tier fixes).
    only_rules: set[str] | None = None


@dataclass
class FixOutcome:
    applied: ApplyReport
    committed: bool = False
    commit_sha: str | None = None
    branch: str | None = None
    pushed: bool = False
    pull_request: PullRequest | None = None
    messages: list[str] = field(default_factory=list)   # human-readable notes
    error: str | None = None

    def note(self, msg: str) -> None:
        self.messages.append(msg)


def run_fix_workflow(project: Project, findings: list[Finding],
                     options: FixOptions) -> FixOutcome:
    root = Path(project.root)

    # Dry run: preview the file changes only, touch nothing.
    if options.dry_run:
        report = apply_fixes(project, findings,
                             include_unverified=options.include_unverified,
                             dry_run=True, only_rules=options.only_rules)
        outcome = FixOutcome(applied=report)
        if options.only_rules is not None:
            outcome.note(f"Auto-tier: only {len(options.only_rules)} "
                         "auto-approved rule(s) considered.")
        outcome.note(report.summary() + " (dry run, no files written)")
        return outcome

    if not git_ops.git_available():
        return FixOutcome(applied=ApplyReport(), error="git is not installed.")
    if not git_ops.is_git_repo(root):
        return FixOutcome(
            applied=ApplyReport(),
            error=("Target is not a git repository. `argus fix` needs a local git "
                   "repo to create a branch and commit fixes."),
        )

    # Safety: refuse to operate on a dirty working tree. `argus fix` creates a
    # branch and commits; on a dirty tree that would sweep the developer's own
    # uncommitted work into the fix commit (and, with --open-pr, into a public
    # pull request). Require a clean tree so the fixes land isolated.
    if git_ops.has_uncommitted_changes(root):
        return FixOutcome(
            applied=ApplyReport(),
            error=("Working tree has uncommitted changes. Commit, stash, or discard "
                   "them first so Argus's fixes land in a clean, isolated commit."),
        )

    base = options.base or git_ops.default_branch(root)
    outcome = FixOutcome(applied=ApplyReport(), branch=options.branch)

    # Create (or reset) the working branch from base.
    try:
        if git_ops.branch_exists(root, options.branch):
            if not options.force_branch:
                return FixOutcome(
                    applied=ApplyReport(),
                    error=(f"Branch '{options.branch}' already exists. Delete it, pick "
                           f"another with --branch, or pass --force-branch."),
                )
            git_ops.checkout(root, options.branch)
        else:
            git_ops.create_branch(root, options.branch, base=base)
        outcome.note(f"Created branch '{options.branch}' from '{base}'.")
    except git_ops.GitError as exc:
        return FixOutcome(applied=ApplyReport(), error=str(exc))

    # Apply the fixes on the branch.
    report = apply_fixes(project, findings,
                         include_unverified=options.include_unverified,
                         dry_run=False, only_rules=options.only_rules)
    outcome.applied = report
    if options.only_rules is not None:
        outcome.note(f"Auto-tier: only {len(options.only_rules)} "
                     "auto-approved rule(s) considered.")
    if not report.any_changes:
        outcome.note("No deterministic fixes could be applied; nothing to commit.")
        # Return to the base branch so we don't leave an empty branch checked out.
        _safe_checkout(root, base, outcome)
        return outcome

    # Commit. Stage only the files Argus rewrote, never `git add -A`, so nothing
    # outside the fix set can be swept into the commit.
    try:
        git_ops.stage_paths(root, report.changed_files)
        message = _commit_message(report)
        outcome.commit_sha = git_ops.commit(root, message)
        outcome.committed = True
        outcome.note(f"Committed {len(report.fixes)} fix(es) as {outcome.commit_sha[:8]}.")
    except git_ops.GitError as exc:
        outcome.error = f"Commit failed: {exc}"
        return outcome

    if not options.open_pr:
        outcome.note("Branch committed locally. Re-run with --open-pr to push and "
                     "open a pull request.")
        return outcome

    # Push and open the PR.
    _push_and_open_pr(root, base, options, report, outcome)
    return outcome


def _push_and_open_pr(root: Path, base: str, options: FixOptions,
                      report: ApplyReport, outcome: FixOutcome) -> None:
    remote = git_ops.remote_url(root)
    if not remote:
        outcome.error = ("No git remote configured, so the branch cannot be pushed. "
                         "Add a remote (git remote add origin <url>) and retry.")
        return
    ref = parse_remote(remote)
    if ref is None:
        outcome.error = f"Unsupported or unrecognized git remote: {remote}"
        return
    try:
        git_ops.push(root, options.branch, set_upstream=True, force=options.force_branch)
        outcome.pushed = True
        outcome.note(f"Pushed '{options.branch}' to {ref.slug}.")
    except git_ops.GitError as exc:
        outcome.error = f"Push failed: {exc}"
        return

    try:
        pr = open_pull_request(
            ref, head=options.branch, base=base,
            title=_pr_title(report), body=_pr_body(report),
        )
        outcome.pull_request = pr
        outcome.note(f"Opened pull request: {pr.url}")
    except HostingError as exc:
        outcome.error = str(exc)
        return

    if options.annotate and pr.number is not None:
        from argus.remediation.annotations import build_fix_comments
        from argus.remediation.hosting import post_pr_review

        comments = build_fix_comments(report)
        try:
            post_pr_review(ref, pr.number, comments,
                           summary="Argus applied these security fixes inline.")
            outcome.note(f"Posted {len(comments)} inline annotation(s) on the pull request.")
        except HostingError as exc:  # annotation failure must not fail the whole run
            outcome.note(f"Could not post inline annotations: {exc}")


def _safe_checkout(root: Path, branch: str, outcome: FixOutcome) -> None:
    try:
        git_ops.checkout(root, branch)
    except git_ops.GitError as exc:  # pragma: no cover - defensive
        outcome.note(f"Could not switch back to '{branch}': {exc}")


# --- message/body builders -------------------------------------------------
def _commit_message(report: ApplyReport) -> str:
    n = len(report.fixes)
    rules = sorted({f.rule_id for f in report.fixes})
    header = f"fix(security): apply {n} Argus fix{'es' if n != 1 else ''}"
    lines = [header, "", "Applied automated security fixes:"]
    for fix in report.fixes:
        mark = "verified" if fix.verified else "unverified"
        lines.append(f"- {fix.path}:{fix.line} {fix.rule_id} ({mark})")
    lines += ["", f"Rules: {', '.join(rules)}", "",
              "Generated by Argus (https://github.com/Argus-CodeSecurity/Argus-appsec)."]
    return "\n".join(lines)


def _pr_title(report: ApplyReport) -> str:
    n = len(report.fixes)
    return f"Argus: fix {n} security finding{'s' if n != 1 else ''}"


def _pr_body(report: ApplyReport) -> str:
    lines = [
        "## Automated security fixes by Argus",
        "",
        f"This pull request applies **{len(report.fixes)}** deterministic security "
        f"fix(es) across **{len(report.changed_files)}** file(s). Each change is a "
        "minimal, line-level rewrite that removes the detected weakness.",
        "",
        "| File | Line | Rule | Verified |",
        "|------|------|------|----------|",
    ]
    for f in report.fixes:
        lines.append(f"| {md_code(f.path, in_table=True)} | {f.line} | "
                     f"{md_code(f.rule_id, in_table=True)} | "
                     f"{'yes' if f.verified else 'no'} |")
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
        "**Verified** fixes are ones where Argus re-checked the rewritten line and "
        "confirmed the detection no longer fires. Please review before merging.",
        "",
        "_Generated by [Argus](https://github.com/Argus-CodeSecurity/Argus-appsec)._",
    ]
    return "\n".join(lines)
