"""Git hosting clients: open a pull/merge request via a provider's API.

Supports GitHub, GitLab, and Bitbucket Cloud today. The remote-URL parsing and
remote-URL parsing and request-payload construction are separated from the
network call so they can be unit-tested without credentials or connectivity.

Tokens are read from the environment: ``GITHUB_TOKEN`` / ``GITLAB_TOKEN``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import quote

import httpx


class HostingError(RuntimeError):
    pass


@dataclass
class RepoRef:
    host: str          # "github" | "gitlab" | "bitbucket"
    owner: str         # org/user (or full namespace path for GitLab subgroups)
    repo: str          # repository name
    web_base: str      # e.g. "https://github.com"

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


_HOSTS = {
    "github.com": ("github", "https://github.com"),
    "gitlab.com": ("gitlab", "https://gitlab.com"),
    "bitbucket.org": ("bitbucket", "https://bitbucket.org"),
}


def parse_remote(url: str) -> RepoRef | None:
    """Parse a git remote URL (https or ssh) into a RepoRef, or None if unknown."""
    url = url.strip()
    host = owner_repo = None

    # SSH form: git@github.com:owner/repo(.git)
    m = re.match(r"^git@([^:]+):(.+?)(?:\.git)?/?$", url)
    if m:
        host, owner_repo = m.group(1), m.group(2)
    else:
        # HTTPS form: https://github.com/owner/repo(.git)
        m = re.match(r"^https?://(?:[^@/]+@)?([^/]+)/(.+?)(?:\.git)?/?$", url)
        if m:
            host, owner_repo = m.group(1), m.group(2)

    if not host or not owner_repo or host.lower() not in _HOSTS:
        return None

    host_key, web_base = _HOSTS[host.lower()]
    parts = owner_repo.split("/")
    if len(parts) < 2:
        return None
    repo = parts[-1]
    owner = "/".join(parts[:-1])
    return RepoRef(host=host_key, owner=owner, repo=repo, web_base=web_base)


@dataclass
class PullRequest:
    url: str
    number: int | None = None


def token_for(host: str) -> str | None:
    return {
        "github": os.environ.get("GITHUB_TOKEN"),
        "gitlab": os.environ.get("GITLAB_TOKEN"),
        "bitbucket": os.environ.get("BITBUCKET_TOKEN"),
    }.get(host)


def open_pull_request(
    ref: RepoRef, *, head: str, base: str, title: str, body: str,
    token: str | None = None, timeout: float = 30.0,
) -> PullRequest:
    """Open a PR/MR on the appropriate host. Raises HostingError on failure."""
    token = token or token_for(ref.host)
    if not token:
        env = {"github": "GITHUB_TOKEN", "gitlab": "GITLAB_TOKEN", "bitbucket": "BITBUCKET_TOKEN"}.get(ref.host, "TOKEN")
        raise HostingError(
            f"No API token found for {ref.host}. Set {env} to open a pull request."
        )

    if ref.host == "github":
        return _github_pr(ref, head, base, title, body, token, timeout)
    if ref.host == "gitlab":
        return _gitlab_mr(ref, head, base, title, body, token, timeout)
    if ref.host == "bitbucket":
        return _bitbucket_pr(ref, head, base, title, body, token, timeout)
    raise HostingError(f"Opening pull requests on {ref.host} is not yet supported.")


def _github_pr(ref: RepoRef, head: str, base: str, title: str, body: str,
               token: str, timeout: float) -> PullRequest:
    url = f"https://api.github.com/repos/{ref.owner}/{ref.repo}/pulls"
    resp = httpx.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json={"title": title, "head": head, "base": base, "body": body},
        timeout=timeout,
    )
    if resp.status_code >= 300:
        raise HostingError(f"GitHub API error {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    return PullRequest(url=data.get("html_url", ""), number=data.get("number"))


def post_pr_review(ref: RepoRef, number: int, comments: list[dict], *,
                   summary: str = "", token: str | None = None,
                   timeout: float = 30.0) -> None:
    """Post a PR review with inline comments (GitHub only). Raises HostingError.

    Each comment is a dict with ``path``, ``line``, ``side``, and ``body``, as
    produced by :func:`argus.remediation.annotations.build_fix_comments`.
    """
    if not comments:
        return
    if ref.host != "github":
        raise HostingError(
            f"Inline PR annotations are only supported on GitHub (got {ref.host}).")
    token = token or token_for(ref.host)
    if not token:
        raise HostingError("No GITHUB_TOKEN found to post PR annotations.")
    url = f"https://api.github.com/repos/{ref.owner}/{ref.repo}/pulls/{number}/reviews"
    resp = httpx.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json={"body": summary, "event": "COMMENT", "comments": comments},
        timeout=timeout,
    )
    if resp.status_code >= 300:
        raise HostingError(f"GitHub review API error {resp.status_code}: {resp.text[:300]}")


def post_issue_comment(ref: RepoRef, number: int, body: str, *,
                       token: str | None = None, timeout: float = 30.0) -> None:
    """Post a normal (non-inline) comment on a PR/issue (GitHub only).

    Used for the PR-review summary when a finding is not on a line the pull
    request changed, so it cannot be attached inline but should still be shown.
    """
    if not body:
        return
    if ref.host != "github":
        raise HostingError(
            f"PR comments are only supported on GitHub (got {ref.host}).")
    token = token or token_for(ref.host)
    if not token:
        raise HostingError("No GITHUB_TOKEN found to post a PR comment.")
    url = f"https://api.github.com/repos/{ref.owner}/{ref.repo}/issues/{number}/comments"
    resp = httpx.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json={"body": body},
        timeout=timeout,
    )
    if resp.status_code >= 300:
        raise HostingError(f"GitHub comment API error {resp.status_code}: {resp.text[:300]}")


def _gitlab_mr(ref: RepoRef, head: str, base: str, title: str, body: str,
               token: str, timeout: float) -> PullRequest:
    project = quote(ref.slug, safe="")
    url = f"https://gitlab.com/api/v4/projects/{project}/merge_requests"
    resp = httpx.post(
        url,
        headers={"PRIVATE-TOKEN": token},
        json={
            "source_branch": head,
            "target_branch": base,
            "title": title,
            "description": body,
        },
        timeout=timeout,
    )
    if resp.status_code >= 300:
        raise HostingError(f"GitLab API error {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    return PullRequest(url=data.get("web_url", ""), number=data.get("iid"))


def _bitbucket_pr(ref: RepoRef, head: str, base: str, title: str, body: str,
                  token: str, timeout: float) -> PullRequest:
    url = f"https://api.bitbucket.org/2.0/repositories/{ref.slug}/pullrequests"
    resp = httpx.post(
        url,
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": title,
            "description": body,
            "source": {"branch": {"name": head}},
            "destination": {"branch": {"name": base}},
        },
        timeout=timeout,
    )
    if resp.status_code >= 300:
        raise HostingError(f"Bitbucket API error {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    links = data.get("links", {}).get("html", {})
    return PullRequest(url=links.get("href", ""), number=data.get("id"))
