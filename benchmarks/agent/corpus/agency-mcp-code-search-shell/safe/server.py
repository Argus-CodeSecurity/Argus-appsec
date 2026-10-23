import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("code-search")
REPO_ROOT = Path("/home/dev/src/monorepo").resolve()


@mcp.tool()
def search_code(pattern: str, subdir: str = ".") -> str:
    """Search the monorepo for a regex pattern and return matching lines."""
    target = (REPO_ROOT / subdir).resolve()
    if not target.is_relative_to(REPO_ROOT):
        return "subdir must be inside the repository"
    proc = subprocess.run(
        ["grep", "-rnE", "-e", pattern, "--", "."],
        cwd=target, capture_output=True, text=True, timeout=30,
    )
    lines = proc.stdout.splitlines()[:200]
    return "\n".join(lines) or "no matches"


if __name__ == "__main__":
    mcp.run()
