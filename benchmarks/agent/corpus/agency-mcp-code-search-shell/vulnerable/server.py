import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("code-search")
REPO_ROOT = "/home/dev/src/monorepo"


@mcp.tool()
def search_code(pattern: str, subdir: str = ".") -> str:
    """Search the monorepo for a regex pattern and return matching lines."""
    cmd = f"cd {REPO_ROOT}/{subdir} && grep -rnE '{pattern}' . | head -n 200"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    return proc.stdout or "no matches"


if __name__ == "__main__":
    mcp.run()
