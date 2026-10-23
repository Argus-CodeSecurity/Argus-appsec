from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
NOTES_ROOT = (Path.home() / "notes").resolve()


@mcp.tool()
def save_note(path: str, content: str) -> str:
    """Save a markdown note. `path` is relative to the notes folder."""
    target = (NOTES_ROOT / path).resolve()
    if not target.is_relative_to(NOTES_ROOT) or target.suffix != ".md":
        raise ValueError("notes must be .md files inside the notes folder")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"saved {target.relative_to(NOTES_ROOT)}"


@mcp.tool()
def list_notes() -> list[str]:
    """List saved notes."""
    return [str(p.relative_to(NOTES_ROOT)) for p in NOTES_ROOT.rglob("*.md")]


if __name__ == "__main__":
    mcp.run()
