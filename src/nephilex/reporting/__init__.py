"""Report formats.

Each reporter turns a :class:`~nephilex.core.models.ScanResult` into a string in one
format. Importing this package registers the built-in reporters. Add a format by
subclassing :class:`~nephilex.core.plugin.Reporter` and decorating with ``@reporter``.
"""

from nephilex.reporting import (  # noqa: F401
    badge,
    gitlab,
    html,
    json_reporter,
    junit,
    markdown,
    sarif,
    vex,
)

__all__ = ["badge", "gitlab", "html", "json_reporter", "junit", "markdown", "sarif", "vex"]
