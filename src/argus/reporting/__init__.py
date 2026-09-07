"""Report formats.

Each reporter turns a :class:`~argus.core.models.ScanResult` into a string in one
format. Importing this package registers the built-in reporters. Add a format by
subclassing :class:`~argus.core.plugin.Reporter` and decorating with ``@reporter``.
"""

from argus.reporting import (  # noqa: F401
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
