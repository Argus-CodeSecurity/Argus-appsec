"""Project context: what a team knows about its code that a scanner cannot see.

``.nephilex/context.yml`` declares project-specific sanitizers, trusted sources,
internal-only paths, exposure notes and data classification. The AST taint
tiers use the first two to stop reporting flows the project has already
neutralised; the engine uses the rest to adjust severity and likelihood.

The file is project configuration, so it follows the same trust rule as
``.nephilex.yml``: it is honoured only for trusted targets (see
:func:`nephilex.core.config.load_project_config`). A pull request that could
declare its own sinks sanitized would otherwise switch off the checks that
are meant to review it.
"""

from __future__ import annotations

from nephilex.context.apply import apply_context, path_matches
from nephilex.context.schema import (
    CONTEXT_FILENAME,
    CONTEXT_PATH,
    DATA_CLASSES,
    EXPOSURE_LEVELS,
    LANGUAGES,
    DataClassification,
    ExposureNote,
    LanguageContext,
    ProjectContext,
    Sanitizer,
    TrustedSource,
    load_context,
    parse_context,
)

__all__ = [
    "CONTEXT_FILENAME",
    "CONTEXT_PATH",
    "DATA_CLASSES",
    "EXPOSURE_LEVELS",
    "LANGUAGES",
    "DataClassification",
    "ExposureNote",
    "LanguageContext",
    "ProjectContext",
    "Sanitizer",
    "TrustedSource",
    "apply_context",
    "load_context",
    "parse_context",
    "path_matches",
]
