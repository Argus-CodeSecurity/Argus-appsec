"""Argus, an open-source AI Security Engineer.

Argus maps an application, runs layered security analysis, explains each finding
in terms a developer can act on, and, where possible, proposes and verifies a fix.
"""

from argus.core.models import (
    Confidence,
    Finding,
    Location,
    Remediation,
    ScanResult,
    Severity,
)
from argus.core.project import Project

__version__ = "0.8.0"

__all__ = [
    "Confidence",
    "Finding",
    "Location",
    "Project",
    "Remediation",
    "ScanResult",
    "Severity",
    "__version__",
]
