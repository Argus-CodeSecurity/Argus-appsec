"""Plugin contracts and the registry.

Argus is plugin-based end to end. The three extension points are:

* :class:`Scanner` analyzes a project and yields findings.
* :class:`Reporter` serializes a scan result to some format.
* :class:`AIProvider` talks to a language model (defined in :mod:`argus.ai.base`).

Plugins register themselves against a process-global :class:`Registry`. Built-in
plugins register on import; third-party packages register through the
``argus.plugins`` entry-point group declared in ``pyproject.toml``. Adding a new
language, scanner, or report format therefore never requires editing the core.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable
from importlib import metadata
from typing import TYPE_CHECKING, ClassVar

from argus.core.models import Finding, ScanResult

if TYPE_CHECKING:
    from argus.ai.base import AIProvider
    from argus.core.config import Config
    from argus.core.project import Project


class ScannerContext:
    """Everything a scanner needs, passed in so scanners stay side-effect-light."""

    def __init__(self, project: Project, config: Config,
                 ai: AIProvider | None = None) -> None:
        self.project = project
        self.config = config
        self.ai = ai


class Scanner(abc.ABC):
    """Base class for a security scanner.

    Subclasses set :attr:`name` and :attr:`category` and implement :meth:`scan`.
    ``applies_to`` lets a scanner opt out cheaply (e.g. a Terraform scanner on a
    project with no ``.tf`` files) so the engine can skip it.
    """

    #: Unique, stable identifier (used in config, CLI flags, and finding ids).
    name: ClassVar[str] = ""
    #: Human-readable grouping, e.g. "secrets", "sast", "dependencies", "iac".
    category: ClassVar[str] = "general"
    #: One-line description shown in `argus scanners`.
    description: ClassVar[str] = ""
    #: True if every finding depends only on the content of a single file.
    #: File-local scanners get per-file result caching: between runs, unchanged
    #: files reuse their cached findings and only changed files are re-analyzed.
    #: Leave False for anything cross-file (dependency resolution, future
    #: cross-file taint), a wrong True here silently serves stale findings.
    file_local: ClassVar[bool] = False

    def applies_to(self, project: Project) -> bool:  # noqa: D401
        """Return True if this scanner is relevant to the project. Default: yes."""
        return True

    def cacheable(self, ctx: ScannerContext) -> bool:
        """Whether findings may be served from the per-file cache for this run.

        Defaults to :attr:`file_local`. A scanner overrides this to opt out when
        a run's options make results time-dependent rather than a pure function
        of file content, e.g. live secret verification, which must re-check the
        credential every run.
        """
        return self.file_local

    @abc.abstractmethod
    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        """Analyze the project and yield findings."""
        raise NotImplementedError


class Reporter(abc.ABC):
    """Base class for a report format."""

    name: ClassVar[str] = ""
    #: Default file extension (without the dot).
    extension: ClassVar[str] = "txt"
    description: ClassVar[str] = ""

    @abc.abstractmethod
    def render(self, result: ScanResult) -> str:
        """Render a scan result to a string."""
        raise NotImplementedError


class Registry:
    """Process-global registry of plugins, keyed by name within each kind."""

    def __init__(self) -> None:
        self._scanners: dict[str, type[Scanner]] = {}
        self._reporters: dict[str, type[Reporter]] = {}
        self._ai_providers: dict[str, type[AIProvider]] = {}
        self._loaded_entrypoints = False

    # --- registration -------------------------------------------------------
    @staticmethod
    def _reject_collision(kind: str, name: str, existing: type, cls: type) -> None:
        """Refuse a different class claiming an already-registered plugin name.

        Idempotent re-registration of the *same* class is allowed so importing
        built-ins twice (or reloading a module) is harmless. A third-party
        plugin silently replacing ``patterns`` / ``json`` / ``heuristic`` is not.
        """
        if existing is not cls:
            raise ValueError(
                f"{kind} name {name!r} is already registered by "
                f"{existing.__module__}.{existing.__qualname__}; "
                f"refusing {cls.__module__}.{cls.__qualname__}"
            )

    def register_scanner(self, cls: type[Scanner]) -> type[Scanner]:
        if not cls.name:
            raise ValueError(f"Scanner {cls.__name__} must define a name")
        existing = self._scanners.get(cls.name)
        if existing is not None:
            self._reject_collision("Scanner", cls.name, existing, cls)
        self._scanners[cls.name] = cls
        return cls

    def register_reporter(self, cls: type[Reporter]) -> type[Reporter]:
        if not cls.name:
            raise ValueError(f"Reporter {cls.__name__} must define a name")
        existing = self._reporters.get(cls.name)
        if existing is not None:
            self._reject_collision("Reporter", cls.name, existing, cls)
        self._reporters[cls.name] = cls
        return cls

    def register_ai_provider(self, cls: type[AIProvider]) -> type[AIProvider]:
        if not cls.name:
            raise ValueError(f"AIProvider {cls.__name__} must define a name")
        existing = self._ai_providers.get(cls.name)
        if existing is not None:
            self._reject_collision("AIProvider", cls.name, existing, cls)
        self._ai_providers[cls.name] = cls
        return cls

    # --- lookup -------------------------------------------------------------
    def scanners(self) -> dict[str, type[Scanner]]:
        self._ensure_entrypoints()
        return dict(self._scanners)

    def reporters(self) -> dict[str, type[Reporter]]:
        self._ensure_entrypoints()
        return dict(self._reporters)

    def ai_providers(self) -> dict[str, type[AIProvider]]:
        self._ensure_entrypoints()
        return dict(self._ai_providers)

    def get_scanner(self, name: str) -> type[Scanner]:
        self._ensure_entrypoints()
        if name not in self._scanners:
            raise KeyError(f"Unknown scanner: {name!r}. "
                           f"Available: {sorted(self._scanners)}")
        return self._scanners[name]

    def get_reporter(self, name: str) -> type[Reporter]:
        self._ensure_entrypoints()
        if name not in self._reporters:
            raise KeyError(f"Unknown reporter: {name!r}. "
                           f"Available: {sorted(self._reporters)}")
        return self._reporters[name]

    def get_ai_provider(self, name: str) -> type[AIProvider]:
        self._ensure_entrypoints()
        if name not in self._ai_providers:
            raise KeyError(f"Unknown AI provider: {name!r}. "
                           f"Available: {sorted(self._ai_providers)}")
        return self._ai_providers[name]

    # --- discovery ----------------------------------------------------------
    def _ensure_entrypoints(self) -> None:
        """Load plugins declared under the ``argus.plugins`` entry-point group.

        Each entry point is a zero-arg callable that receives nothing and is
        expected to register its plugins as a side effect (via this registry).
        Failures in one plugin never abort discovery of the others.
        """
        if self._loaded_entrypoints:
            return
        self._loaded_entrypoints = True
        try:
            eps = metadata.entry_points(group="argus.plugins")
        except Exception:  # pragma: no cover - environment dependent
            return
        for ep in eps:
            try:
                from argus.plugins.signing import verify_plugin_entry
                if not verify_plugin_entry(ep):
                    import warnings
                    warnings.warn(f"Blocked untrusted Argus plugin {ep.name!r}", stacklevel=2)
                    continue
                register = ep.load()
                register()
            except Exception as exc:  # pragma: no cover - defensive
                import warnings
                warnings.warn(f"Failed to load Argus plugin {ep.name!r}: {exc}",
                              stacklevel=2)


#: The shared registry every part of Argus talks to.
registry = Registry()


# Decorator sugar so plugin modules read cleanly.
def scanner(cls: type[Scanner]) -> type[Scanner]:
    return registry.register_scanner(cls)


def reporter(cls: type[Reporter]) -> type[Reporter]:
    return registry.register_reporter(cls)


def ai_provider(cls: type[AIProvider]) -> type[AIProvider]:
    return registry.register_ai_provider(cls)
