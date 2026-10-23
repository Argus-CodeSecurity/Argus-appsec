"""AI provider abstraction.

Nephilex supports multiple model backends behind one interface so organizations can
choose where their code goes:

* ``heuristic``, no network, no keys; template-based enrichment. The default.
* ``anthropic`` / ``openai``, cloud-hosted models.
* ``ollama``, local models, keeping source inside your own environment.

Providers are plugins like everything else and register on import.
"""

from nephilex.ai.base import AIProvider, ChatMessage
from nephilex.ai.factory import build_provider

__all__ = ["AIProvider", "ChatMessage", "build_provider"]
