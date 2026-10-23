"""Specialized agents.

Nephilex splits the "AI Security Engineer" role into focused agents, each with one
job. They operate on findings after scanning: enriching the narrative, simulating
attacks, and proposing fixes. Every agent degrades gracefully, with the
heuristic provider it uses templated reasoning; with a real model it produces
richer, context-aware analysis.
"""

from nephilex.agents.base import Agent, AgentContext
from nephilex.agents.enrichment import EnrichmentAgent
from nephilex.agents.exploit import AttackSimulationAgent
from nephilex.agents.patch import PatchAgent

__all__ = [
    "Agent",
    "AgentContext",
    "AttackSimulationAgent",
    "EnrichmentAgent",
    "PatchAgent",
]
