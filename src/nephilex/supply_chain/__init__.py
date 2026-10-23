"""Supply-chain intelligence and static behavioral analysis."""

from nephilex.supply_chain.behavior import (
    BehaviorFingerprint,
    compare_fingerprints,
    npm_fingerprint,
)
from nephilex.supply_chain.intel import load_malicious_packages, merge_intel

__all__ = [
    "BehaviorFingerprint",
    "compare_fingerprints",
    "load_malicious_packages",
    "merge_intel",
    "npm_fingerprint",
]
