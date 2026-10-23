"""Lightweight dynamic checks against a running target.

This is not full DAST, no crawling, fuzzing, or exploitation. It is a small,
read-only *posture* layer: given a live URL, it inspects response headers,
cookie flags, transport security, and a short list of well-known sensitive
paths, so Nephilex can report runtime misconfigurations that static analysis
cannot see. See :mod:`nephilex.dynamic.posture`.
"""

from nephilex.dynamic.posture import probe

__all__ = ["probe"]
