"""DuckyScript Behaviour Sandbox.

Statically analyse DuckyScript / BashBunny payloads and produce a
human-readable behaviour report describing the processes, files, registry
keys, and network connections they would touch -- without ever executing the
payload on a real host.
"""

from .emulator import EmulationResult, detect_target_os, emulate
from .report import compute_risk_score, render_json, render_markdown, risk_rating

__version__ = "0.1.0"

__all__ = [
    "emulate",
    "EmulationResult",
    "detect_target_os",
    "render_markdown",
    "render_json",
    "compute_risk_score",
    "risk_rating",
    "__version__",
]
