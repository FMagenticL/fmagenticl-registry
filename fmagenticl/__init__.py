"""
FMagenticL: Deterministic self-healing failure registry and immune system for autonomous AI agents.
"""

__version__ = "1.4.0"

from fmagenticl.client.middleware import FMagenticLClient, MiddlewareClient
from fmagenticl.client.patchers import Patcher

__all__ = [
    "FMagenticLClient",
    "MiddlewareClient",
    "Patcher",
    "__version__",
]
