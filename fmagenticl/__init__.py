"""
FMagenticL: Signed Open Registry of Malicious AI Agent Signatures, Offensive Harnesses & Behavioral IOCs.
"""

__version__ = "3.0.0"

from fmagenticl.client.middleware import FMagenticLClient, MiddlewareClient
from fmagenticl.client.patchers import Patcher
from fmagenticl.client.scanner import WorkspaceScanner

__all__ = [
    "FMagenticLClient",
    "MiddlewareClient",
    "Patcher",
    "WorkspaceScanner",
    "__version__",
]
