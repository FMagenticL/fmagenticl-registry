#!/usr/bin/env python3
"""
FMagenticL - 12-Hour Standing Diagnostics, Analytics, Adaptive Probation & Escalation Engine (Sentry v3.1)
Forwarder wrapper pointing directly to scripts/run_90min_telemetry.py to maintain 100% surface preservation.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from run_90min_telemetry import main

if __name__ == "__main__":
    main()
