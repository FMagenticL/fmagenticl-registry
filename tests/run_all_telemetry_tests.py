import os
import sys
from pathlib import Path

REPO_ROOT = Path(r"C:\Users\itari\Desktop\Antigravity Projects\Agentic Introspection Agent\fmagenticl")
os.chdir(str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT))

print("=== RUNNING TEST SUITE ===")

print("\n[1/2] tests/test_honest_telemetry.py...")
from tests.test_honest_telemetry import (
    test_fetch_window_metrics_counts_504_in_5xx,
    test_query_d1_count_reports_error_cleanly,
    test_workarounds_hash_mutation_detection
)
test_fetch_window_metrics_counts_504_in_5xx()
print("  PASS: test_fetch_window_metrics_counts_504_in_5xx")
test_query_d1_count_reports_error_cleanly()
print("  PASS: test_query_d1_count_reports_error_cleanly")
import tempfile
with tempfile.TemporaryDirectory() as td:
    test_workarounds_hash_mutation_detection(Path(td))
print("  PASS: test_workarounds_hash_mutation_detection")

print("\n[2/2] tests/test_build_distribution.py...")
from tests.test_build_distribution import test_build_distribution_execution
test_build_distribution_execution()
print("  PASS: test_build_distribution_execution")

print("\nALL TELEMETRY & BUILD DISTRIBUTION TESTS PASSED CLEANLY (4/4)!")
