import pytest
import json
from unittest.mock import patch, MagicMock
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
# NOTE (2026-11-25): `scratch/` was previously inserted ahead of `scripts/` here. Because
# .gitignore lists scratch/ (line 51), a local untracked scratch/run_90min_telemetry.py shadowed
# the tracked module and masked a collection failure that CI never ran. Do not reintroduce it:
# local runs must import exactly what a clean checkout imports.
#
# The retired helper `check_workarounds_mutation` was folded into `audit_workarounds_payload`
# by commit 5bdeeba without updating this file, which broke collection for 20 days / 186 commits.

from fetch_cf_analytics import fetch_window_metrics, query_d1_count
from run_90min_telemetry import audit_workarounds_payload


def test_fetch_window_metrics_counts_504_in_5xx():
    mock_response = {
        "data": {
            "viewer": {
                "accounts": [
                    {
                        "totals": [{"count": 100, "sum": {"edgeResponseBytes": 1048576, "visits": 10}}],
                        "statusCodes": [
                            {"count": 80, "dimensions": {"edgeResponseStatus": 200, "originResponseStatus": 0}},
                            {"count": 10, "dimensions": {"edgeResponseStatus": 404, "originResponseStatus": 0}},
                            {"count": 8, "dimensions": {"edgeResponseStatus": 504, "originResponseStatus": 0}},
                            {"count": 2, "dimensions": {"edgeResponseStatus": 500, "originResponseStatus": 500}},
                        ],
                        "paths": [{"count": 80, "dimensions": {"clientRequestPath": "/mcp"}}],
                        "errorsByPath": [
                            {"count": 8, "dimensions": {"clientRequestPath": "/mcp", "edgeResponseStatus": 504}},
                            {"count": 2, "dimensions": {"clientRequestPath": "/v1/health", "edgeResponseStatus": 500}},
                        ],
                        "countries": [{"count": 100, "dimensions": {"clientCountryName": "US"}}],
                    }
                ]
            }
        }
    }

    with patch("fetch_cf_analytics.execute_graphql", return_value=mock_response):
        from datetime import datetime, timezone
        start = datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 11, 1, 4, 0, 0, tzinfo=timezone.utc)
        metrics = fetch_window_metrics("fake_acc", start, end, "fake_token")

        # Assert total 5xx is 10 (8 + 2), NOT 2!
        assert metrics["c_5xx_total"] == 10
        assert metrics["c_504"] == 8
        assert metrics["c_5xx_other"] == 2
        assert metrics["c_2xx"] == 80
        assert metrics["c_4xx"] == 10
        assert metrics["total_requests"] == 100
        assert metrics["rate_5xx"] == 10.0
        assert len(metrics["top_error_paths"]) == 2
        assert metrics["top_error_paths"][0] == ("/mcp (504)", 8)
        assert metrics["top_error_paths"][1] == ("/v1/health (500)", 2)


def test_query_d1_count_reports_error_cleanly():
    with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
        count, err = query_d1_count("fake_acc", "fake_token", "SELECT COUNT(*) FROM telemetry;")
        assert count == 0
        assert err is not None
        assert "Connection refused" in err


def test_workarounds_mutation_detection_via_audit_payload(tmp_path):
    """Mutation detection, asserted through the surface that actually exists today.

    `check_workarounds_mutation` was folded into `audit_workarounds_payload`'s `mutation_status`
    by commit 5bdeeba. This test now exercises that surviving surface, and patches the same three
    module-level paths the function actually writes (STATE_CACHE, SHA256_CACHE, SCRATCH_DIR).
    """
    state_file = tmp_path / ".state.json"
    sha_file = tmp_path / ".sha256"
    scratch_dir = tmp_path / "scratch"

    def payload(ids):
        return json.dumps({
            "workarounds": [
                {
                    "id": i,
                    "target": "requests",
                    "symptom": "pool exhaustion under load",
                    "workaround": "Upgrade requests to 2.31.0 to clear the pool exhaustion defect.",
                    "created_at": "2026-01-01T00:00:00",
                }
                for i in ids
            ]
        }).encode("utf-8")

    with patch("run_90min_telemetry.STATE_CACHE", state_file), \
         patch("run_90min_telemetry.SHA256_CACHE", sha_file), \
         patch("run_90min_telemetry.SCRATCH_DIR", scratch_dir):

        # First observation establishes the baseline: no previous hash, no change, no violations.
        info1, violations1 = audit_workarounds_payload(payload(["g1"]))
        assert info1["mutation_status"] == "STABLE"
        assert info1["prev_sha256"] == ""
        assert violations1 == []

        # Identical payload -> same hash, still stable.
        info2, _ = audit_workarounds_payload(payload(["g1"]))
        assert info2["sha256"] == info1["sha256"]
        assert info2["mutation_status"] == "STABLE"

        # Mutated payload (one added record) -> change detected against the previous hash.
        info3, _ = audit_workarounds_payload(payload(["g1", "g2"]))
        assert info3["sha256"] != info1["sha256"]
        assert info3["prev_sha256"] == info1["sha256"]
        assert info3["delta"] == 1
        assert info3["mutation_status"].startswith("HARVEST_GROWTH")


if __name__ == "__main__":
    import tempfile
    print("Running test_fetch_window_metrics_counts_504_in_5xx...")
    test_fetch_window_metrics_counts_504_in_5xx()
    print("PASS: test_fetch_window_metrics_counts_504_in_5xx")

    print("Running test_query_d1_count_reports_error_cleanly...")
    test_query_d1_count_reports_error_cleanly()
    print("PASS: test_query_d1_count_reports_error_cleanly")

    print("Running test_workarounds_mutation_detection_via_audit_payload...")
    with tempfile.TemporaryDirectory() as td:
        test_workarounds_mutation_detection_via_audit_payload(Path(td))
    print("PASS: test_workarounds_mutation_detection_via_audit_payload")

    print("\nALL HONEST TELEMETRY UNIT TESTS PASSED (3/3)!")
