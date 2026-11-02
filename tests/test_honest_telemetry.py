import pytest
import json
from unittest.mock import patch, MagicMock
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "scratch"))

from fetch_cf_analytics import fetch_window_metrics, query_d1_count
from run_90min_telemetry import check_workarounds_mutation


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


def test_workarounds_hash_mutation_detection(tmp_path):
    cache_file = tmp_path / ".test_sha256"
    with patch("run_90min_telemetry.SHA256_CACHE", cache_file):
        # First call sets baseline
        h1, changed1, old1 = check_workarounds_mutation(b"first payload")
        assert not changed1
        assert old1 == ""

        # Second call with same payload -> no change
        h2, changed2, old2 = check_workarounds_mutation(b"first payload")
        assert not changed2
        assert h2 == h1

        # Third call with mutated payload -> detected change
        h3, changed3, old3 = check_workarounds_mutation(b"mutated payload")
        assert changed3
        assert old3 == h1
        assert h3 != h1


if __name__ == "__main__":
    import tempfile
    print("Running test_fetch_window_metrics_counts_504_in_5xx...")
    test_fetch_window_metrics_counts_504_in_5xx()
    print("PASS: test_fetch_window_metrics_counts_504_in_5xx")

    print("Running test_query_d1_count_reports_error_cleanly...")
    test_query_d1_count_reports_error_cleanly()
    print("PASS: test_query_d1_count_reports_error_cleanly")

    print("Running test_workarounds_hash_mutation_detection...")
    with tempfile.TemporaryDirectory() as td:
        test_workarounds_hash_mutation_detection(Path(td))
    print("PASS: test_workarounds_hash_mutation_detection")

    print("\nALL HONEST TELEMETRY UNIT TESTS PASSED (3/3)!")
