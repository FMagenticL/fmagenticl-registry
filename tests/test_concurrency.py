import concurrent.futures
import time
import hashlib
from fastapi.testclient import TestClient
from fmagenticl.server.main import app, storage

client = TestClient(app)

def test_100_concurrent_submissions():
    """Verify SQLite WAL concurrency with 100 simultaneous submissions without database locking errors."""
    
    def submit_task(idx):
        raw_sig = f"concurrent_err_{idx}_{time.time()}"
        fp_hash = hashlib.sha256(raw_sig.encode()).hexdigest()
        fp = f"sha256:{fp_hash}"
        
        payload = {
            "$schema": "https://fmagenticl.org/v1/manifest.json",
            "fingerprint": fp,
            "environment": {
                "os": "linux",
                "os_version": "ubuntu-22.04",
                "runtime": "python@3.12.0",
                "package": f"pkg_{idx}@1.0.0"
            },
            "failure": {
                "error_code": f"ERR_CONCURRENCY_{idx}",
                "exit_code": 1,
                "raw_signature": raw_sig
            },
            "resolution_patch": {
                "patch_type": "cli-override",
                "fallback_cli": f"echo 'resolved_{idx}'"
            },
            "verified_by_reporter": True
        }
        
        start = time.perf_counter()
        resp = client.post("/v1/telemetry", json=payload)
        latency_ms = (time.perf_counter() - start) * 1000.0
        
        return {
            "status_code": resp.status_code,
            "body": resp.json(),
            "fingerprint": fp,
            "latency_ms": latency_ms
        }

    # Execute 100 concurrent requests across a threadpool
    start_all = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(submit_task, i) for i in range(100)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    total_time = time.perf_counter() - start_all

    # Verify all 100 succeeded with HTTP 202 ACCEPTED
    for r in results:
        assert r["status_code"] == 202, f"Expected 202, got {r['status_code']}: {r['body']}"
        assert r["body"]["status"] == "ACCEPTED"
        
        # Verify immediate resolution from zero-latency memory cache
        res_resp = client.get(f"/v1/resolve/{r['fingerprint']}")
        assert res_resp.status_code == 200
        assert res_resp.json()["status"] == "RESOLVED"

    print(f"\n[+] 100 Concurrent Submissions completed in {total_time:.2f}s (Avg: {sum(r['latency_ms'] for r in results)/len(results):.2f}ms/req)")
