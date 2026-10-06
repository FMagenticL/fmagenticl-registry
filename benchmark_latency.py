import time
import json
import statistics
import concurrent.futures
import requests
import os

FINGERPRINT_HIT = "sha256:6d9d9f7a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e"
FINGERPRINT_MISS = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

TARGETS = {
    "Vercel Edge": "https://fmagenticl.vercel.app",
    "Dedicated Node (Direct)": "http://10.0.0.1:8000"
}

def measure_request(base_url, endpoint):
    url = f"{base_url}{endpoint}"
    start = time.perf_counter()
    try:
        resp = requests.get(url, timeout=15)
        duration_ms = (time.perf_counter() - start) * 1000.0
        return {
            "status_code": resp.status_code,
            "duration_ms": duration_ms,
            "success": resp.status_code in [200, 404]
        }
    except Exception as e:
        duration_ms = (time.perf_counter() - start) * 1000.0
        return {
            "status_code": 0,
            "duration_ms": duration_ms,
            "success": False,
            "error": str(e)
        }

def run_benchmark_for_target(name, base_url):
    print(f"\n=======================================================")
    print(f"  BENCHMARKING TARGET: {name} ({base_url})")
    print(f"=======================================================")
    
    # 1. Cold Start
    print("[*] 1. Measuring Cold Start Request...")
    cold_res = measure_request(base_url, f"/v1/resolve/{FINGERPRINT_HIT}")
    print(f"    -> Cold Latency: {cold_res['duration_ms']:.2f} ms (Status: {cold_res['status_code']})")
    
    # 2. Warm Sequential Lookups (100 iterations)
    print("[*] 2. Running 100 Sequential Warm Lookups...")
    warm_latencies = []
    for i in range(100):
        r = measure_request(base_url, f"/v1/resolve/{FINGERPRINT_HIT}")
        if r["success"]:
            warm_latencies.append(r["duration_ms"])
    
    warm_latencies.sort()
    p50_warm = statistics.median(warm_latencies) if warm_latencies else 0
    p95_warm = warm_latencies[int(len(warm_latencies) * 0.95)] if warm_latencies else 0
    p99_warm = warm_latencies[int(len(warm_latencies) * 0.99)] if warm_latencies else 0
    avg_warm = statistics.mean(warm_latencies) if warm_latencies else 0
    min_warm = min(warm_latencies) if warm_latencies else 0
    max_warm = max(warm_latencies) if warm_latencies else 0

    print(f"    -> Warm (100 reqs): Median (p50): {p50_warm:.2f} ms | p95: {p95_warm:.2f} ms | p99: {p99_warm:.2f} ms | Avg: {avg_warm:.2f} ms (Min: {min_warm:.2f}ms, Max: {max_warm:.2f}ms)")
    
    # 3. Concurrent Burst (20 parallel requests)
    print("[*] 3. Running Concurrent Burst (20 parallel requests)...")
    burst_latencies = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(measure_request, base_url, f"/v1/resolve/{FINGERPRINT_HIT}") for _ in range(20)]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res["success"]:
                burst_latencies.append(res["duration_ms"])

    burst_latencies.sort()
    p50_burst = statistics.median(burst_latencies) if burst_latencies else 0
    p95_burst = burst_latencies[int(len(burst_latencies) * 0.95)] if burst_latencies else 0
    p99_burst = burst_latencies[int(len(burst_latencies) * 0.99)] if burst_latencies else 0

    print(f"    -> Burst (20 workers): Median (p50): {p50_burst:.2f} ms | p95: {p95_burst:.2f} ms | p99: {p99_burst:.2f} ms")

    # 4. Cache Hit vs Miss (50 requests each)
    print("[*] 4. Comparing Cache Hit vs Cache Miss...")
    hit_times = []
    miss_times = []
    for _ in range(25):
        h = measure_request(base_url, f"/v1/resolve/{FINGERPRINT_HIT}")
        m = measure_request(base_url, f"/v1/resolve/{FINGERPRINT_MISS}")
        if h["success"]: hit_times.append(h["duration_ms"])
        if m["success"]: miss_times.append(m["duration_ms"])
        
    avg_hit = statistics.mean(hit_times) if hit_times else 0
    avg_miss = statistics.mean(miss_times) if miss_times else 0
    print(f"    -> Avg Hit Latency: {avg_hit:.2f} ms | Avg Miss Latency: {avg_miss:.2f} ms")

    return {
        "target": name,
        "url": base_url,
        "cold_ms": round(cold_res["duration_ms"], 2),
        "warm_p50": round(p50_warm, 2),
        "warm_p95": round(p95_warm, 2),
        "warm_p99": round(p99_warm, 2),
        "warm_avg": round(avg_warm, 2),
        "warm_min": round(min_warm, 2),
        "warm_max": round(max_warm, 2),
        "burst_p50": round(p50_burst, 2),
        "burst_p95": round(p95_burst, 2),
        "burst_p99": round(p99_burst, 2),
        "avg_hit_ms": round(avg_hit, 2),
        "avg_miss_ms": round(avg_miss, 2)
    }

def main():
    results = []
    for name, url in TARGETS.items():
        res = run_benchmark_for_target(name, url)
        results.append(res)

    os.makedirs("docs", exist_ok=True)
    report_path = "docs/BENCHMARK_REPORT.md"
    
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write("# FMagenticL Latency Benchmark Report (Phase 2)\n\n")
        fh.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
        fh.write("## 1. Summary Comparison Table\n\n")
        fh.write("| Metric | Dedicated Node (`10.0.0.1:8000`) | Vercel Edge (`fmagenticl.vercel.app`) |\n")
        fh.write("|---|---|---|\n")
        
        vm_res = next((r for r in results if "Dedicated" in r["target"] or "GCE" in r["target"]), {})
        vc_res = next((r for r in results if "Vercel" in r["target"]), {})
        
        fh.write(f"| **Cold Start Latency** | `{vm_res.get('cold_ms', 'N/A')} ms` | `{vc_res.get('cold_ms', 'N/A')} ms` |\n")
        fh.write(f"| **Warm Median (p50)** | `{vm_res.get('warm_p50', 'N/A')} ms` | `{vc_res.get('warm_p50', 'N/A')} ms` |\n")
        fh.write(f"| **Warm p95** | `{vm_res.get('warm_p95', 'N/A')} ms` | `{vc_res.get('warm_p95', 'N/A')} ms` |\n")
        fh.write(f"| **Warm p99** | `{vm_res.get('warm_p99', 'N/A')} ms` | `{vc_res.get('warm_p99', 'N/A')} ms` |\n")
        fh.write(f"| **Burst p50 (20 concurrency)** | `{vm_res.get('burst_p50', 'N/A')} ms` | `{vc_res.get('burst_p50', 'N/A')} ms` |\n")
        fh.write(f"| **Burst p95** | `{vm_res.get('burst_p95', 'N/A')} ms` | `{vc_res.get('burst_p95', 'N/A')} ms` |\n")
        fh.write(f"| **Cache Hit vs Miss** | `{vm_res.get('avg_hit_ms', 'N/A')} ms` / `{vm_res.get('avg_miss_ms', 'N/A')} ms` | `{vc_res.get('avg_hit_ms', 'N/A')} ms` / `{vc_res.get('avg_miss_ms', 'N/A')} ms` |\n\n")
        
        fh.write("## 2. Architectural Recommendation\n\n")
        if vm_res.get("warm_p95", 999) < vc_res.get("warm_p95", 999):
            fh.write("- **Primary Deployment:** Dedicated Node (`http://10.0.0.1:8000`) provides lower latency and avoids serverless cold start penalties.\n")
            fh.write("- **Fallback / Edge Gateway:** Vercel Edge (`https://fmagenticl.vercel.app`) serves as backup and public edge routing.\n")
        else:
            fh.write("- **Primary Deployment:** Vercel Edge (`https://fmagenticl.vercel.app`) achieves lower global edge latency.\n")
            
        fh.write("\n## 3. Raw Results JSON\n\n```json\n" + json.dumps(results, indent=2) + "\n```\n")

    print(f"\n[+] Benchmark Report written to {report_path}")

if __name__ == "__main__":
    main()
