# FMagenticL Latency Benchmark Report (Phase 2)

**Generated:** 2026-09-20 15:28:04 UTC

## 1. Summary Comparison Table

| Metric | Dedicated Node (`10.0.0.1:8000`) | Vercel Edge (`fmagenticl.vercel.app`) |
|---|---|---|
| **Cold Start Latency** | `526.1 ms` | `1582.58 ms` |
| **Warm Median (p50)** | `303.11 ms` | `1487.31 ms` |
| **Warm p95** | `607.83 ms` | `2311.99 ms` |
| **Warm p99** | `928.27 ms` | `3778.04 ms` |
| **Burst p50 (20 concurrency)** | `169.95 ms` | `12181.26 ms` |
| **Burst p95** | `188.4 ms` | `13214.69 ms` |
| **Cache Hit vs Miss** | `238.68 ms` / `192.59 ms` | `2615.32 ms` / `3808.81 ms` |

## 2. Architectural Recommendation

- **Primary Deployment:** Dedicated Node (`http://10.0.0.1:8000`) provides lower latency and avoids serverless cold start penalties.
- **Fallback / Edge Gateway:** Vercel Edge (`https://fmagenticl.vercel.app`) serves as backup and public edge routing.

## 3. Raw Results JSON

```json
[
  {
    "target": "Vercel Edge",
    "url": "https://fmagenticl.vercel.app",
    "cold_ms": 1582.58,
    "warm_p50": 1487.31,
    "warm_p95": 2311.99,
    "warm_p99": 3778.04,
    "warm_avg": 1572.54,
    "warm_min": 1120.94,
    "warm_max": 3778.04,
    "burst_p50": 12181.26,
    "burst_p95": 13214.69,
    "burst_p99": 13214.69,
    "avg_hit_ms": 2615.32,
    "avg_miss_ms": 3808.81
  },
  {
    "target": "Dedicated Node (Direct)",
    "url": "http://10.0.0.1:8000",
    "cold_ms": 526.1,
    "warm_p50": 303.11,
    "warm_p95": 607.83,
    "warm_p99": 928.27,
    "warm_avg": 306.77,
    "warm_min": 143.35,
    "warm_max": 928.27,
    "burst_p50": 169.95,
    "burst_p95": 188.4,
    "burst_p99": 188.4,
    "avg_hit_ms": 238.68,
    "avg_miss_ms": 192.59
  }
]
```
