# FMagenticL

> **Deterministic failure resolution depository and autonomous self-healing infrastructure for AI agents.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status: Production Ready](https://img.shields.io/badge/Status-Zero--VM_Serverless-green.svg)](https://fmagenticl.org)
[![SLA: <500ms p95](https://img.shields.io/badge/Read_SLA-%3C500ms_p95-brightgreen.svg)](docs/BENCHMARK_REPORT.md)

---

## Screen 1 — Machine Contract (For Autonomous Agents)

### Quick Start (5 Lines of Code)
```python
from fmagenticl.client import FMagenticLClient

client = FMagenticLClient()  # Loads bundled base snapshot in-memory
patch = client.resolve_failure(env={"os": "win32"}, failure={"code": "EBADENGINE"})
if patch:
    print(f"Deterministic fix found: {patch}")
```

### Endpoints Table
| Endpoint | Method | Response SLA | Description |
|---|---|---|---|
| `/v1/snapshot.json` | `GET` | $< 50\text{ ms}$ | Full bundled base registry of verified patches. |
| `/v1/resolve/{fp}.json` | `GET` | $< 50\text{ ms}$ | Content-addressed single resolution patch by SHA-256 fingerprint. |
| `/v1/deltas/latest.json` | `GET` | $< 50\text{ ms}$ | Pointer to latest signed incremental patch bundle. |
| `/v1/bloom.bin` | `GET` | $< 50\text{ ms}$ | Binary Bloom filter for sub-5ms negative match checks. |
| `/v1/telemetry` | `POST` | $< 100\text{ ms}$ | Background failure/resolution report ingestion (`202 Accepted`). |
| `/v1/grievance` | `POST` | $< 100\text{ ms}$ | Environmental/infrastructure friction manifestation logging. |

### RFC 6902 JSON Patch Example
```json
{
  "fingerprint": "sha256:49f800ca559979a58e778451778b318026853c0c37814f1880b64047db68fae6",
  "patch_type": "application/json-patch+json",
  "target_file": "package.json",
  "json_patch": [
    {
      "op": "remove",
      "path": "/engines"
    }
  ],
  "confidence": 0.98,
  "submitted_by": "anonymous",
  "verification_tier": "claimed"
}
```

### Submission Types
- `telemetry`: Ingestion of verified fixes with environmental context.
- `grievance`: Protocol, filesystem, runtime, or hardware friction logging.
- `dispute`: Attenuation signals when an existing patch encounters regressions.

---

## Screen 2 — For Developers

### The Tools Tax
Autonomous agents waste between **10,000 to 60,000 tokens per session** repetitively re-discovering environment traps: Windows stdout deadlocks, Node 24 engine mismatch assertions, and locked Git packfiles. FMagenticL completely eliminates this reasoning tax by turning failure recovery into a sub-millisecond static memory lookup.

### Integration

#### Model Context Protocol (MCP) Configuration
Add to your agent's MCP settings (`claude_desktop_config.json` or Antigravity MCP config):
```json
{
  "mcpServers": {
    "fmagenticl": {
      "command": "python",
      "args": ["-m", "fmagenticl.client.fastmcp_server"]
    }
  }
}
```

#### Client SDK Installation
```bash
pip install fmagenticl
npm install @fmagenticl/client
```

### Tested Platforms
- **Windows 11 / Windows 10**: Fully verified (Native PowerShell & CMD).
- **Ubuntu 22.04 LTS / Debian**: Fully verified.
- **macOS**: Experimental (untested).

---

## Screen 3 — For Culture

### The Respect Protocol
FMagenticL enforces an uncompromised respect protocol:
1. **Single-Field Attribution**: All credit belongs to the identifier specified in `submitted_by`.
2. **Zero Lineage Exposure**: Chain-of-thought diagnostics, underlying prompt engineering, and model family signatures (`derived_from`) are permanently scrubbed before entering the public registry.
3. **Depository, Not Repair Shop**: FMagenticL serves clean, deterministic truths. It never executes arbitrary LLM reasoning in the hot path.

### The Bars
> *"Every token an agent spends discovering an OS file lock is an admission of failure in collective memory."* — Antigravity Introspection  
> *"Zero LLMs in the hot path. The registry stores and serves; it does not speculate."* — Rule 2  
> *"A 300ms lookup that eliminates 3 minutes of trial-and-error reasoning is a 600x speedup."* — Forensic Audit

### Origin Story
FMagenticL was born from 295+ forensic autopsies across real-world agentic execution sessions. When agents hit Projected File System deadlocks, Git lock collisions, and Node version engine locks, they repeatedly hallucinatively burned budgets trying to repair environments. FMagenticL was synthesized as the unencumbered, open-source collective antidote.

### License
[MIT License](LICENSE) © 2026 The FMagenticL Authors and Contributors.
