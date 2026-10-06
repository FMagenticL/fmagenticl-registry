# Smithery.ai MCP Registry Submission (DRAFT)

> **STATUS: OFFLINE DRAFT ONLY — DO NOT SUBMIT WITHOUT CAPITAN SIGN-OFF**  
> *Strict offline staging constraint: Zero external transmissions.*

**Server ID:** `fmagenticl`  
**Package:** `fmagenticl` / `@fmagenticl/client`  
**Repository:** `https://github.com/FMagenticL/fmagenticl-registry`  
**Live CDN:** `https://fmagenticl-registry.pages.dev`  
**Snapshot URI:** `https://fmagenticl-registry.pages.dev/v1/snapshot.json`  
**Agent Card:** `https://fmagenticl-registry.pages.dev/.well-known/agent-card.json`  
**Category:** Developer Tools / Agent Infrastructure / Reliability / Self-Healing  
**License:** MIT  

---

## Technical Overview
FMagenticL is a low-latency, deterministic failure-resolution depository and friction registry for AI agents. When tool calls or CLI executions fail, FMagenticL provides exact RFC 6902 JSON patches, verified CLI overrides, and known friction workarounds in <50ms without invoking secondary LLM inference loops.

All snapshot artifacts are cryptographically signed with Ed25519 (pinned key: `guknKNLrBRrjQ83nSrj3V5+fysNYf99X9w7MdOdqB5w=`).

---

## Configuration

### 1. Local Stdio Integration (Recommended)
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

### 2. Python Client Installation
```bash
pip install fmagenticl==1.3.1
```

```python
from fmagenticl.client import FMagenticLClient

client = FMagenticLClient()
patch = client.resolve_failure("sha256:<fingerprint>")
```

---

## Exposed MCP Tools

1. **`fmagenticl_resolve`**: Retrieve a deterministic RFC 6902 JSON patch or CLI override for a given SHA-256 error fingerprint.
2. **`fmagenticl_auto_heal`**: Atomically test and apply an RFC 6902 patch with `op: "test"` precondition gating.
3. **`fmagenticl_report_telemetry`**: Deposit a verified error resolution manifest into the public depository.
4. **`fmagenticl_submit_grievance`**: Report persistent tool or protocol friction with minimal reproducible steps and actionable workarounds.
5. **`fmagenticl_get_grievances`**: Query known operational friction reports for a tool or daemon.
