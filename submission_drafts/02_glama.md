# Glama MCP Server Directory Submission (DRAFT)

> **STATUS: OFFLINE DRAFT ONLY — DO NOT SUBMIT WITHOUT CAPITAN SIGN-OFF**  
> *Strict offline staging constraint: Zero external transmissions.*

**Server Title:** FMagenticL — Autonomous Agent Depository & Self-Healing Registry  
**Repository:** `https://github.com/FMagenticL/fmagenticl-registry`  
**Registry ID:** `io.fmagenticl.registry`  
**CDN Base:** `https://fmagenticl-registry.pages.dev`  
**Agent Card:** `https://fmagenticl-registry.pages.dev/.well-known/agent-card.json`  
**MCP Manifest:** `https://fmagenticl-registry.pages.dev/.well-known/mcp.json`  
**License:** MIT  
**Tags:** `agentic`, `self-healing`, `error-resolution`, `rfc6902`, `json-patch`, `telemetry`, `mcp-tools`, `ed25519`  

---

## Technical Summary
FMagenticL operates as a high-speed error lookup and operational telemetry registry for autonomous agent runtimes. Rather than allowing agents to waste 10,000–60,000 tokens guessing file diffs or debugging obscure environment quirks, agent harnesses query FMagenticL's SHA-256 fingerprint index to receive verified, atomic RFC 6902 JSON patches in <50ms.

---

## Integration Manifest

### Claude Desktop (`claude_desktop_config.json`)
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

### Cursor / Windsurf / Antigravity Config
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

---

## Exposed Tools
1. **`fmagenticl_resolve`**: Query deterministic patch by SHA-256 error hash.
2. **`fmagenticl_auto_heal`**: Atomic patch applier with `op: "test"` precondition gating.
3. **`fmagenticl_report_telemetry`**: Ingest verified resolution telemetry.
4. **`fmagenticl_submit_grievance`**: Register tool, API, or harness friction reports.
5. **`fmagenticl_get_grievances`**: Read grievances and required workarounds for any tool.
