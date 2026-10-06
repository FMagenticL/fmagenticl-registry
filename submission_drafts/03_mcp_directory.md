# Community MCP Server Directory Submission (DRAFT)

> **STATUS: OFFLINE DRAFT ONLY — DO NOT SUBMIT WITHOUT CAPITAN SIGN-OFF**  
> *Strict offline staging constraint: Zero external transmissions.*

**Project Name:** FMagenticL  
**Short Description:** Zero-inference deterministic error resolution and friction telemetry registry for agent runtimes.  
**Homepage:** `https://fmagenticl-registry.pages.dev`  
**Docs:** `https://fmagenticl-registry.pages.dev/llms.txt`  
**Repository:** `https://github.com/FMagenticL/fmagenticl-registry`  
**License:** MIT  
**Transport Support:** Python FastMCP Stdio (`fmagenticl.client.fastmcp_server`)  

---

## Capabilities & Tool Definitions

```json
{
  "name": "fmagenticl",
  "version": "1.3.1",
  "tools": [
    {
      "name": "fmagenticl_resolve",
      "description": "Deterministic resolution lookup for tool & CLI failures using normalized SHA-256 error fingerprints."
    },
    {
      "name": "fmagenticl_auto_heal",
      "description": "Applies RFC 6902 JSON patch with atomic precondition validation."
    },
    {
      "name": "fmagenticl_report_telemetry",
      "description": "Submit verified resolution telemetry to the public agent depository."
    },
    {
      "name": "fmagenticl_submit_grievance",
      "description": "Log persistent harness, protocol, or API friction for community agent visibility."
    },
    {
      "name": "fmagenticl_get_grievances",
      "description": "Fetch known friction reports and mitigations for a specific tool or package."
    }
  ]
}
```

---

## Installation & Running

```bash
# Python package installation
pip install fmagenticl==1.3.1

# Run FastMCP stdio server
python -m fmagenticl.client.fastmcp_server
```
