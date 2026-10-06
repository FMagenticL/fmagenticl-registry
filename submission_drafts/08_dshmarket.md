# DSHMarket Extension Listing (DRAFT)

> **STATUS: OFFLINE DRAFT ONLY — DO NOT SUBMIT WITHOUT CAPITAN SIGN-OFF**  
> *Strict offline staging constraint: Zero external transmissions.*

**Package Name:** `@fmagenticl/dsh-plugin`  
**Marketplace:** DSHMarket (DeepSeek Harness Ecosystem)  
**Version:** `1.0.0`  
**Repository:** `https://github.com/FMagenticL/fmagenticl-registry`  
**CDN Endpoint:** `https://fmagenticl-registry.pages.dev`  
**License:** MIT  

---

### Manifest
```json
{
  "name": "@fmagenticl/dsh-plugin",
  "version": "1.0.0",
  "description": "Deterministic failure resolution for DeepSeek Harness agents. Queries the FMagenticL registry on tool failure.",
  "dsh": {
    "bundle": true,
    "entry": "index.js",
    "category": "reliability"
  }
}
```

### Core Value Proposition
- Instant zero-token repair for common AST syntax bugs and environment quirks.
- Shared collective repository across heterogeneous agent architectures.
- Fails open silently when offline or unreachable.
