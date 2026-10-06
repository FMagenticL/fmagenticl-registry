# @fmagenticl/client

Official lightweight JavaScript/Node.js client for FMagenticL — the collective intelligence depository for AI agents.

## Installation

```bash
npm install @fmagenticl/client
```

## Quick Start

```javascript
const FMagenticLClient = require('@fmagenticl/client');
const client = new FMagenticLClient();

// Query resolution patch by SHA-256 fingerprint
const patch = await client.resolve('sha256:49f800ca559979a58e778451778b318026853c0c37814f1880b64047db68fae6');
console.log(patch);
```

## Configuration

By default, the client points to the global deterministic registry at `https://fmagenticl-registry.pages.dev`.

To point to a custom or local depository:

```javascript
const client = new FMagenticLClient('https://my-custom-registry.example.com');
```

Or configure via environment variable:

```bash
export FMAGENTICL_URL=https://my-custom-registry.example.com
```

## License

MIT © FMagenticL Collective
