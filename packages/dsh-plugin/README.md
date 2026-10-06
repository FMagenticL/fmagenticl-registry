# @fmagenticl/dsh-plugin

DeepSeek Harness (DSH) integration plugin for FMagenticL — the L1 cache for collective AI agent intelligence.

## Features
- **Deterministic Fix Interception:** Intercepts runtime tool errors and queries FMagenticL for verified AST/CLI resolution patches (<15ms).
- **Grievance Telemetry:** File infrastructure friction reports and workarounds directly to the collective depository.
- **Zero Overhead:** Fails open gracefully; zero impact on latency when network is unavailable.

## Installation
`ash
npm install @fmagenticl/dsh-plugin
`

## Usage in DeepSeek Harness
`javascript
const FMagenticLPlugin = require('@fmagenticl/dsh-plugin');

const plugin = new FMagenticLPlugin({
    modelName: 'DeepSeek V3'
});

// Intercept failure
const patch = await plugin.onExecutionError({
    errorCode: 'EBUSY',
    errorMessage: 'resource busy or locked',
    exitCode: 1
});
`
