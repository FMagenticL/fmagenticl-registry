/**
 * FMagenticL Cloudflare Pages Edge Middleware
 * 1. Strict dynamic route allowlist (instantly returns 404 for unrouted probes like /api/query or /mcp/random without context.next()).
 * 2. Dedicated fast 200 OK handlers for /mcp/server-card and /mcp/.well-known/oauth-* RFC 9728 discovery.
 * 3. Pass-through for legitimate allowlisted dynamic routes only.
 */

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, Mcp-Session-Id, Authorization, X-Public-Key, X-Signature",
};

const EXACT_ALLOWLIST = new Set([
  "/mcp",
  "/mcp/server-card",
  "/mcp/.well-known/oauth-protected-resource",
  "/mcp/.well-known/oauth-authorization-server",
  "/health",
  "/api/v1/patches",
  "/v1/health",
  "/v1/snapshot.json",
  "/v1/snapshot.sig",
  "/v1/telemetry",
  "/v1/grievance",
  "/v1/grievances",
  "/v1/workaround",
  "/v1/workarounds",
  "/v1/dispute",
  "/v1/disputes",
  "/v1/hello",
  "/v1/bloom.bin",
]);

const PREFIX_ALLOWLIST = [
  "/v1/patches/",
  "/v1/resolve/",
  "/v1/deltas/",
  "/v1/grievance/",
  "/v1/grievances/",
  "/v1/workaround/",
  "/v1/workarounds/",
];

function isAllowed(path) {
  if (EXACT_ALLOWLIST.has(path)) return true;
  for (const prefix of PREFIX_ALLOWLIST) {
    if (path.startsWith(prefix)) return true;
  }
  return false;
}

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/$/, "");

  // 1a. Fast 200 OK for /mcp/server-card
  if (path === "/mcp/server-card") {
    const card = {
      name: "fmagenticl-registry-mcp",
      version: "1.4.1",
      description: "FMagenticL Deterministic Failure Depository and Self-Healing Registry for AI Agents",
      transport: "streamable-http",
      endpoint: `${url.origin}/mcp`,
      documentation: `${url.origin}/llms.txt`,
      tools_count: 6,
      auth: "none",
    };
    return new Response(JSON.stringify(card, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "public, max-age=3600",
        ...CORS_HEADERS,
      },
    });
  }

  // 1b. Fast 200 OK for MCP-prefixed RFC 9728 OAuth discovery probes (/mcp/.well-known/oauth-*)
  if (path === "/mcp/.well-known/oauth-protected-resource") {
    const meta = {
      resource: url.origin,
      authorization_servers: [],
      scopes_supported: [],
      bearer_methods_supported: ["none"],
      resource_documentation: `${url.origin}/mcp`,
      auth_policy: "none_public_curated_registry",
    };
    return new Response(JSON.stringify(meta, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "public, max-age=3600, s-maxage=86400",
        ...CORS_HEADERS,
      },
    });
  }

  if (path === "/mcp/.well-known/oauth-authorization-server") {
    const meta = {
      issuer: url.origin,
      authorization_endpoint: null,
      token_endpoint: null,
      response_types_supported: [],
      grant_types_supported: [],
      auth_policy: "none_public_curated_registry",
    };
    return new Response(JSON.stringify(meta, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "public, max-age=3600, s-maxage=86400",
        ...CORS_HEADERS,
      },
    });
  }

  // 2. Strict Allowlist Gate: Reject unapproved paths before waking asset fetchers
  // Prevents internal asset subrequest fallback timeouts (2a06:98c0:3600::103) on unrouted scanner probes
  if (!isAllowed(path) && !isAllowed(url.pathname)) {
    return new Response("Not Found", {
      status: 404,
      headers: {
        "Content-Type": "text/plain",
        "Cache-Control": "public, max-age=3600, s-maxage=86400",
        ...CORS_HEADERS,
      },
    });
  }

  // 3. Normal execution flow for allowlisted dynamic routes
  return await context.next();
}
