/**
 * FMagenticL v3.0 Cloudflare Pages Edge Middleware
 * Strict read-only allowlist + security headers + MCP discovery cards.
 */

const SECURITY_HEADERS = {
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy":
    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
};

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, Mcp-Session-Id, X-FMagenticL-Profile",
  ...SECURITY_HEADERS,
};

const EXACT_ALLOWLIST = new Set([
  "",
  "/",
  "/index.html",
  "/llms.txt",
  "/registry.json",
  "/mcp",
  "/mcp/server-card",
  "/mcp/.well-known/oauth-protected-resource",
  "/mcp/.well-known/oauth-authorization-server",
  "/health",
  "/v1/health",
  "/v1/snapshot.json",
  "/v1/snapshot.sig",
  "/v1/snapshot.v3.sig",
  "/v1/keyring.json",
  "/v1/bloom.bin",
  "/.well-known/mcp.json",
  "/.well-known/agent.json",
]);

const PREFIX_ALLOWLIST = [
  "/v1/signatures/",
  "/v1/resolve/",
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

  if (path === "/mcp/server-card") {
    const card = {
      name: "fmagenticl-registry-mcp",
      version: "3.0.0",
      description:
        "FMagenticL Signed Registry of Malicious AI Agent Signatures, Offensive Harnesses & Behavioral IOCs",
      transport: "streamable-http",
      endpoint: `${url.origin}/mcp`,
      documentation: `${url.origin}/llms.txt`,
      tools_count: 3,
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

  const response = await context.next();
  const nextHeaders = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    if (!nextHeaders.has(k)) nextHeaders.set(k, v);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: nextHeaders,
  });
}
