/**
 * FMagenticL Cloudflare Pages Edge Middleware
 * 1. Fast 404 for exploit probes & dotfiles (prevents 36KB SPA index.html fallback timeouts).
 * 2. Dedicated handler for /mcp/server-card (resolves missing card endpoint).
 * 3. Pass-through for legitimate registry assets, API routes, and MCP protocol traffic.
 */

const SCANNER_PROBE_REGEX = /^\/(actuator(\/.*)?|\.env.*|\.git.*|\.vscode(\/.*)?|\.cursor(\/.*)?|wp-.*|api\/auth(\/.*)?|[a-f0-9]{32})$/i;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, Mcp-Session-Id, Authorization",
};

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/$/, "");

  // 1. Fast-reject automated exploit scanner paths and random hex hashes
  if (SCANNER_PROBE_REGEX.test(path)) {
    return new Response("Not Found", {
      status: 404,
      headers: {
        "Content-Type": "text/plain",
        "Cache-Control": "public, max-age=3600, s-maxage=86400",
        ...CORS_HEADERS,
      },
    });
  }

  // 2. Fast 200 OK for /mcp/server-card
  if (path === "/mcp/server-card") {
    const card = {
      name: "fmagenticl-registry-mcp",
      version: "1.4.0",
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

  // 3. Normal execution flow
  return await context.next();
}
