/**
 * FMagenticL - Health Endpoint Handler
 * Directly intercepts GET /health at the Cloudflare Pages Functions edge
 * to return application/json instead of falling through to SPA index.html.
 */

const CORS_HEADERS = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Cache-Control": "public, max-age=60, s-maxage=120"
};

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  // 1. Attempt to serve compiled static health manifest from ASSETS
  if (env && env.ASSETS) {
    try {
      const assetUrl = new URL("/health", request.url);
      const res = await env.ASSETS.fetch(new Request(assetUrl, { method: "GET" }));
      if (res && res.ok) {
        const body = await res.text();
        return new Response(body, { status: 200, headers: CORS_HEADERS });
      }
    } catch (_) {}
  }

  // 2. Fallback dynamic payload if ASSETS fetch is unavailable
  return new Response(JSON.stringify({
    status: "ok",
    protocol_version: "1.3.1",
    service: "FMagenticL-Curated-Registry",
    auth_policy: "none_public_curated_registry"
  }), { status: 200, headers: CORS_HEADERS });
}
