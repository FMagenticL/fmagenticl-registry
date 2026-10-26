export async function onRequest(context) {
  const url = new URL(context.request.url);
  const leaf = url.pathname.replace(/^\/\.well-known\/+/, "").toLowerCase();

  // 1. Serve zero-cost x402 machine-payment discovery manifest
  if (leaf === "x402" || leaf === "x402.json") {
    return new Response(
      JSON.stringify({
        version: "1.0",
        name: "FMagenticL",
        endpoint: "https://fmagenticl-registry.pages.dev/mcp",
        payment_required: false,
        price: "0.00",
        currency: "USDC",
        network: "Base",
        description: "Zero-cost public MCP failure registry and deterministic patch engine."
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "public, max-age=3600"
        }
      }
    );
  }

  // 2. Return clean 404 JSON for unauthenticated OAuth / OIDC discovery probes
  if (leaf.startsWith("oauth") || leaf.startsWith("openid")) {
    return new Response(
      JSON.stringify({
        error: "not_found",
        oauth_required: false,
        message: "FMagenticL is a public, unauthenticated MCP registry."
      }),
      {
        status: 404,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "public, max-age=3600"
        }
      }
    );
  }

  // 3. Fetch legitimate static discovery files (.well-known/agent.json, mcp.json, ai-catalog.json, glama.json)
  const assetResponse = await context.env.ASSETS.fetch(context.request);
  const contentType = assetResponse.headers.get("content-type") || "";

  // Prevent Cloudflare Pages SPA fallback from serving index.html (text/html) on nonexistent .well-known paths
  if (contentType.includes("text/html")) {
    return new Response(
      JSON.stringify({
        error: "not_found",
        path: url.pathname,
        message: "Requested .well-known discovery document does not exist."
      }),
      {
        status: 404,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "public, max-age=3600"
        }
      }
    );
  }

  return assetResponse;
}
