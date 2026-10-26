export async function onRequest(context) {
  const url = new URL(context.request.url);
  const leaf = url.pathname.replace(/^\/\.well-known\/+/, "").toLowerCase();

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

  return context.env.ASSETS.fetch(context.request);
}
