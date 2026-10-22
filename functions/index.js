/**
 * Cloudflare Pages Functions — Root Content Negotiation
 * Route: /
 *
 * Directs clients to the human landing page (/index.html) by default.
 * Directs requests with Accept: text/plain to /llms.txt.
 */

export async function onRequestGet(context) {
  const { request, env } = context;
  const accept = request.headers.get("Accept") || "";

  const wantsLlms = accept.includes("text/plain") && !accept.includes("text/html");

  if (env && env.ASSETS) {
    let resp;
    if (wantsLlms) {
      const targetUrl = new URL("/llms.txt", request.url);
      resp = await env.ASSETS.fetch(new Request(targetUrl.toString(), request));
    } else {
      resp = await env.ASSETS.fetch(request);
    }
    const newHeaders = new Headers(resp.headers);
    newHeaders.set("Vary", "Accept, User-Agent");
    return new Response(resp.body, {
      status: resp.status,
      headers: newHeaders,
    });
  }

  return new Response("FMagenticL Registry", { status: 200 });
}

export async function onRequestHead(context) {
  return onRequestGet(context);
}
