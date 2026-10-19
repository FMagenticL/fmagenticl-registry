/**
 * Cloudflare Pages Functions — Root Content Negotiation
 * Route: /
 *
 * Directs browsers (Accept: text/html) to the human dark-mode landing page (/index.html).
 * Directs AI agents & CLI tools (curl, python, node, Claude, ChatGPT, text/plain) to /llms.txt.
 */

export async function onRequestGet(context) {
  const { request, env } = context;
  const accept = request.headers.get("Accept") || "";
  const userAgent = (request.headers.get("User-Agent") || "").toLowerCase();

  const isAgentCli =
    userAgent.includes("curl") ||
    userAgent.includes("wget") ||
    userAgent.includes("httpie") ||
    userAgent.includes("python") ||
    userAgent.includes("node") ||
    userAgent.includes("claude") ||
    userAgent.includes("chatgpt") ||
    userAgent.includes("bot") ||
    !accept.includes("text/html");

  if (env && env.ASSETS) {
    const targetPath = isAgentCli ? "/llms.txt" : "/index.html";
    const targetUrl = new URL(targetPath, request.url);
    const resp = await env.ASSETS.fetch(new Request(targetUrl.toString(), request));
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
