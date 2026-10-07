// Cloudflare Pages Function — /api/v1/patches
// Reads registry.json from static assets, applies query filters, returns paginated JSON.
// Schema expected: { registry_version, generated, count, patches: [{ id, attribution, failure_mode, patch_hash, signed }] }

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept",
};

const JSON_HEADERS = {
  ...CORS_HEADERS,
  "Content-Type": "application/json; charset=utf-8",
};

function jsonResponse(body, status, extraHeaders = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  });
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    return jsonResponse(
      { error: "method_not_allowed", allowed: ["GET", "HEAD", "OPTIONS"] },
      405
    );
  }

  // Fetch registry.json from static assets.
  const registryUrl = new URL("/registry.json", url.origin);
  let registryResp;
  try {
    registryResp = await env.ASSETS.fetch(
      new Request(registryUrl.toString(), { method: "GET" })
    );
  } catch (err) {
    return jsonResponse(
      {
        error: "registry_unreachable",
        hint: "ASSETS binding failed. Confirm dist/registry.json exists and Pages Functions are enabled.",
      },
      503
    );
  }

  if (!registryResp.ok) {
    return jsonResponse(
      {
        error: "registry_unavailable",
        upstream_status: registryResp.status,
        hint: "dist/registry.json not found or not served.",
      },
      503
    );
  }

  let registry;
  try {
    registry = await registryResp.json();
  } catch (err) {
    return jsonResponse(
      { error: "registry_malformed", hint: "registry.json is not valid JSON." },
      500
    );
  }

  const params = url.searchParams;
  const filterId = params.get("id");
  const filterAgent = params.get("agent");
  const filterFailureMode = params.get("failure_mode");

  const rawLimit = parseInt(params.get("limit") ?? "100", 10);
  const rawOffset = parseInt(params.get("offset") ?? "0", 10);
  const limit = Number.isFinite(rawLimit) ? Math.min(Math.max(rawLimit, 1), 500) : 100;
  const offset = Number.isFinite(rawOffset) ? Math.max(rawOffset, 0) : 0;

  let patches = Array.isArray(registry.patches) ? registry.patches : [];

  if (filterId) patches = patches.filter((p) => p.id === filterId);
  if (filterAgent) patches = patches.filter((p) => p.attribution === filterAgent);
  if (filterFailureMode) patches = patches.filter((p) => p.failure_mode === filterFailureMode);

  const total = patches.length;
  const page = patches.slice(offset, offset + limit);

  const body = {
    registry_version: registry.registry_version ?? "1.0.0",
    generated: registry.generated ?? null,
    count: page.length,
    total,
    offset,
    limit,
    patches: page,
  };

  return jsonResponse(body, 200, {
    "Cache-Control": "public, max-age=300, s-maxage=600",
    "X-FMagenticL-Registry-Version": registry.registry_version ?? "1.0.0",
    "X-FMagenticL-Patch-Count": String(total),
  });
}
