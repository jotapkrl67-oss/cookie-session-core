import { createClient } from "npm:@supabase/supabase-js@2";

const coreUrl = Deno.env.get("COOKIE_CORE_API_URL")?.replace(/\/$/, "");
const adminSecret = Deno.env.get("COOKIE_CORE_ADMIN_SECRET");
const allowedOrigin = Deno.env.get("LOVABLE_APP_ORIGIN")?.replace(/\/$/, "");
const supabaseUrl = Deno.env.get("SUPABASE_URL");
const supabaseKey = Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ?? Deno.env.get("SUPABASE_ANON_KEY");
const expectedAdminRole = Deno.env.get("COOKIE_CORE_ADMIN_ROLE") ?? "admin";
const parsedTimeout = Number(Deno.env.get("COOKIE_CORE_TIMEOUT_MS") ?? "120000");
const parsedMaxBody = Number(Deno.env.get("COOKIE_CORE_MAX_BODY_BYTES") ?? "1100000");
const coreTimeoutMs = Number.isFinite(parsedTimeout)
  ? Math.min(600_000, Math.max(5_000, parsedTimeout))
  : 120_000;
const maxBodyBytes = Number.isFinite(parsedMaxBody)
  ? Math.min(2_000_000, Math.max(100_000, parsedMaxBody))
  : 1_100_000;

if (!coreUrl || !adminSecret || !allowedOrigin || !supabaseUrl || !supabaseKey) {
  throw new Error("Cookie Core Edge Function secrets are incomplete");
}
const parsedCoreUrl = new URL(coreUrl);
if (!['http:', 'https:'].includes(parsedCoreUrl.protocol)
  || parsedCoreUrl.username || parsedCoreUrl.password
  || !['', '/'].includes(parsedCoreUrl.pathname)
  || parsedCoreUrl.search || parsedCoreUrl.hash) {
  throw new Error("COOKIE_CORE_API_URL must be one HTTP(S) origin");
}

const corsHeaders = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Vary": "Origin",
};

const allowedRoutes: Array<[RegExp, string[]]> = [
  [/^\/v1\/services$/, ["GET"]],
  [/^\/v1\/services\/[0-9a-f-]{36}\/launch$/, ["POST"]],
  [/^\/v1\/admin\/services$/, ["GET", "POST"]],
  [/^\/v1\/admin\/services\/[0-9a-f-]{36}$/, ["PUT"]],
  [
    /^\/v1\/admin\/services\/[0-9a-f-]{36}\/users\/[0-9a-f-]{36}\/cookies\/import$/,
    ["POST"],
  ],
  [
    /^\/v1\/admin\/services\/[0-9a-f-]{36}\/users\/[0-9a-f-]{36}\/cookies$/,
    ["GET", "DELETE"],
  ],
  [
    /^\/v1\/admin\/services\/[0-9a-f-]{36}\/users\/[0-9a-f-]{36}\/localstorage\/import$/,
    ["POST"],
  ],
  [
    /^\/v1\/admin\/services\/[0-9a-f-]{36}\/users\/[0-9a-f-]{36}\/localstorage$/,
    ["GET", "DELETE"],
  ],
  [/^\/v1\/admin\/cf\/clearance$/, ["GET", "POST"]],
  [/^\/v1\/admin\/cf\/clearance\/(?:__all__|[a-z0-9.-]+)$/, ["DELETE"]],
  [/^\/v1\/admin\/cf\/status$/, ["GET"]],
  [/^\/v1\/admin\/cf\/solve$/, ["POST"]],
];

function routeAllowed(path: string, method: string): boolean {
  return allowedRoutes.some(([pattern, methods]) => pattern.test(path) && methods.includes(method));
}

function json(body: unknown, status: number): Response {
  return Response.json(body, { status, headers: corsHeaders });
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  if (request.headers.get("origin")?.replace(/\/$/, "") !== allowedOrigin) {
    return json({ detail: "Origin not allowed" }, 403);
  }

  const authorization = request.headers.get("authorization");
  const bearer = authorization?.match(/^Bearer\s+(\S+)$/i);
  if (!authorization || !bearer) {
    return json({ detail: "Authentication required" }, 401);
  }

  const supabase = createClient(
    supabaseUrl,
    supabaseKey,
    { global: { headers: { Authorization: authorization } } },
  );
  let data;
  let error;
  try {
    ({ data, error } = await supabase.auth.getUser(bearer[1]));
  } catch {
    return json({ detail: "Authentication service is unavailable" }, 503);
  }
  if (error || !data.user) return json({ detail: "Invalid authentication" }, 401);

  const url = new URL(request.url);
  const path = url.searchParams.get("path") ?? "";
  if (!routeAllowed(path, request.method)) return json({ detail: "Route not allowed" }, 404);

  const isAdminRoute = path.startsWith("/v1/admin/");
  if (isAdminRoute) {
    // This reads server-controlled app_metadata, not editable user_metadata.
    // If your existing Lovable project stores roles in a table, replace ONLY this
    // expression with the same server-side permission check already used there.
    const role = data.user.app_metadata?.role;
    if (role !== expectedAdminRole) return json({ detail: "Administrator permission required" }, 403);
  }

  const headers = new Headers({
    "Authorization": authorization,
    "Content-Type": request.headers.get("content-type") ?? "application/json",
    "X-Request-ID": crypto.randomUUID(),
  });
  if (isAdminRoute) headers.set("X-Cookie-Core-Admin", adminSecret);

  const hasBody = !["GET", "HEAD"].includes(request.method);
  const contentLength = request.headers.get("content-length");
  const declaredLength = Number(contentLength ?? "0");
  if (contentLength && (!Number.isSafeInteger(declaredLength) || declaredLength < 0)) {
    return json({ detail: "Invalid Content-Length" }, 400);
  }
  if (hasBody && declaredLength > maxBodyBytes) {
    return json({ detail: "Request body is too large" }, 413);
  }
  const body = hasBody ? await request.arrayBuffer() : undefined;
  if (body && body.byteLength > maxBodyBytes) {
    return json({ detail: "Request body is too large" }, 413);
  }
  let upstream: Response;
  try {
    upstream = await fetch(`${coreUrl}${path}`, {
      method: request.method,
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(coreTimeoutMs),
    });
  } catch (error) {
    const timedOut = error instanceof DOMException && error.name === "TimeoutError";
    return json(
      { detail: timedOut ? "Cookie Core timed out" : "Cookie Core is unavailable" },
      timedOut ? 504 : 502,
    );
  }
  const responseHeaders = new Headers(corsHeaders);
  responseHeaders.set("Content-Type", upstream.headers.get("content-type") ?? "application/json");
  responseHeaders.set("Cache-Control", "no-store");
  const requestId = upstream.headers.get("x-request-id");
  if (requestId) responseHeaders.set("X-Request-ID", requestId);
  const retryAfter = upstream.headers.get("retry-after");
  if (retryAfter) responseHeaders.set("Retry-After", retryAfter);
  return new Response(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });
});
