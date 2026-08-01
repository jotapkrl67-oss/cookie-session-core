import { createClient } from "npm:@supabase/supabase-js@2";

const coreUrl = Deno.env.get("COOKIE_CORE_API_URL")?.replace(/\/$/, "");
const adminSecret = Deno.env.get("COOKIE_CORE_ADMIN_SECRET");
const allowedOrigin = Deno.env.get("LOVABLE_APP_ORIGIN")?.replace(/\/$/, "");
const expectedAdminRole = Deno.env.get("COOKIE_CORE_ADMIN_ROLE") ?? "admin";

if (!coreUrl || !adminSecret || !allowedOrigin) {
  throw new Error("Cookie Core Edge Function secrets are incomplete");
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
  if (!authorization?.startsWith("Bearer ")) return json({ detail: "Authentication required" }, 401);

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    (Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ?? Deno.env.get("SUPABASE_ANON_KEY"))!,
    { global: { headers: { Authorization: authorization } } },
  );
  const { data, error } = await supabase.auth.getUser(authorization.slice(7));
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
  });
  if (isAdminRoute) headers.set("X-Cookie-Core-Admin", adminSecret);

  const body = ["GET", "HEAD"].includes(request.method) ? undefined : await request.arrayBuffer();
  const upstream = await fetch(`${coreUrl}${path}`, {
    method: request.method,
    headers,
    body,
    redirect: "manual",
  });
  const responseHeaders = new Headers(corsHeaders);
  responseHeaders.set("Content-Type", upstream.headers.get("content-type") ?? "application/json");
  responseHeaders.set("Cache-Control", "no-store");
  const requestId = upstream.headers.get("x-request-id");
  if (requestId) responseHeaders.set("X-Request-ID", requestId);
  return new Response(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });
});
