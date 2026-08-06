/**
 * Adapter for an existing Lovable/Supabase project.
 * Import the project's existing Supabase client instead of creating another one.
 */
export async function cookieCoreRequest<T>(
  supabase: {
    auth: {
      getSession: () => Promise<{ data: { session: { access_token: string } | null } }>;
      refreshSession?: () => Promise<{
        data: { session: { access_token: string } | null };
        error?: unknown;
      }>;
    };
  },
  supabaseUrl: string,
  publishableKey: string,
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const { data } = await supabase.auth.getSession();
  if (!data.session) throw new Error("Sua sessão expirou. Entre novamente.");

  const endpoint = `${supabaseUrl.replace(/\/$/, "")}/functions/v1/cookie-core?path=${encodeURIComponent(path)}`;
  const send = (accessToken: string) => {
    const headers = new Headers(init.headers);
    headers.set("apikey", publishableKey);
    headers.set("Authorization", `Bearer ${accessToken}`);
    if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    return fetch(endpoint, { ...init, headers });
  };

  let response = await send(data.session.access_token);
  if (response.status === 401 && supabase.auth.refreshSession) {
    const refreshed = await supabase.auth.refreshSession();
    if (refreshed.data.session) response = await send(refreshed.data.session.access_token);
  }
  const payload = await response.json().catch(() => ({} as Record<string, unknown>));
  if (!response.ok) {
    const detail = typeof payload.detail === "string"
      ? payload.detail
      : "Não foi possível concluir a operação.";
    const requestId = response.headers.get("x-request-id");
    throw new Error(requestId ? `${detail} (código: ${requestId})` : detail);
  }
  return payload as T;
}
