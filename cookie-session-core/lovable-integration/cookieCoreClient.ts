/**
 * Adapter for an existing Lovable/Supabase project.
 * Import the project's existing Supabase client instead of creating another one.
 */
export async function cookieCoreRequest<T>(
  supabase: {
    auth: { getSession: () => Promise<{ data: { session: { access_token: string } | null } }> };
  },
  supabaseUrl: string,
  publishableKey: string,
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const { data } = await supabase.auth.getSession();
  if (!data.session) throw new Error("Sua sessão expirou. Entre novamente.");

  const response = await fetch(
    `${supabaseUrl.replace(/\/$/, "")}/functions/v1/cookie-core?path=${encodeURIComponent(path)}`,
    {
      ...init,
      headers: {
        "apikey": publishableKey,
        "Authorization": `Bearer ${data.session.access_token}`,
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        ...init.headers,
      },
    },
  );
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || "Não foi possível concluir a operação.");
  return payload as T;
}
