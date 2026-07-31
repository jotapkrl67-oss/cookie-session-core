const statusElement = document.querySelector("#status");
const token = new URLSearchParams(location.hash.slice(1)).get("token");
history.replaceState(null, "", "/remote/start");

async function exchange() {
  if (!token || token.length < 32) {
    statusElement.textContent = "Link inválido ou incompleto.";
    return;
  }
  try {
    const response = await fetch("/v1/launch/exchange", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || "Não foi possível abrir a sessão.");
    location.replace(`/remote/${payload.session_id}/`);
  } catch (error) {
    statusElement.textContent = error instanceof Error ? error.message : "Falha ao abrir.";
  }
}

exchange();
