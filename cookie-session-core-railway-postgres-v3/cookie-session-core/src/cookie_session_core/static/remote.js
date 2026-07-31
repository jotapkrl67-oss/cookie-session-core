const viewport = document.querySelector(".viewport");
const screen = document.querySelector("#screen");
const context = screen.getContext("2d", { alpha: false });
const overlay = document.querySelector(".overlay");
const statusText = document.querySelector(".state");
const sessionId = document.body.dataset.session;
const returnUrl = document.body.dataset.return;
const wsScheme = location.protocol === "https:" ? "wss" : "ws";
let socket;
let reconnectAttempts = 0;
let manuallyClosed = false;
let hasFrame = false;
let lastMove = 0;
let rendering = false;
let pendingFrame;
let remoteWidth = screen.width;
let remoteHeight = screen.height;
let resizeTimer;

function send(payload) {
  if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify(payload));
}

function position(event) {
  const rect = screen.getBoundingClientRect();
  return {
    x: Math.max(0, Math.min(remoteWidth, (event.clientX - rect.left) * remoteWidth / rect.width)),
    y: Math.max(0, Math.min(remoteHeight, (event.clientY - rect.top) * remoteHeight / rect.height)),
  };
}

function connect() {
  const ws = new WebSocket(`${wsScheme}://${location.host}/remote/${sessionId}/ws`);
  ws.binaryType = "arraybuffer";
  socket = ws;
  ws.onopen = () => {
    reconnectAttempts = 0;
    statusText.textContent = "Conectado";
    resizeRemote(true);
  };
  ws.onmessage = (event) => {
    if (typeof event.data === "string") {
      const message = JSON.parse(event.data);
      if (message.type === "state") statusText.textContent = message.title || "Conectado";
      return;
    }
    renderLatest(event.data);
  };
  ws.onclose = (event) => {
    if (socket !== ws) return;
    if (manuallyClosed || event.code === 4401) {
      overlay.classList.remove("hidden");
      overlay.textContent = "Sessão encerrada";
      if (manuallyClosed && returnUrl) setTimeout(() => location.assign(returnUrl), 350);
      return;
    }
    statusText.textContent = "Reconectando…";
    const delay = Math.min(500 * (2 ** reconnectAttempts++), 5000);
    setTimeout(connect, delay);
  };
}

async function renderLatest(frame) {
  if (rendering) {
    pendingFrame = frame;
    return;
  }
  rendering = true;
  let next = frame;
  try {
    while (next) {
      pendingFrame = undefined;
      const bitmap = await createImageBitmap(new Blob([next], { type: "image/png" }));
      if (screen.width !== bitmap.width || screen.height !== bitmap.height) {
        screen.width = bitmap.width;
        screen.height = bitmap.height;
        remoteWidth = bitmap.width;
        remoteHeight = bitmap.height;
      }
      context.drawImage(bitmap, 0, 0, screen.width, screen.height);
      bitmap.close();
      hasFrame = true;
      overlay.classList.add("hidden");
      next = pendingFrame;
    }
  } finally {
    rendering = false;
    if (pendingFrame) {
      const latest = pendingFrame;
      pendingFrame = undefined;
      renderLatest(latest);
    }
  }
}

function resizeRemote(force = false) {
  const rect = viewport.getBoundingClientRect();
  const width = Math.max(640, Math.min(2560, Math.floor(rect.width)));
  const height = Math.max(480, Math.min(1440, Math.floor(rect.height)));
  if (!force && width === remoteWidth && height === remoteHeight) return;
  send({ type: "resize", width, height });
}

new ResizeObserver(() => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(resizeRemote, 80);
}).observe(viewport);

viewport.addEventListener("mousedown", (event) => {
  viewport.focus();
  send({ type: "click", ...position(event), button: event.button, count: event.detail || 1 });
  event.preventDefault();
});
viewport.addEventListener("mousemove", (event) => {
  const now = performance.now();
  if (now - lastMove < 60) return;
  lastMove = now;
  send({ type: "move", ...position(event) });
});
viewport.addEventListener("wheel", (event) => {
  send({ type: "wheel", deltaX: event.deltaX, deltaY: event.deltaY });
  event.preventDefault();
}, { passive: false });
viewport.addEventListener("keydown", (event) => {
  send({
    type: "key",
    key: event.key,
    ctrl: event.ctrlKey,
    alt: event.altKey,
    shift: event.shiftKey,
    meta: event.metaKey,
  });
  event.preventDefault();
});
viewport.addEventListener("paste", (event) => {
  const text = event.clipboardData?.getData("text/plain");
  if (text) send({ type: "text", text: text.slice(0, 20000) });
  event.preventDefault();
});
document.querySelector("[data-action=back]").onclick = () => send({ type: "back" });
document.querySelector("[data-action=reload]").onclick = () => send({ type: "reload" });
document.querySelector("[data-action=close]").onclick = () => {
  manuallyClosed = true;
  send({ type: "close" });
};

connect();
