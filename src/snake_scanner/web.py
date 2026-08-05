"""Web GUI for the Voice AI verification snake.

Serves a single self-contained page and streams each stage result to the browser
over Server-Sent Events as it completes, so the chain builds live in the UI.
All probing is delegated to `engine`; this module is transport + presentation.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

try:
    import uvicorn
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, StreamingResponse
except ImportError:  # pragma: no cover - import-time guard
    print("The web GUI needs extra deps:  pip install 'snake-scanner[web]'", file=sys.stderr)
    raise

from . import __tool_name__
from .engine import STAGE_NAMES, run_stream, save

app = FastAPI(title=__tool_name__, docs_url=None, redoc_url=None)


# ── SSE stream ───────────────────────────────────────────────────────────────────
def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


def stream_snake(host: str, port: int, service: str = "auto", active: bool = False):
    def _gen():
        results = []
        detected_service = service
        t0 = time.time()
        ctx: dict = {}

        for result, svc, cur_ctx in run_stream(host, port, service, active=active):
            ctx = cur_ctx
            if result is None:  # service-detected sentinel
                detected_service = svc
                yield _sse({"type": "service", "service": svc})
                continue
            results.append(result)
            yield _sse({"type": "stage", "name": result.name, "status": result.status,
                        "evidence": result.evidence, "detail": result.detail})

        elapsed = time.time() - t0
        try:
            save(host, port, detected_service, results, elapsed, ctx)
        except OSError:
            pass
        yield _sse({"type": "complete", "elapsed": round(elapsed, 1),
                    "open_paths": ctx.get("open_paths", []),
                    "surfaces": ctx.get("exploit_surfaces", []),
                    "adjacent_count": len(ctx.get("adjacent", []))})

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/run")
def run_endpoint(host: str, port: int, service: str = "auto", active: bool = False):
    return stream_snake(host, port, service, active=active)


@app.get("/")
def index():
    return HTMLResponse(_render_index())


# ── frontend ─────────────────────────────────────────────────────────────────────
def _render_index() -> str:
    # Inject the canonical stage list so the UI never drifts from the engine.
    return _HTML.replace("__STAGE_NAMES__", json.dumps(STAGE_NAMES))


_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>🐍 Voice AI verification snake</title>
<style>
  :root {
    --bg:#0d0d0f; --bg2:#141418; --bg3:#1c1c22; --border:#2a2a35;
    --text:#e8e8f0; --dim:#5a5a6e; --green:#3dd68c; --red:#ff5f6d;
    --yellow:#f5c542; --cyan:#4ecdc4; --magenta:#c084fc; --grey:#4a4a5a;
    --mono:"JetBrains Mono","Fira Code","Cascadia Code",monospace;
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body {
    background:var(--bg); color:var(--text); font-family:var(--mono);
    font-size:13px; min-height:100vh; display:flex; flex-direction:column;
    align-items:center; padding:32px 16px;
  }
  .header { text-align:center; margin-bottom:32px; }
  .header h1 { font-size:26px; letter-spacing:2px; color:var(--green); }
  .header p  { color:var(--dim); margin-top:6px; font-size:12px; letter-spacing:1px; }
  .input-bar {
    display:flex; gap:8px; align-items:center; background:var(--bg2);
    border:1px solid var(--border); border-radius:8px; padding:12px 16px;
    width:100%; max-width:680px; margin-bottom:14px; flex-wrap:wrap;
  }
  .input-bar input {
    background:transparent; border:none; outline:none; color:var(--text);
    font-family:var(--mono); font-size:14px; flex:1; min-width:120px;
  }
  .input-bar input::placeholder { color:var(--dim); }
  .sep { color:var(--border); font-size:18px; }
  .input-bar input.port { width:72px; flex:0 0 auto; text-align:center; }
  .run-btn {
    background:var(--green); color:#000; border:none; border-radius:6px;
    padding:8px 20px; font-family:var(--mono); font-size:13px; font-weight:700;
    cursor:pointer; letter-spacing:1px; transition:opacity .15s; white-space:nowrap;
  }
  .run-btn:hover { opacity:.85; }
  .run-btn:disabled { opacity:.4; cursor:not-allowed; }
  .active-toggle {
    display:flex; align-items:center; gap:6px; color:var(--dim);
    font-size:11px; letter-spacing:.5px; max-width:680px; width:100%;
    margin-bottom:24px; cursor:pointer;
  }
  .active-toggle input { accent-color:var(--yellow); }
  .active-toggle .warn { color:var(--yellow); }
  .chain-bar {
    display:flex; flex-wrap:wrap; gap:6px; width:100%; max-width:900px;
    margin-bottom:24px; min-height:34px;
  }
  .chip {
    border:1px solid var(--border); border-radius:5px; padding:4px 10px;
    font-size:11px; letter-spacing:.5px; color:var(--dim); transition:all .25s ease;
    display:flex; align-items:center; gap:5px;
  }
  .chip .sym { font-size:13px; }
  .chip.pass  { border-color:var(--green);  color:var(--green);  background:#3dd68c10; }
  .chip.open  { border-color:var(--yellow); color:var(--yellow); background:#f5c54210; }
  .chip.gated { border-color:var(--cyan);   color:var(--cyan);   background:#4ecdc410; }
  .chip.fail, .chip.skip { border-color:var(--grey); color:var(--grey); background:transparent; }
  .chip.error { border-color:var(--red);    color:var(--red);    background:#ff5f6d10; }
  .chip.running { border-color:var(--cyan); color:var(--cyan);   animation:pulse 1s infinite; }
  @keyframes pulse { 0%,100%{opacity:.5} 50%{opacity:1} }
  .stages { width:100%; max-width:900px; display:flex; flex-direction:column; gap:4px; }
  .stage-row {
    display:grid; grid-template-columns:160px 72px 1fr; gap:12px;
    background:var(--bg2); border:1px solid var(--border); border-radius:6px;
    padding:10px 14px; animation:fadeIn .2s ease;
  }
  @keyframes fadeIn { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:none} }
  .stage-name { font-weight:700; color:var(--dim); font-size:11px; letter-spacing:1px; align-self:center; }
  .stage-status { font-size:11px; font-weight:700; border-radius:4px; padding:2px 8px; text-align:center; align-self:center; }
  .stage-evidence { color:var(--text); font-size:12px; align-self:center; line-height:1.5; word-break:break-word; }
  .detail-row { grid-column:3; color:var(--dim); font-size:11px; margin-top:2px; line-height:1.6; }
  .s-pass  .stage-status { background:#3dd68c20; color:var(--green); }
  .s-open  .stage-status { background:#f5c54220; color:var(--yellow); }
  .s-gated .stage-status { background:#4ecdc420; color:var(--cyan); }
  .s-fail  .stage-status, .s-skip .stage-status { background:transparent; color:var(--grey); }
  .s-error .stage-status { background:#ff5f6d20; color:var(--red); }
  .s-pass  .stage-name { color:var(--green); }
  .s-open  .stage-name { color:var(--yellow); }
  .s-gated .stage-name { color:var(--cyan); }
  .summary-card {
    width:100%; max-width:900px; margin-top:20px; background:var(--bg2);
    border:1px solid var(--border); border-radius:8px; padding:20px 24px;
    display:flex; align-items:center; gap:24px; animation:fadeIn .3s ease; flex-wrap:wrap;
  }
  .summary-verdict { font-size:18px; font-weight:700; letter-spacing:2px; padding:8px 18px; border-radius:6px; white-space:nowrap; }
  .summary-verdict.open  { background:#f5c54220; color:var(--yellow); border:1px solid var(--yellow); }
  .summary-verdict.clear { background:#3dd68c10; color:var(--green); border:1px solid var(--green); }
  .summary-num { font-size:28px; font-weight:700; color:var(--text); }
  .summary-label { font-size:11px; color:var(--dim); letter-spacing:1px; }
  .summary-surfaces { flex:1; min-width:200px; }
  .summary-surfaces .surf { display:inline-block; margin:3px 4px 3px 0; background:#f5c54210; border:1px solid #f5c54240; border-radius:4px; padding:3px 10px; font-size:11px; color:var(--yellow); }
  .summary-surfaces .none { color:var(--dim); font-size:12px; }
  .summary-elapsed { color:var(--dim); font-size:11px; white-space:nowrap; }
  .svc-badge { display:inline-block; margin-bottom:12px; background:var(--bg3); border:1px solid var(--border); border-radius:4px; padding:3px 12px; font-size:11px; color:var(--cyan); letter-spacing:1px; }
  .status-line { color:var(--dim); font-size:11px; letter-spacing:1px; margin-bottom:8px; width:100%; max-width:900px; }
  hr.divider { border:none; border-top:1px solid var(--border); width:100%; max-width:900px; margin:20px 0; }
</style>
</head>
<body>

<div class="header">
  <h1>🐍 VOICE AI VERIFICATION SNAKE</h1>
  <p>12-STAGE AI/ML SERVICE VERIFICATION CHAIN</p>
</div>

<div class="input-bar">
  <input id="ip" type="text" placeholder="IP or hostname" value="" spellcheck="false" autocomplete="off">
  <span class="sep">:</span>
  <input id="port" type="number" class="port" placeholder="port" value="">
  <button class="run-btn" id="runBtn" onclick="startSnake()">RUN</button>
</div>
<label class="active-toggle" for="active">
  <input type="checkbox" id="active">
  <span><span class="warn">⚠ active mode</span> — allow the INFERENCE stage to invoke the target's compute (authorized targets only)</span>
</label>

<div id="chain" class="chain-bar"></div>
<div id="svcBadge"></div>
<div id="statusLine" class="status-line"></div>
<div id="stages" class="stages"></div>
<div id="summaryCard"></div>

<script>
const STAGE_NAMES = __STAGE_NAMES__;
const STATUS_SYM = { PASS:"✓", FAIL:"✗", OPEN:"⚠", GATED:"🔒", SKIP:"—", ERROR:"!" };
const SHOW_DETAIL = new Set(["open","open_paths","findings","surfaces","high_impact","adjacent","adjacent_count","count","sample","type","bytes","reachable"]);

let es = null;

function startSnake() {
  const host = document.getElementById("ip").value.trim();
  const port = document.getElementById("port").value.trim();
  const active = document.getElementById("active").checked;
  if (!host || !port) return;

  document.getElementById("chain").innerHTML = "";
  document.getElementById("stages").innerHTML = "";
  document.getElementById("summaryCard").innerHTML = "";
  document.getElementById("svcBadge").innerHTML = "";
  document.getElementById("statusLine").textContent = "connecting...";
  document.getElementById("runBtn").disabled = true;

  STAGE_NAMES.forEach(n => {
    const chip = document.createElement("div");
    chip.className = "chip";
    chip.id = "chip-" + n;
    chip.innerHTML = `<span class="sym">·</span><span>${n}</span>`;
    document.getElementById("chain").appendChild(chip);
  });

  if (es) es.close();
  const url = `/run?host=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}&active=${active}`;
  es = new EventSource(url);

  updateChip("ENDPOINT", "running", "…");
  document.getElementById("statusLine").textContent = `probing ${host}:${port} …`;

  const stageOrder = [...STAGE_NAMES];
  let nextIdx = 0;

  es.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.type === "service") {
      document.getElementById("svcBadge").innerHTML =
        `<div class="svc-badge">auto-detected: ${escHtml(data.service)}</div>`;
      return;
    }
    if (data.type === "stage") {
      const { name, status, evidence, detail } = data;
      updateChip(name, status.toLowerCase(), STATUS_SYM[status] || "?");
      appendStage(name, status, evidence, detail);
      nextIdx++;
      if (nextIdx < stageOrder.length) updateChip(stageOrder[nextIdx], "running", "…");
      document.getElementById("statusLine").textContent = `${name} [${status}]  —  ${evidence.slice(0, 80)}`;
      return;
    }
    if (data.type === "complete") {
      es.close();
      document.getElementById("runBtn").disabled = false;
      document.getElementById("statusLine").textContent = `done — ${data.elapsed}s`;
      renderSummary(data);
    }
  };

  es.onerror = () => {
    es.close();
    document.getElementById("runBtn").disabled = false;
    document.getElementById("statusLine").textContent = "connection error";
  };
}

function updateChip(name, cssClass, sym) {
  const chip = document.getElementById("chip-" + name);
  if (!chip) return;
  chip.className = "chip " + cssClass;
  chip.innerHTML = `<span class="sym">${sym}</span><span>${escHtml(name)}</span>`;
}

function appendStage(name, status, evidence, detail) {
  const row = document.createElement("div");
  row.className = `stage-row s-${status.toLowerCase()}`;
  const detailLines = Object.entries(detail || {})
    .filter(([k]) => SHOW_DETAIL.has(k))
    .map(([k, v]) => {
      const vs = typeof v === "object" ? JSON.stringify(v).slice(0, 120) : String(v).slice(0, 120);
      return `<span style="color:var(--dim)">${escHtml(k)}</span>: ${escHtml(vs)}`;
    }).join("  ·  ");
  row.innerHTML = `
    <div class="stage-name">${escHtml(name)}</div>
    <div class="stage-status">${escHtml(status)}</div>
    <div class="stage-evidence">${escHtml(evidence)}
      ${detailLines ? `<div class="detail-row">${detailLines}</div>` : ""}
    </div>`;
  document.getElementById("stages").appendChild(row);
  row.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function renderSummary(data) {
  const surfaces = data.surfaces || [];
  const openCount = (data.open_paths || []).length;
  const exposed = openCount > 0 || surfaces.length > 0;
  const surfsHtml = surfaces.length
    ? surfaces.map(s => `<span class="surf">${escHtml(s)}</span>`).join("")
    : `<span class="none">no exploit surface classified</span>`;
  const verdict = exposed
    ? `<div class="summary-verdict open">OPEN</div>`
    : `<div class="summary-verdict clear">NO EXPOSURE</div>`;
  document.getElementById("summaryCard").innerHTML = `
    <hr class="divider">
    <div class="summary-card">
      <div>${verdict}</div>
      <div>
        <div class="summary-num">${openCount}</div>
        <div class="summary-label">OPEN PATHS</div>
      </div>
      <div class="summary-surfaces">${surfsHtml}</div>
      <div class="summary-elapsed">${escHtml(String(data.elapsed))}s · ${data.adjacent_count ?? 0} adjacent</div>
    </div>`;
}

function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

document.addEventListener("DOMContentLoaded", () => {
  ["ip","port"].forEach(id => {
    document.getElementById(id).addEventListener("keydown", e => {
      if (e.key === "Enter") startSnake();
    });
  });
});
</script>
</body>
</html>"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="snake-web", description="Web GUI for the Voice AI verification snake.")
    ap.add_argument("--port", "-p", type=int, default=7331)
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1; use 0.0.0.0 to expose on the LAN)")
    args = ap.parse_args(argv)
    print(f"🐍 {__tool_name__}  →  http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
