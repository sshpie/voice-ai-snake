# 🐍 Voice AI verification snake

A **12-stage verification chain** for exposed AI/ML service infrastructure. Point it at a host:port and it tells you, layer by layer, *what service is running* and *what is reachable without authentication*.

Snake is a **verification** tool, not a discovery scanner. It does not sweep the internet for targets — it takes a target you already have (from Shodan, Censys, an asset inventory, or a scope list) and drives the chain from a live endpoint to an evidenced summary of what's exposed. The load-bearing stage is not the scan; it is turning a *candidate* into a *confirmed, evidenced finding*.

```
ENDPOINT → SCHEMA → AUTH → ENUM → INVENTORY → DATA
  → INFERENCE → EXPLOIT-SURFACE → CHAIN → STORAGE → MONITORING → SUMMARY
```

> **Authorized use only.** Run this only against infrastructure you own or are explicitly permitted to assess. It probes real services and, with `--active`, spends a target's compute. See [Safe-by-default](#safe-by-default).

---

## What it looks like

### Full chain — unauthenticated voice AI stack

```
🐍 SNAKE  10.0.1.5:443  generic  2026-08-06T14:38:27Z

  [ENDPOINT ✓] → [SCHEMA ✓] → [AUTH ⚠] → [ENUM ✗] → [INVENTORY ✗] → [DATA ✗]
     [INFERENCE ⚠] → [EXPLOIT-SURFACE ⚠] → [CHAIN ✓] → [STORAGE ✗] → [MONITORING ✓] → [SUMMARY ⚠]

  ENDPOINT           [PASS]  https 200  server:nginx/1.24.0 (Ubuntu)  701B
  SCHEMA             [PASS]  /openapi.json → 200 non-JSON
  AUTH               [OPEN]  NO AUTH — 10 paths open: /v1/models, /metrics, /slots, /speakers
  ENUM               [FAIL]  no enumerable endpoints returned data
  INVENTORY          [FAIL]  no inventory endpoint found
  DATA               [FAIL]  no data-layer exposure found
  INFERENCE          [OPEN]  inference route reachable — not invoked (pass --active to confirm):
                              /v1/audio/speech(200), /v1/chat/completions(200), /v1/completions(200)
  EXPLOIT-SURFACE    [OPEN]  1 surfaces: COMPUTE-THEFT
  CHAIN              [PASS]  3 adjacent: :80 404 nginx/1.24.0 | :8080 200 nginx/1.29.8 | :9000 200 uvicorn
  STORAGE            [FAIL]  no exposed storage found
  MONITORING         [PASS]  local /metrics — 701B
  SUMMARY            [OPEN]  10 path(s) open without auth · 1 exploit surface(s): COMPUTE-THEFT · 3 adjacent

  OPEN PATHS  (no auth required)
  /v1/models        Model inventory — reveals loaded models
  /metrics          Metrics endpoint
  /slots            Inference slot state — active sessions side-channel
  /speakers         Speaker inventory — voice clone surface
  /asr              Speech recognition endpoint
  /admin            Admin panel
  /config           Config dump
  /actuator/env     Spring Boot actuator — env vars / potential creds
  /v1/audio/voices  Voice inventory
  /health           Health / version info

  ◉ CHAIN COMPLETE
  12 stages  39.2s

  report → ~/.snake/unified/10.0.1.5_443_20260806T143827Z.json
```

The **OPEN PATHS** table appears whenever AUTH is `OPEN` — each unprotected path is paired with a plain-English description of what it enables.

---

### Whisper ASR — schema exposed, auth indeterminate

```
🐍 SNAKE  10.0.1.5:9000  whisper-modern  2026-08-06T14:39:24Z

  [ENDPOINT ✓] → [SCHEMA ✓] → [AUTH ✗] → [ENUM ✗] → [INVENTORY ✗] → [DATA ✗]
     [INFERENCE ⚠] → [EXPLOIT-SURFACE ✗] → [CHAIN ✓] → [STORAGE ✗] → [MONITORING ✗] → [SUMMARY ✗]

  ENDPOINT           [PASS]  http 200  server:uvicorn  856B
  SCHEMA             [PASS]  /openapi.json → 2 paths  Whisper Asr Webservice v1.9.1
  AUTH               [FAIL]  auth state indeterminate
  ENUM               [FAIL]  no enumerable endpoints returned data
  INVENTORY          [FAIL]  no inventory endpoint found
  DATA               [FAIL]  no data-layer exposure found
  INFERENCE          [OPEN]  inference route reachable — not invoked (pass --active to confirm): /asr(405)
  EXPLOIT-SURFACE    [FAIL]  no exploitable surface classified
  CHAIN              [PASS]  3 adjacent: :80 404 nginx/1.24.0 | :443 400 nginx/1.24.0 | :8080 200 nginx/1.29.8
  STORAGE            [FAIL]  no exposed storage found
  MONITORING         [FAIL]  no monitoring endpoint exposed
  SUMMARY            [FAIL]  no unauthenticated exposure found

  ◉ FRONTIER  snake stopped at SUMMARY
  12 stages  52.1s
```

`FRONTIER` means the chain ran to completion but no confirmed open exposure was found. `/asr` returns 405 on GET (it is POST-only); auth state is indeterminate without submitting a payload — use `--active` to resolve.

---

### Hardened host — auth enforced everywhere

```
🐍 SNAKE  10.0.2.1:443  generic  2026-08-06T09:12:04Z

  [ENDPOINT ✓] → [SCHEMA ✓] → [AUTH 🔒] → [ENUM ✗] → [INVENTORY ✗] → [DATA ✗]
     [INFERENCE ✗] → [EXPLOIT-SURFACE ✗] → [CHAIN ✓] → [STORAGE ✗] → [MONITORING ✗] → [SUMMARY ✗]

  ENDPOINT           [PASS]  https 200  server:nginx/1.29.3  2048B
  SCHEMA             [FAIL]  no schema or tech signal found
  AUTH               [GATED] AUTH ENFORCED — /v1/models, /metrics, /admin, /config
  ENUM               [FAIL]  no enumerable endpoints returned data
  INVENTORY          [FAIL]  no inventory endpoint found
  DATA               [FAIL]  no data-layer exposure found
  INFERENCE          [FAIL]  no inference route reachable
  EXPLOIT-SURFACE    [FAIL]  no exploitable surface classified
  CHAIN              [PASS]  1 adjacent: :22 — SSH
  STORAGE            [FAIL]  no exposed storage found
  MONITORING         [FAIL]  no monitoring endpoint exposed
  SUMMARY            [FAIL]  no unauthenticated exposure found

  ◉ FRONTIER  snake stopped at SUMMARY
  12 stages  18.4s
```

`GATED` means auth is enforced — a finding, but not an exposure. This is the correct-negative output for a hardened host.

---

### Batch mode — ranked summary

```bash
snake --batch targets.txt
```

```
────────────────────────────────────────────────────────────────

🐍 SNAKE  10.0.1.5:8880  kokoro  ...
  [AUTH ⚠] ...

────────────────────────────────────────────────────────────────

🐍 SNAKE  10.0.1.6:8880  whisperx  ...
  [AUTH 🔒] ...

────────────────────────────────────────────────────────────────

BATCH SUMMARY — 3 hosts

  10.0.1.5:8880     OPEN   10 open  COMPUTE-THEFT, VOICE-CLONE
  10.0.1.7:7860     OPEN    3 open  CONFIG-DISCLOSE
  10.0.1.6:8880     —       0 open  no surface classified
```

Hosts are ranked by surface count then open-path count, so the worst exposure is always first.

---

### JSON output

```bash
snake 10.0.1.5 443 --json
```

```json
{
  "host": "10.0.1.5",
  "port": 443,
  "service": "generic",
  "timestamp": "20260806T143827Z",
  "elapsed_s": 39.23,
  "active": false,
  "open_paths": [
    "/v1/models",
    "/metrics",
    "/slots",
    "/speakers",
    "/asr",
    "/admin",
    "/config",
    "/actuator/env",
    "/v1/audio/voices",
    "/health"
  ],
  "exploit_surfaces": ["COMPUTE-THEFT"],
  "adjacent_count": 3,
  "stages": [
    { "name": "ENDPOINT", "status": "PASS", "evidence": "https 200  server:nginx/1.24.0  701B" },
    { "name": "AUTH",     "status": "OPEN", "evidence": "NO AUTH — 10 paths open: /v1/models, ..." },
    "..."
  ]
}
```

---

## What it does

| Stage | What it checks |
|-------|----------------|
| **ENDPOINT** | Is the port live? HTTPS-first, HTTP fallback; captures server banner + body size. |
| **SCHEMA** | OpenAPI/Swagger schema (`/openapi.json`, `/swagger.json`, …); falls back to a tech fingerprint (FastAPI, Gradio, Prometheus, GraphQL). |
| **AUTH** | Probes a path set and classifies each as **OPEN** (200, no auth), **GATED** (401/403), or partial — the core "what's open" signal. When OPEN, renders a table of every unprotected path and its significance. |
| **ENUM** | Pulls service identity + model info from health/version/model endpoints. |
| **INVENTORY** | Lists voices / speakers / models when the service type exposes them. |
| **DATA** | Metrics (Prometheus hardware queries), job records, llama.cpp slot side-channel. |
| **INFERENCE** | Confirms the inference route. **Passive** by default (reachability only); **active** (`--active`) submits one minimal, non-retained probe to prove synthesis/completion. |
| **EXPLOIT-SURFACE** | Classifies findings into named surfaces (see below). |
| **CHAIN** | Sweeps co-located ports for adjacent services (the exposure is usually worse than one port). |
| **STORAGE** | Job queues and exposed object storage (MinIO health/banner). |
| **MONITORING** | Exposed `/metrics`, node-exporter, and Prometheus targets. |
| **SUMMARY** | Rolls up: open paths, classified surfaces, adjacent service count. No score — the finding is the exposure itself. |

Stages that don't apply to the detected service type emit **SKIP** and the chain continues.

### Status symbols

Status is **shape + color**, never color alone (color-blind safe):

| Symbol | Status | Meaning |
|--------|--------|---------|
| `✓` | PASS | Stage succeeded |
| `✗` | FAIL | Nothing found / not reachable |
| `⚠` | OPEN | Reachable **without auth** — the finding signal |
| `🔒` | GATED | Reachable but auth-enforced |
| `—` | SKIP | Not applicable to this service type |
| `!` | ERROR | Probe errored |

### Service auto-detection

Auto-detection runs most-specific-first (services that all expose `/metrics` are disambiguated by unique signals before the generic Prometheus check). Force a type with `--service` to skip detection.

```
kokoro · whisperx · cosyvoice · vllm · llamacpp · whisper-modern · subtitle · prometheus · lunary · generic
```

### Exploit surfaces

The `EXPLOIT-SURFACE` stage classifies what an unauthenticated exposure enables. Surfaces marked ★ are **high-impact** — their mere unauthenticated presence is treated as a live exposure (drives the `OPEN` verdict in `SUMMARY`); the rest are informational.

| Surface | Meaning |
|---------|---------|
| COMPUTE-THEFT ★ | Unauthenticated inference — free use of the target's compute |
| VOICE-CLONE ★ | Voice / speaker cloning surface exposed |
| BIOMETRIC-GDPR ★ | Speaker diarization / biometric data (GDPR-relevant) |
| VPN-PIVOT ★ | Overlay-network (e.g. Tailscale) details enabling lateral movement |
| LLM-ABUSE ★ | Open LLM endpoint usable for arbitrary generation |
| TOPOLOGY-LEAK | Infrastructure topology disclosed (Prometheus targets) |
| CONTENT-LEAK | Job / queue records exposing processed content |
| CONFIG-DISCLOSE | Version / config details disclosed |

### Open path significance

When AUTH is `OPEN`, snake renders an **OPEN PATHS** table mapping every unprotected path to plain-English significance:

| Path | Significance |
|------|-------------|
| `/v1/chat/completions` | LLM inference — send arbitrary prompts |
| `/v1/completions` | LLM completions (legacy OpenAI-compat) |
| `/v1/audio/speech` | TTS synthesis — generate audio |
| `/v1/audio/transcriptions` | Audio → text transcription |
| `/asr` | Speech recognition endpoint |
| `/v1/models` | Model inventory — reveals loaded models |
| `/slots` | Inference slot state — active sessions side-channel |
| `/speakers` | Speaker inventory — voice clone surface |
| `/actuator/env` | Spring Boot actuator — env vars / potential creds |
| `/admin` | Admin panel |
| `/config` | Config dump |
| `/api/v1/targets` | Prometheus scrape targets — topology leak |

Unknown paths appear in the table with `—` — they are still reported, just without a pre-mapped description.

---

## Install

```bash
# core CLI
pip install .

# with the web GUI
pip install '.[web]'

# for development (tests + linter)
pip install '.[dev]'
```

Requires Python ≥ 3.9. The only runtime dependency is `requests`; the web GUI adds `fastapi` + `uvicorn`.

### Zero-install (single file)

Don't want to install anything? Grab the standalone [`snake.py`](snake.py) — the whole CLI amalgamated into one file — and run it directly. It needs only `requests`:

```bash
pip install requests           # the sole dependency
python snake.py 10.0.0.5 8880  # same CLI as the installed `snake` command
```

`snake.py` is **generated** from the package sources (`src/snake_scanner/engine.py` + `cli.py`) by `tools/build_standalone.py`; a test asserts it stays byte-identical to a fresh build, so the single-file copy never drifts from the package. Don't edit it by hand — edit the package and run `python tools/build_standalone.py`.

---

## Usage

### CLI

```bash
# auto-detect and run the full chain (passive) — port required
snake 10.0.0.5 8880

# no port: sweep all 42 AI/ML ports, chain against each live one
snake 10.0.0.5

# run chain against every service identified in an aimap JSON report
snake --from-aimap report.json

# combine aimap discovery with snake verification in one pipeline
aimap -target 10.0.0.5 -o report.json && snake --from-aimap report.json

# force a service type, actively confirm inference
snake voice.example.com 8880 --service kokoro --active

# machine-readable output
snake 10.0.0.5 8880 --json

# batch: a file of host:port lines (# comments allowed), ranked summary at the end
snake --batch targets.txt

# re-print the last saved report
snake --report last
```

Also runnable as a module: `python -m snake_scanner 10.0.0.5 8880`.

Honors `NO_COLOR` and non-TTY output automatically; force with `--no-color`.

### Port discovery (no-port mode)

When no port is given, snake sweeps the same 42 AI/ML ports that aimap scans by default, then chains against every port that responds over HTTP:

```
SWEEP  10.0.0.5  42 ports…
  4 live  :80(404)  :443(200)  :8080(200)  :9000(200)

────────────────────────────────────────────────────────────────

🐍 SNAKE  10.0.0.5:443  generic  …
  [AUTH ⚠] …

────────────────────────────────────────────────────────────────

…

════════════════════════════════════════════════════════════════
DISCOVER SUMMARY — 4 target(s)

  10.0.0.5:443    OPEN  10 open  COMPUTE-THEFT
  10.0.0.5:9000   —      0 open  no surface classified
  10.0.0.5:8080   —      0 open  no surface classified
  10.0.0.5:80     —      0 open  no surface classified
```

The sweep is concurrent (24 threads, 3s timeout per port) — wall time is dominated by the slowest single port, not the sum.

### aimap integration (`--from-aimap`)

If you already have an aimap report, snake reads it directly. It pulls from two sections:
- `services[]` — fingerprint-confirmed AI services; service name is mapped to a snake `--service` hint so auto-detection is skipped
- `open_ports[]` — any port returning 200 that aimap didn't fingerprint; chaineed with `--service auto`

```
FROM-AIMAP  report.json  3 target(s)

────────────────────────────────────────────────────────────────
  aimap hint: 10.0.0.5:9000  whisper-asr → whisper-modern

🐍 SNAKE  10.0.0.5:9000  whisper-modern  …

────────────────────────────────────────────────────────────────
  aimap hint: 10.0.0.5:443  auto → auto

🐍 SNAKE  10.0.0.5:443  generic  …
  [AUTH ⚠] …

════════════════════════════════════════════════════════════════
AIMAP SUMMARY — 3 target(s)

  10.0.0.5:443    OPEN  10 open  COMPUTE-THEFT
  10.0.0.5:9000   —      0 open  no surface classified
  10.0.0.5:8080   —      0 open  no surface classified
```

Service name mapping (aimap → snake):

| aimap service | snake `--service` |
|---------------|-------------------|
| Whisper ASR | `whisper-modern` |
| WhisperX | `whisperx` |
| Kokoro | `kokoro` |
| CosyVoice | `cosyvoice` |
| vLLM | `vllm` |
| Llama.cpp | `llamacpp` |
| RTP-LLM | `generic` |
| Chatterbox TTS API | `generic` |
| Prometheus | `prometheus` |
| Lunary | `lunary` |
| (unknown) | `generic` |

### Web GUI

```bash
snake-web            # serves http://127.0.0.1:7331
```

A single-page dark UI streams each stage live over Server-Sent Events as the chain runs. Binds to `127.0.0.1` by default — bind elsewhere only deliberately.

```bash
snake-web --host 127.0.0.1 --port 7331
```

---

## Safe-by-default

Snake defaults to the least-intrusive posture that still produces an evidenced verdict:

- **INFERENCE is passive by default.** It confirms an inference route *exists and is reachable* without submitting a job. Only `--active` submits a probe — and that probe is minimal (`"hi"` for TTS, a 5-token cap for LLM) and the output is **not retained**. ASR is never sent real audio.
- **The web GUI binds to localhost**, not `0.0.0.0`.
- **Reports stay local.** Runs are written to `~/.snake/` (override with the `SNAKE_HOME` environment variable). Nothing is transmitted anywhere.

---

## Reports

Every run writes JSON to `$SNAKE_HOME/unified/<host>_<port>_<timestamp>.json` and updates `$SNAKE_HOME/last.json`. Each report records the stage results, the paths open without auth, the classified surfaces, the adjacent-service count, and whether the run was `active`.

```bash
SNAKE_HOME=./out snake 10.0.0.5 8880      # reports land in ./out
```

---

## Architecture

```
engine.py   pure chain + summary — never prints, returns StageResult objects
   │
   ├── cli.py    terminal rendering (stage evidence, open-path table, batch summary)
   └── web.py    FastAPI + SSE transport, embedded single-page UI
```

The engine holds no CLI or transport concerns; the findings roll-up is a pure function (`summarize`) that is unit-tested without a network. Front-ends decide only how results are presented.

---

## Development

```bash
pip install '.[dev]'
pytest          # offline suite — FakeSession, no real network, no writes to ~/.snake
ruff check .
```

The test suite mocks all HTTP with a routing `FakeSession` and redirects `SNAKE_HOME` to a temp dir. `tests/test_standalone.py` asserts byte-identity between `snake.py` and a fresh build — the standalone file cannot drift from the package.

---

## License

MIT © 2026 NuClide Research. See [LICENSE](LICENSE).
