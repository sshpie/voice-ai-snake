# 🐍 voice-ai-snake

A **12-stage verification chain** for exposed AI/ML and voice service infrastructure. Takes a target — from Shodan, Censys, aimap, or a scope list — and walks it layer by layer: *what service is running*, *what is reachable without authentication*, and *what does that exposure enable*.

```
ENDPOINT → SCHEMA → AUTH → ENUM → INVENTORY → DATA
  → INFERENCE → EXPLOIT-SURFACE → CHAIN → STORAGE → MONITORING → SUMMARY
```

Snake is a **verification tool**, not a discovery scanner. The load-bearing stage is turning a *candidate* into a *confirmed, evidenced finding*. Pair it with [aimap](https://github.com/zellkernel/aimap) for the full discovery-to-finding pipeline.

> **Authorized use only.** Run this only against infrastructure you own or are explicitly permitted to assess. With `--active`, it spends a target's compute. See [Safe-by-default](#safe-by-default).

---

## Three ways to run

### 1. Single target (explicit port)

```bash
snake 10.0.1.5 443
```

Classic mode — run the full 12-stage chain against one host:port.

### 2. No-port sweep (discover then chain)

```bash
snake 10.0.1.5
```

Sweeps the same 42 AI/ML ports that aimap covers (concurrent, 24 threads, 3s timeout per port). Every port that responds over HTTP gets the full chain. Use this when you have an IP but no port.

### 3. aimap pipeline (`--from-aimap`)

```bash
aimap -target 10.0.1.5 -o report.json
snake --from-aimap report.json
```

Reads an aimap JSON report, pulls fingerprint-confirmed services and open ports, maps aimap service names to snake `--service` hints (so auto-detection is skipped for confirmed services), and chains against all of them with a ranked summary at the end.

---

## Terminal output

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
  EXPLOIT-SURFACE    [OPEN]  1 surface: COMPUTE-THEFT
  CHAIN              [PASS]  3 adjacent: :80 404 nginx/1.24.0 | :8080 200 nginx/1.29.8 | :9000 200 uvicorn
  STORAGE            [FAIL]  no exposed storage found
  MONITORING         [PASS]  local /metrics — 701B
  SUMMARY            [OPEN]  10 path(s) open without auth · 1 exploit surface(s): COMPUTE-THEFT · 3 adjacent

  OPEN PATHS  (no auth required)
  /v1/chat/completions    LLM inference — send arbitrary prompts
  /v1/completions         LLM completions (legacy OpenAI-compat)
  /v1/audio/speech        TTS synthesis — generate audio
  /v1/audio/transcriptions  Audio → text transcription
  /v1/models              Model inventory — reveals loaded models
  /slots                  Inference slot state — active sessions side-channel
  /speakers               Speaker inventory — voice clone surface
  /actuator/env           Spring Boot actuator — env vars / potential creds
  /admin                  Admin panel
  /health                 Health / version info

  ◉ CHAIN COMPLETE
  12 stages  39.2s

  report → ~/.snake/unified/10.0.1.5_443_20260806T143827Z.json
```

---

### Hardened host — auth enforced

```
🐍 SNAKE  10.0.2.1:8000  generic  2026-08-06T09:12:04Z

  [ENDPOINT ✓] → [SCHEMA ✗] → [AUTH 🔒] → [ENUM ✗] → [INVENTORY ✗] → [DATA ✗]
     [INFERENCE ⚠] → [EXPLOIT-SURFACE ✗] → [CHAIN ✓] → [STORAGE ✗] → [MONITORING ✗] → [SUMMARY ✗]

  ENDPOINT           [PASS]  http 401  server:—  341B
  SCHEMA             [FAIL]  no schema or tech signal found
  AUTH               [GATED]  AUTH ENFORCED — /v1/models, /api/v1/jobs, /api/v1/targets, /metrics
  ENUM               [FAIL]  no enumerable endpoints returned data
  INVENTORY          [FAIL]  no inventory endpoint found
  DATA               [FAIL]  no data-layer exposure found
  INFERENCE          [OPEN]  inference route reachable — not invoked (pass --active to confirm):
                              /v1/audio/speech(401), /v1/chat/completions(401), /v1/completions(401)
  EXPLOIT-SURFACE    [FAIL]  no exploitable surface classified
  CHAIN              [PASS]  2 adjacent: :80 200 nginx/1.24.0 (Ubuntu) | :443 400 nginx/1.24.0 (Ubuntu)
  STORAGE            [FAIL]  no exposed storage found
  MONITORING         [FAIL]  no monitoring endpoint exposed
  SUMMARY            [FAIL]  no unauthenticated exposure found

  ◉ FRONTIER  snake stopped at SUMMARY
  12 stages  33.9s
```

`GATED` means auth is enforced — a finding, but not an exposure. `FRONTIER` means the chain ran to completion with no confirmed open surface. This is the correct-negative output for a hardened host.

---

### No-port sweep

```bash
snake 10.0.1.5
```

```
SWEEP  10.0.1.5  42 ports…
  3 live  :80(200)  :443(200)  :9000(200)

────────────────────────────────────────────────────────────────

🐍 SNAKE  10.0.1.5:443  generic  2026-08-06T14:38:27Z
  [AUTH ⚠] ...

────────────────────────────────────────────────────────────────

🐍 SNAKE  10.0.1.5:9000  whisper-modern  2026-08-06T14:39:01Z
  [AUTH 🔒] ...

────────────────────────────────────────────────────────────────

🐍 SNAKE  10.0.1.5:80  generic  2026-08-06T14:39:38Z
  [AUTH ✗] ...

════════════════════════════════════════════════════════════════
DISCOVER SUMMARY — 3 target(s)

  10.0.1.5:443    OPEN   10 open  COMPUTE-THEFT
  10.0.1.5:9000   —       0 open  no surface classified
  10.0.1.5:80     —       0 open  no surface classified
```

Hosts are ranked by surface count then open-path count — worst exposure always first.

---

### aimap pipeline

```bash
aimap -target 10.0.1.5 -o report.json
snake --from-aimap report.json
```

```
FROM-AIMAP  report.json  3 target(s)

────────────────────────────────────────────────────────────────
  aimap hint: 10.0.1.5:9000  whisper-asr → whisper-modern

🐍 SNAKE  10.0.1.5:9000  whisper-modern  2026-08-06T14:39:24Z

  [ENDPOINT ✓] → [SCHEMA ✓] → [AUTH ✗] → [ENUM ✗] → [INVENTORY ✗] → [DATA ✗]
     [INFERENCE ⚠] → [EXPLOIT-SURFACE ✗] → [CHAIN ✓] → [STORAGE ✗] → [MONITORING ✗] → [SUMMARY ✗]

  ENDPOINT           [PASS]  http 200  server:uvicorn  856B
  SCHEMA             [PASS]  /openapi.json → 2 paths  Whisper Asr Webservice v1.9.1
  AUTH               [FAIL]  auth state indeterminate
  INFERENCE          [OPEN]  inference route reachable — not invoked (pass --active to confirm): /asr(405)
  CHAIN              [PASS]  3 adjacent: :80 404 nginx/1.24.0 | :443 200 nginx/1.24.0 | :8080 200 nginx/1.29.8

  ◉ FRONTIER  snake stopped at SUMMARY
  12 stages  52.1s

────────────────────────────────────────────────────────────────
  aimap hint: 10.0.1.5:443  chatterbox → generic

🐍 SNAKE  10.0.1.5:443  generic  2026-08-06T14:40:17Z
  [AUTH ⚠] ...

════════════════════════════════════════════════════════════════
AIMAP SUMMARY — 3 target(s)

  10.0.1.5:443    OPEN   10 open  COMPUTE-THEFT
  10.0.1.5:9000   —       0 open  no surface classified
  10.0.1.5:8080   —       0 open  no surface classified
```

The `aimap hint:` line shows the service name aimap confirmed and the snake `--service` it maps to. For services aimap did not fingerprint, the mode is `auto`.

---

### Batch mode

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

════════════════════════════════════════════════════════════════
BATCH SUMMARY — 2 hosts

  10.0.1.5:8880   OPEN   10 open  COMPUTE-THEFT, VOICE-CLONE
  10.0.1.6:8880   —       0 open  no surface classified
```

`targets.txt` is a list of `host:port` lines; `#` comments are ignored.

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
  "open_paths": ["/v1/models", "/metrics", "/slots", "/speakers", "/asr"],
  "exploit_surfaces": ["COMPUTE-THEFT"],
  "adjacent_count": 3,
  "stages": [
    { "name": "ENDPOINT", "status": "PASS", "evidence": "https 200  server:nginx/1.24.0  701B" },
    { "name": "AUTH",     "status": "OPEN", "evidence": "NO AUTH — 10 paths open: /v1/models, ..." }
  ]
}
```

---

## aimap → snake workflow

[aimap](https://github.com/zellkernel/aimap) fingerprints AI/ML services across 36 platform types. Snake reads aimap's JSON output and carries the service identification forward so it doesn't re-detect what aimap already confirmed.

```
aimap                               snake
──────────────────────────────      ──────────────────────────────────────
Port sweep (42 ports)          →    Skip sweep (ports known)
AI service fingerprinting      →    --service hint (skip auto-detection)
open_ports[] + services[]      →    Verify each, chain 12 stages
                                    Ranked summary
```

### aimap service → snake `--service` mapping

| aimap fingerprint | snake `--service` |
|-------------------|-------------------|
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
| (unrecognized) | `auto` |

Open ports not matched to a service (`status_code == 200`, no fingerprint) are chained with `--service auto`.

---

## Stage reference

| Stage | What it checks |
|-------|----------------|
| **ENDPOINT** | Is the port live? HTTPS-first, HTTP fallback. Captures server banner and body size. |
| **SCHEMA** | OpenAPI/Swagger at `/openapi.json`, `/swagger.json`, etc. Falls back to tech fingerprint (FastAPI, Gradio, Prometheus, GraphQL). |
| **AUTH** | Probes a path set without credentials. Classifies each path as `OPEN` (200), `GATED` (401/403), or `REDIRECT` (3xx). Renders the OPEN PATHS table when auth is missing. |
| **ENUM** | Pulls service identity and model info from health/version/model endpoints. |
| **INVENTORY** | Lists voices, speakers, or models when the service type exposes them. |
| **DATA** | Prometheus hardware queries, job records, llama.cpp slot side-channel. |
| **INFERENCE** | Confirms inference route reachability. Passive by default — does not invoke compute. `--active` submits one minimal, non-retained probe. |
| **EXPLOIT-SURFACE** | Classifies confirmed open paths into named surface categories. |
| **CHAIN** | Sweeps co-located ports for adjacent services — exposures are usually worse than one port. |
| **STORAGE** | Job queues, MinIO health and banner. |
| **MONITORING** | `/metrics`, node-exporter, Prometheus scrape targets. |
| **SUMMARY** | Rolls up: open paths, classified surfaces, adjacent service count. No score — the finding is the exposure itself. |

Stages that do not apply to the detected service type emit `SKIP` and the chain continues.

---

## Status symbols

Shape + color. Never color alone (color-blind safe).

| Symbol | Status | Meaning |
|--------|--------|---------|
| `✓` | PASS | Stage succeeded |
| `✗` | FAIL | Nothing found / not reachable |
| `⚠` | OPEN | Reachable **without auth** — the finding signal |
| `🔒` | GATED | Reachable but auth-enforced |
| `—` | SKIP | Not applicable to this service type |
| `!` | ERROR | Probe errored |

---

## Exploit surfaces

The EXPLOIT-SURFACE stage classifies what an unauthenticated exposure enables. Surfaces marked ★ are **high-impact** — their unauthenticated presence alone drives `OPEN` in the SUMMARY verdict.

| Surface | Meaning |
|---------|---------|
| COMPUTE-THEFT ★ | Unauthenticated inference — free use of the target's GPU |
| VOICE-CLONE ★ | Voice / speaker cloning surface exposed without auth |
| BIOMETRIC-GDPR ★ | Speaker diarization / biometric data accessible |
| VPN-PIVOT ★ | Overlay-network details enabling lateral movement |
| LLM-ABUSE ★ | Open LLM endpoint for arbitrary generation |
| TOPOLOGY-LEAK | Infrastructure topology disclosed (Prometheus targets) |
| CONTENT-LEAK | Job / queue records exposing processed content |
| CONFIG-DISCLOSE | Version or config details disclosed |

---

## Open path significance

When AUTH is `OPEN`, snake renders an OPEN PATHS table. Each unprotected path is mapped to a plain-English description of what it enables. Unknown paths appear with `—`.

| Path | Significance |
|------|-------------|
| `/v1/chat/completions` | LLM inference — send arbitrary prompts |
| `/v1/completions` | LLM completions (legacy OpenAI-compat) |
| `/v1/audio/speech` | TTS synthesis — generate audio |
| `/v1/audio/transcriptions` | Audio → text transcription |
| `/v1/audio/voices` | Voice inventory |
| `/transcribe` | Transcription route |
| `/asr` | Speech recognition endpoint |
| `/v1/models` | Model inventory — reveals loaded models |
| `/slots` | Inference slot state — active sessions side-channel |
| `/speakers` | Speaker inventory — voice clone surface |
| `/actuator/env` | Spring Boot actuator — env vars / potential creds |
| `/admin` | Admin panel |
| `/config` | Config dump |
| `/metrics` | Metrics endpoint |
| `/health` | Health / version info |
| `/openapi.json` | API schema |
| `/api/v1/targets` | Prometheus scrape targets — topology leak |
| `/queue-metrics` | Job queue metrics |
| `/detect-language` | Language detection |

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

Requires Python ≥ 3.9. The only runtime dependency is `requests`. The web GUI adds `fastapi` + `uvicorn`.

### Zero-install (single file)

Grab the standalone [`snake.py`](snake.py) — the whole CLI in one file — and run it directly:

```bash
pip install requests
python snake.py 10.0.1.5 443
```

`snake.py` is generated from the package sources by `tools/build_standalone.py`. A test asserts byte-identity between the file and a fresh build — it cannot drift from the package. Do not edit it by hand.

---

## Usage reference

```bash
# single target — explicit port
snake 10.0.1.5 443

# no-port sweep — discover all 42 AI/ML ports, chain against live ones
snake 10.0.1.5

# aimap pipeline — read fingerprinted services from an aimap JSON report
snake --from-aimap report.json

# combined: aimap discovers and fingerprints, snake verifies
aimap -target 10.0.1.5 -o report.json && snake --from-aimap report.json

# force service type
snake 10.0.1.5 8880 --service kokoro

# active inference probe (submits one minimal payload)
snake 10.0.1.5 443 --active

# machine-readable output
snake 10.0.1.5 443 --json

# batch mode: host:port file, ranked summary at the end
snake --batch targets.txt

# print the last saved report
snake --report last

# disable color (also auto-disabled on non-TTY; respects NO_COLOR)
snake 10.0.1.5 443 --no-color

# module invocation
python -m snake_scanner 10.0.1.5 443
```

### Service types

```
kokoro · whisperx · cosyvoice · vllm · llamacpp · whisper-modern
subtitle · prometheus · lunary · generic · auto (default)
```

Auto-detection runs most-specific-first. Services that all expose `/metrics` are disambiguated by unique signals before the generic Prometheus check falls through to `generic`.

---

## Safe-by-default

- **INFERENCE is passive by default.** Confirms a route exists and is reachable — does not invoke it. `--active` submits one minimal, non-retained probe: `"hi"` for TTS, a 5-token cap for LLM. ASR is never sent real audio.
- **The web GUI binds to localhost.** `--host 0.0.0.0` only if you mean it.
- **Reports stay local.** Written to `~/.snake/` (override with `SNAKE_HOME`). Nothing is transmitted anywhere.

---

## Reports

Every run writes JSON to `$SNAKE_HOME/unified/<host>_<port>_<timestamp>.json` and updates `$SNAKE_HOME/last.json`. Each report captures stage results, open paths, classified surfaces, adjacent services, and whether the run was `active`.

```bash
SNAKE_HOME=./out snake 10.0.1.5 443    # reports land in ./out/
snake --report last                     # print the last run
```

---

## Architecture

```
engine.py     chain logic + sweep — never prints; returns StageResult objects
   │
   ├── cli.py    terminal rendering (stage evidence, OPEN PATHS table, ranked summary)
   └── web.py    FastAPI + SSE transport, embedded single-page UI
```

The engine holds no CLI or transport concerns. The `summarize` function is a pure function tested without a network. Front-ends only decide how results are presented.

---

## Development

```bash
pip install '.[dev]'
pytest          # offline suite — FakeSession, no real network, no writes to ~/.snake
ruff check .
python tools/build_standalone.py    # rebuild snake.py after engine/cli changes
```

The test suite mocks all HTTP with a routing `FakeSession` and redirects `SNAKE_HOME` to a temp dir. `tests/test_standalone.py` asserts byte-identity between `snake.py` and a fresh build.

---

## License

MIT © 2026 . See [LICENSE](LICENSE).
