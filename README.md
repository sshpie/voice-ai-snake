# 🐍 Voice AI verification snake

A **12-stage verification chain** for exposed AI/ML service infrastructure. Point it at a host:port and it tells you, layer by layer, *what service is running* and *what is reachable without authentication*.

Snake is a **verification** tool, not a discovery scanner. It does not sweep the internet for targets — it takes a target you already have (from Shodan, Censys, an asset inventory, or a scope list) and drives the chain from a live endpoint to an evidenced summary of what's exposed. The load-bearing stage is not the scan; it is turning a *candidate* into a *confirmed, evidenced finding*.

```
ENDPOINT → SCHEMA → AUTH → ENUM → INVENTORY → DATA
  → INFERENCE → EXPLOIT-SURFACE → CHAIN → STORAGE → MONITORING → SUMMARY
```

> **Authorized use only.** Run this only against infrastructure you own or are explicitly permitted to assess. It probes real services and, with `--active`, spends a target's compute. See [Safe-by-default](#safe-by-default).

---

## What it does

| Stage | What it checks |
|-------|----------------|
| **ENDPOINT** | Is the port live? HTTPS-first, HTTP fallback; captures server banner + body size. |
| **SCHEMA** | OpenAPI/Swagger schema (`/openapi.json`, `/swagger.json`, …); falls back to a tech fingerprint (FastAPI, Gradio, Prometheus, GraphQL). |
| **AUTH** | Probes a path set and classifies each as **OPEN** (200, no auth), **GATED** (401/403), or partial — the core "what's open" signal. |
| **ENUM** | Pulls service identity + model info from health/version/model endpoints. |
| **INVENTORY** | Lists voices / speakers / models when the service type exposes them. |
| **DATA** | Metrics (Prometheus hardware queries), job records, llama.cpp slot side-channel. |
| **INFERENCE** | Confirms the inference route. **Passive** by default (reachability only); **active** (`--active`) submits one minimal, non-retained probe to prove synthesis/completion. |
| **EXPLOIT-SURFACE** | Classifies findings into named surfaces (COMPUTE-THEFT, VOICE-CLONE, BIOMETRIC-GDPR, TOPOLOGY-LEAK, VPN-PIVOT, CONTENT-LEAK, CONFIG-DISCLOSE, LLM-ABUSE). |
| **CHAIN** | Sweeps co-located ports for adjacent services (the exposure is usually worse than one port). |
| **STORAGE** | Job queues and exposed object storage (MinIO health/banner). |
| **MONITORING** | Exposed `/metrics`, node-exporter, and Prometheus targets. |
| **SUMMARY** | Rolls up the findings: which paths answered without auth, which surfaces were classified, how many adjacent services turned up. No score — the finding is the exposure itself. |

Stages that don't apply to the detected service type emit **SKIP** and the chain continues — a null result is a *logged* result, never a silent gap.

### Service auto-detection

Auto-detection runs most-specific-first (services that all expose `/metrics` are disambiguated by unique signals before the generic Prometheus check). Force a type with `--service` to skip detection.

```
kokoro · whisperx · cosyvoice · vllm · llamacpp · whisper-modern · subtitle · prometheus · lunary · generic
```

### Exploit surfaces

The `EXPLOIT-SURFACE` stage classifies what an unauthenticated exposure enables. Surfaces marked ★ are **high-impact** — their mere unauthenticated presence is treated as a live exposure (and drives the `OPEN` verdict in `SUMMARY`); the rest are informational.

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
# auto-detect and run the full chain (passive)
snake 10.0.0.5 8880

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

Status is **shape + color**, never color alone (color-blind safe):
`✓ PASS` · `✗ FAIL` · `⚠ OPEN` · `🔒 GATED` · `— SKIP` · `! ERROR`.
Honors `NO_COLOR` and non-TTY output automatically; force with `--no-color`.

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

Three layers, cleanly separated:

```
engine.py   pure chain + summary — never prints, returns StageResult objects
   │
   ├── cli.py    terminal rendering, batch, argument parsing
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

The test suite mocks all HTTP with a routing `FakeSession` and redirects `SNAKE_HOME` to a temp dir, so it never touches the network or your real report directory.

---

## License

MIT © 2026 NuClide Research. See [LICENSE](LICENSE).
