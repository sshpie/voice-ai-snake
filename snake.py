#!/usr/bin/env python3
"""Voice AI verification snake — standalone single-file build.

Zero-install: `python snake.py <host> <port> [--service NAME] [--active] [--json]`.
Requires only `requests`  (pip install requests).

GENERATED from src/snake_scanner/engine.py + cli.py by tools/build_standalone.py.
Do NOT edit by hand — edit the package and run `python tools/build_standalone.py`.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import json as _json
import os
import re
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ── ANSI palette ( dark: cyan structure, magenta critical) ──────────────
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GREY = "\033[90m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def c(col: str, txt: str) -> str:
    """Wrap `txt` in an ANSI colour code."""
    return f"{col}{txt}{RESET}"


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes — the single choke point for `--no-color`."""
    return _ANSI_RE.sub("", text)


# ── status vocabulary ──────────────────────────────────────────────────────────
PASS = "PASS"    # stage succeeded
FAIL = "FAIL"    # nothing found / not reachable
OPEN = "OPEN"    # reachable WITHOUT auth (the finding signal)
GATED = "GATED"  # reachable but auth-enforced
SKIP = "SKIP"    # not applicable to this service type
ERROR = "ERROR"  # probe errored

# Status is shape + colour, never colour alone (colour-blind safe).
_SYMBOL = {PASS: "✓", FAIL: "✗", OPEN: "⚠", GATED: "\U0001f512", SKIP: "—", ERROR: "!"}
_COLOR = {PASS: GREEN, FAIL: GREY, OPEN: YELLOW, GATED: CYAN, SKIP: GREY, ERROR: RED}


@dataclass
class StageResult:
    """The outcome of one stage in the chain."""

    name: str
    status: str
    evidence: str
    detail: dict = field(default_factory=dict)
    raw: Any = None

    def passed(self) -> bool:
        return self.status in (PASS, OPEN, GATED)

    def symbol(self) -> str:
        return _SYMBOL[self.status]

    def color(self) -> str:
        return _COLOR[self.status]

    def as_dict(self, with_detail: bool = True) -> dict:
        out = {"name": self.name, "status": self.status, "evidence": self.evidence}
        if with_detail:
            out["detail"] = self.detail
        return out


# ── HTTP helpers ────────────────────────────────────────────────────────────────
DEFAULT_TIMEOUT = 8


def make_session() -> requests.Session:
    """A TLS-lenient session (self-signed certs are the norm on exposed infra)."""
    s = requests.Session()
    s.verify = False
    return s


def get(session: requests.Session, url: str, **kw) -> requests.Response | None:
    """GET that returns None on any network error instead of raising."""
    kw.setdefault("timeout", DEFAULT_TIMEOUT)
    try:
        return session.get(url, **kw)
    except requests.RequestException:
        return None


def post(session: requests.Session, url: str, **kw) -> requests.Response | None:
    """POST that returns None on any network error instead of raising."""
    kw.setdefault("timeout", DEFAULT_TIMEOUT)
    try:
        return session.post(url, **kw)
    except requests.RequestException:
        return None


# ── service-type sets — which stages are relevant per service class ─────────────
VOICE_SERVICES = {"kokoro", "whisperx", "cosyvoice", "whisper-modern", "subtitle", "generic"}
INFRA_SERVICES = {"prometheus", "lunary", "generic"}
LLM_SERVICES = {"vllm", "llamacpp", "generic"}
ALL_SERVICES = VOICE_SERVICES | INFRA_SERVICES | LLM_SERVICES

SERVICE_CHOICES = [
    "auto", "kokoro", "whisperx", "cosyvoice", "vllm", "llamacpp",
    "whisper-modern", "subtitle", "prometheus", "lunary", "generic",
]


def _is_pure_infra(service: str) -> bool:
    """True for service types where voice/inference stages do not apply."""
    return service in INFRA_SERVICES and service not in VOICE_SERVICES and service not in LLM_SERVICES


# ── stage 1: endpoint ───────────────────────────────────────────────────────────
def s_endpoint(session, host, port, ctx) -> StageResult:
    for scheme in ("https", "http"):
        r = get(session, f"{scheme}://{host}:{port}/", timeout=6)
        if r is not None:
            ctx.update({"scheme": scheme, "base": f"{scheme}://{host}:{port}"})
            return StageResult(
                "ENDPOINT", PASS,
                f"{scheme} {r.status_code}  server:{r.headers.get('server', '—')}  {len(r.content)}B",
                detail={
                    "scheme": scheme,
                    "status": r.status_code,
                    "server": r.headers.get("server", "—"),
                    "content_type": r.headers.get("content-type", "—"),
                },
                raw=r.text[:300],
            )
    return StageResult("ENDPOINT", FAIL, "connection refused / timeout")


# ── stage 2: schema ─────────────────────────────────────────────────────────────
def s_schema(session, host, port, ctx) -> StageResult:
    base = ctx["base"]
    for path in ["/openapi.json", "/swagger.json", "/api-docs",
                 "/v1/openapi.json", "/api/v1/openapi.json"]:
        r = get(session, base + path, timeout=5)
        if r and r.status_code == 200:
            try:
                data = r.json()
                n = len(data.get("paths", {}))
                title = (data.get("info") or {}).get("title", "?")
                ver = (data.get("info") or {}).get("version", "?")
                ctx["schema"] = data
                return StageResult(
                    "SCHEMA", PASS,
                    f"{path} → {n} paths  {title} v{ver}",
                    detail={"path": path, "title": title, "version": ver,
                            "n_paths": n, "paths": list(data.get("paths", {}).keys())[:20]},
                )
            except (ValueError, AttributeError):
                return StageResult("SCHEMA", PASS, f"{path} → 200 non-JSON", raw=r.text[:200])
    # tech fingerprint fallback
    r = get(session, base + "/", timeout=4)
    if r:
        text = r.text[:600].lower()
        for sig, tech in [("prometheus", "prometheus"), ("gradio", "gradio"),
                          ("fastapi", "fastapi"), ("swagger", "swagger"),
                          ("graphql", "graphql")]:
            if sig in text:
                ctx["tech"] = tech
                return StageResult("SCHEMA", PASS,
                                   f"no schema endpoint — tech fingerprint: {tech}",
                                   detail={"tech": tech})
    return StageResult("SCHEMA", FAIL, "no schema or tech signal found")


# ── stage 3: auth ───────────────────────────────────────────────────────────────
def s_auth(session, host, port, ctx) -> StageResult:
    base = ctx["base"]
    schema = ctx.get("schema", {})
    probe = list(schema.get("paths", {}).keys())[:8]
    probe += ["/v1/models", "/api/v1/jobs", "/api/v1/targets", "/metrics",
              "/slots", "/speakers", "/asr", "/admin", "/config", "/actuator/env",
              "/v1/audio/voices", "/health"]
    # de-dupe (schema paths can repeat the fixed list) while preserving order, so a
    # path is probed once and the open-path count reflects distinct paths.
    seen: set[str] = set()
    probe = [p for p in probe if not (p in seen or seen.add(p))]
    open_p: list[str] = []
    gated_p: list[str] = []
    for p in probe[:14]:
        r = get(session, base + p, timeout=4, allow_redirects=False)
        if r is None:
            continue
        if r.status_code == 200:
            open_p.append(p)
        elif r.status_code in (301, 302, 307, 308, 401, 403):
            gated_p.append(p)
    ctx.update({"open_paths": open_p, "gated_paths": gated_p})
    detail = {"open": open_p, "gated": gated_p}
    if open_p and not gated_p:
        return StageResult("AUTH", OPEN,
                           f"NO AUTH — {len(open_p)} paths open: {', '.join(open_p[:4])}", detail=detail)
    if gated_p and not open_p:
        return StageResult("AUTH", GATED, f"AUTH ENFORCED — {', '.join(gated_p[:4])}", detail=detail)
    if open_p and gated_p:
        return StageResult("AUTH", OPEN, f"PARTIAL — {len(open_p)} open / {len(gated_p)} gated", detail=detail)
    return StageResult("AUTH", FAIL, "auth state indeterminate")


# ── stage 4: enum (service identity + model info) ───────────────────────────────
def _parse_models(r):
    try:
        items = r.json().get("data", [])
        if items:
            return [m.get("id", "?") for m in items[:4]]
    except (ValueError, AttributeError):
        pass
    return None


def _jv(r, fields):
    try:
        data = r.json()
        out = {f: data[f] for f in fields if f in data and isinstance(data[f], (str, int, float, bool))}
        return out or None
    except (ValueError, AttributeError):
        return None


def _parse_prom_targets(r):
    try:
        active = r.json().get("data", {}).get("activeTargets", [])
        return {"n_targets": len(active),
                "jobs": list({t.get("labels", {}).get("job", "?") for t in active})}
    except (ValueError, AttributeError):
        return None


def _list_items(r, keys):
    try:
        data = r.json()
        for k in keys:
            if k in data and isinstance(data[k], list):
                return {"count": len(data[k]), "sample": data[k][:4]}
    except (ValueError, AttributeError):
        pass
    return None


def _parse_voices(r):
    try:
        data = r.json()
        items = data if isinstance(data, list) else data.get("voices", [])
        names = [i.get("id", i) if isinstance(i, dict) else i for i in items[:8]]
        return {"count": len(items), "sample": names}
    except (ValueError, AttributeError):
        return None


def _parse_jobs(r):
    try:
        body = r.json()
        items = body if isinstance(body, list) else body.get("jobs", [])
        return {"count": len(items)}
    except (ValueError, AttributeError):
        return None


def s_enum(session, host, port, ctx) -> StageResult:
    base = ctx["base"]
    findings: dict[str, Any] = {}
    probes = {
        "/v1/models": ("llm_models", _parse_models),
        "/model_info": ("model_info", lambda r: _jv(r, ["model_name", "version", "model"])),
        "/health": ("health", lambda r: _jv(r, ["version", "service", "model", "status", "stack"])),
        "/api/v1/health": ("health", lambda r: _jv(r, ["version", "deployment_mode", "auth_provider"])),
        "/": ("root", lambda r: _jv(r, ["version", "service", "model", "stack"])),
        "/props": ("llamacpp", lambda r: _jv(r, ["total_slots", "n_ctx", "model_alias"])),
        "/api/v1/targets": ("prometheus", _parse_prom_targets),
        "/speakers": ("speakers", lambda r: _list_items(r, ["speakers"])),
        "/v1/audio/voices": ("voices", _parse_voices),
        "/api/v1/jobs": ("jobs", _parse_jobs),
        "/version": ("version", lambda r: _jv(r, ["version"])),
    }
    for path, (key, fn) in probes.items():
        r = get(session, base + path, timeout=5)
        if r and r.status_code == 200:
            val = fn(r)
            if val:
                findings[key] = val
    ctx["enum"] = findings
    if findings:
        summary = " | ".join(f"{k}:{str(v)[:50]}" for k, v in list(findings.items())[:4])
        return StageResult("ENUM", PASS, summary, detail=findings)
    return StageResult("ENUM", FAIL, "no enumerable endpoints returned data")


# ── stage 5: inventory (voice/speaker/model list) ───────────────────────────────
def _iname(i):
    if isinstance(i, str):
        return i
    if isinstance(i, dict):
        return i.get("id") or i.get("name") or i.get("voice_id") or str(i)[:24]
    return str(i)[:24]


def s_inventory(session, host, port, ctx) -> StageResult:
    if _is_pure_infra(ctx.get("service", "auto")):
        return StageResult("INVENTORY", SKIP, "not applicable for infra service type")
    base = ctx["base"]
    probes = [("/v1/audio/voices", "voices"), ("/speakers", "speakers"),
              ("/v1/models", "models"), ("/api/v1/models", "models")]
    for path, key in probes:
        r = get(session, base + path, timeout=5)
        if r and r.status_code == 200:
            try:
                data = r.json()
                items = data if isinstance(data, list) else data.get(key, data.get("data", []))
                if isinstance(items, list) and items:
                    names = [_iname(i) for i in items[:6]]
                    ctx["inventory"] = items
                    return StageResult(
                        "INVENTORY", PASS,
                        f"{path} → {len(items)} {key}: {', '.join(names)}",
                        detail={"path": path, "count": len(items), "type": key, "sample": items[:6]},
                    )
            except (ValueError, AttributeError):
                pass
    return StageResult("INVENTORY", FAIL, "no inventory endpoint found")


# ── stage 6: data (metrics, job records, slots side-channel) ────────────────────
def s_data(session, host, port, ctx) -> StageResult:
    base = ctx["base"]
    findings: list[str] = []

    # Prometheus hardware queries
    for label, query, fmt in [
        ("memory", "node_memory_MemTotal_bytes", lambda v: f"{float(v) / 1e9:.1f} GB RAM"),
        ("cpu", 'count(node_cpu_seconds_total{mode="idle"})', lambda v: f"{int(float(v))} CPU"),
        ("disk", 'node_filesystem_size_bytes{mountpoint="/"}', lambda v: f"{float(v) / 1e9:.0f} GB disk"),
        ("network", "node_network_info", lambda v: "network interfaces"),
    ]:
        r = get(session, base + f"/api/v1/query?query={query}", timeout=5)
        if r and r.status_code == 200:
            try:
                result = r.json().get("data", {}).get("result", [])
                if result:
                    val = result[0].get("value", [None, None])[1]
                    if val:
                        findings.append(f"{label}: {fmt(val)}")
            except (ValueError, AttributeError, IndexError, TypeError):
                pass

    # job records
    r = get(session, base + "/api/v1/jobs", timeout=5)
    if r and r.status_code == 200:
        try:
            body = r.json()
            items = body if isinstance(body, list) else body.get("jobs", [])
            findings.append(f"jobs: {len(items)} records")
            ctx["jobs_raw"] = items[:3]
        except (ValueError, AttributeError):
            pass

    # llama.cpp slots side-channel
    r = get(session, base + "/slots", timeout=5)
    if r and r.status_code == 200:
        try:
            slots = r.json()
            if isinstance(slots, list):
                findings.append(f"slots: {len(slots)} inference slots (side-channel)")
        except (ValueError, AttributeError):
            pass

    ctx["data_findings"] = findings
    if findings:
        return StageResult("DATA", PASS, " | ".join(findings[:5]), detail={"findings": findings})
    return StageResult("DATA", FAIL, "no data-layer exposure found")


# ── stage 7: inference ──────────────────────────────────────────────────────────
# Passive (default): confirm the inference route is reachable without submitting a
# job. Active (--active): submit a minimal, non-retained probe to prove the
# endpoint actually serves inference. Active spends the target's compute, so it is
# opt-in.
_INFERENCE_ROUTES = ["/v1/audio/speech", "/v1/chat/completions", "/v1/completions",
                     "/asr", "/v1/audio/transcriptions", "/transcribe"]


def _inference_passive(session, base, ctx) -> StageResult:
    reachable = []
    for path in _INFERENCE_ROUTES:
        # A GET/OPTIONS to a POST-only route returns 405/200/400/422 if the route
        # exists; it does not run inference.
        r = get(session, base + path, timeout=4)
        if r is not None and r.status_code in (200, 400, 401, 403, 405, 422):
            reachable.append(f"{path}({r.status_code})")
    if reachable:
        return StageResult(
            "INFERENCE", OPEN,
            f"inference route reachable — not invoked (pass --active to confirm): {', '.join(reachable[:3])}",
            detail={"mode": "passive", "reachable": reachable},
        )
    return StageResult("INFERENCE", FAIL, "no inference route reachable")


def _inference_active(session, base, ctx) -> StageResult:
    # TTS probe (minimal input, audio not retained)
    voices = ctx.get("inventory", [])
    voice_id = _iname(voices[0]) if voices else "af_bella"
    r = post(session, base + "/v1/audio/speech",
             json={"model": "kokoro", "input": "hi", "voice": voice_id, "response_format": "mp3"},
             timeout=15)
    if r and r.status_code == 200 and len(r.content) > 100:
        return StageResult(
            "INFERENCE", PASS,
            f"TTS synthesis confirmed — {len(r.content)}B audio (not retained)",
            detail={"mode": "active", "type": "tts", "voice": voice_id, "bytes": len(r.content)},
        )

    # LLM inference (5-token cap)
    models = ctx.get("enum", {}).get("llm_models", [])
    model_id = models[0] if models else None
    if model_id:
        r = post(session, base + "/v1/chat/completions",
                 json={"model": model_id, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 5},
                 headers={"Content-Type": "application/json"}, timeout=20)
        if r and r.status_code == 200:
            try:
                data = r.json()
                content = data["choices"][0]["message"]["content"]
                tokens = data.get("usage", {}).get("completion_tokens", "?")
                return StageResult(
                    "INFERENCE", PASS,
                    f"LLM inference confirmed — {tokens} tokens — '{content[:40]}'",
                    detail={"mode": "active", "type": "llm", "model": model_id,
                            "tokens": tokens, "response": content[:40]},
                )
            except (ValueError, KeyError, IndexError, TypeError):
                pass

    # ASR probe — schema-only, no audio submitted
    for path in ["/asr", "/v1/audio/transcriptions", "/transcribe"]:
        r = post(session, base + path, data={}, timeout=5)
        if r and r.status_code in (200, 400, 422):
            status = PASS if r.status_code == 200 else OPEN
            return StageResult(
                "INFERENCE", status,
                f"ASR endpoint reachable at {path} — {r.status_code} (no audio submitted per restraint)",
                detail={"mode": "active", "type": "asr", "path": path, "status": r.status_code},
            )

    return StageResult("INFERENCE", FAIL, "no inference endpoint responded")


def s_inference(session, host, port, ctx) -> StageResult:
    if _is_pure_infra(ctx.get("service", "auto")):
        return StageResult("INFERENCE", SKIP, "not applicable for infra service type")
    base = ctx["base"]
    if ctx.get("active"):
        return _inference_active(session, base, ctx)
    return _inference_passive(session, base, ctx)


# ── stage 8: exploit-surface classifier ─────────────────────────────────────────
# Surfaces whose mere presence (unauthenticated) is treated as a live exposure
# rather than an informational signal.
HIGH_IMPACT_SURFACES = {"COMPUTE-THEFT", "VOICE-CLONE", "BIOMETRIC-GDPR", "VPN-PIVOT", "LLM-ABUSE"}


def s_exploit_surface(session, host, port, ctx) -> StageResult:
    base = ctx["base"]
    open_p = ctx.get("open_paths", [])
    enum = ctx.get("enum", {})
    surfaces: list[str] = []

    if any(p in open_p for p in ["/v1/models", "/v1/audio/speech", "/asr", "/v1/chat/completions"]):
        surfaces.append("COMPUTE-THEFT")
    if "speakers" in enum or "voices" in enum:
        r = get(session, base + "/speakers", timeout=4)
        if r and r.status_code == 200:
            surfaces.append("VOICE-CLONE")
    if "llm_models" in enum:
        surfaces.append("LLM-ABUSE")
    r = get(session, base + "/openapi.json", timeout=5)
    if r and r.status_code == 200:
        body = r.text.lower()
        if "diarize" in body or "pyannote" in body:
            surfaces.append("BIOMETRIC-GDPR")
    if "prometheus" in enum or any("/api/v1/targets" in p for p in open_p):
        surfaces.append("TOPOLOGY-LEAK")
    r = get(session, base + "/api/v1/query?query=node_network_info", timeout=5)
    if r and r.status_code == 200 and "tailscale" in r.text.lower():
        surfaces.append("VPN-PIVOT")
    if "jobs" in enum:
        surfaces.append("CONTENT-LEAK")
    health = enum.get("health", {})
    if isinstance(health, dict) and "version" in health:
        surfaces.append("CONFIG-DISCLOSE")

    ctx["exploit_surfaces"] = surfaces
    if surfaces:
        status = OPEN if any(s in HIGH_IMPACT_SURFACES for s in surfaces) else PASS
        return StageResult("EXPLOIT-SURFACE", status,
                           f"{len(surfaces)} surfaces: " + " | ".join(surfaces[:4]),
                           detail={"surfaces": surfaces, "count": len(surfaces)})
    return StageResult("EXPLOIT-SURFACE", FAIL, "no exploitable surface classified")


# ── stage 9: chain (adjacent port sweep) ────────────────────────────────────────
ADJACENT_PORTS = [80, 443, 3000, 6379, 8000, 8001, 8080, 8443, 8880,
                  9000, 9001, 9090, 9100, 9200, 11434, 50000]


def s_chain(session, host, port, ctx) -> StageResult:
    found = []
    for p in ADJACENT_PORTS:
        if p == port:
            continue
        r = get(session, f"http://{host}:{p}/", timeout=2)
        if r is not None:
            found.append({"port": p, "status": r.status_code,
                          "server": r.headers.get("server", "?"), "bytes": len(r.content)})
    ctx["adjacent"] = found
    if found:
        summary = " | ".join(f":{f['port']} {f['status']} {f['server']}" for f in found[:5])
        return StageResult("CHAIN", PASS, f"{len(found)} adjacent: {summary}", detail={"adjacent": found})
    return StageResult("CHAIN", FAIL, "no adjacent services found")


# ── stage 10: storage (job queues, MinIO) ───────────────────────────────────────
def s_storage(session, host, port, ctx) -> StageResult:
    base = ctx["base"]
    findings: list[str] = []
    for path in ["/api/v1/jobs", "/jobs", "/queue"]:
        r = get(session, base + path, timeout=5)
        if r and r.status_code == 200:
            try:
                body = r.json()
                items = body if isinstance(body, list) else body.get("jobs", [])
                if isinstance(items, list):
                    findings.append(f"job queue: {len(items)} records at {path}")
                    ctx["job_queue"] = items
            except (ValueError, AttributeError):
                pass
    for mp in [9000, 9001]:
        r = get(session, f"http://{host}:{mp}/minio/health/live", timeout=3)
        if r and r.status_code == 200:
            findings.append(f"MinIO live :{mp}")
        else:
            r2 = get(session, f"http://{host}:{mp}/", timeout=3)
            if r2 and "minio" in (r2.headers.get("server", "") + r2.text[:100]).lower():
                findings.append(f"MinIO :{mp}")
    if findings:
        return StageResult("STORAGE", PASS, " | ".join(findings), detail={"findings": findings})
    return StageResult("STORAGE", FAIL, "no exposed storage found")


# ── stage 11: monitoring ─────────────────────────────────────────────────────────
def s_monitoring(session, host, port, ctx) -> StageResult:
    base = ctx["base"]
    probes = [
        (base + "/metrics", "local /metrics"),
        (base + "/queue-metrics", "queue-metrics"),
        (f"http://{host}:9090/api/v1/targets", "Prometheus :9090"),
        (f"http://{host}:9090/metrics", "Prometheus self :9090"),
        (f"http://{host}:9100/metrics", "node-exporter :9100"),
    ]
    for url, label in probes:
        r = get(session, url, timeout=4)
        if r and r.status_code == 200:
            ctx["monitoring_url"] = url
            return StageResult("MONITORING", PASS,
                               f"{label} — {len(r.content)}B: {r.text[:60].replace(chr(10), ' ')}",
                               detail={"url": url, "label": label, "bytes": len(r.content)})
    return StageResult("MONITORING", FAIL, "no monitoring endpoint exposed")


# ── stage 12: summary ─────────────────────────────────────────────────────────
# Final roll-up of what the chain found: which paths answered without auth, which
# exploit surfaces were classified, and how many co-located services turned up.
# No score, no severity tier — the finding is the exposure itself.
def summarize(surfaces: list[str], open_paths: list[str], adjacent_count: int) -> dict:
    """Pure roll-up of the chain's findings — testable without a network."""
    return {
        "open_paths": list(open_paths),
        "surfaces": list(surfaces),
        "high_impact": [s for s in surfaces if s in HIGH_IMPACT_SURFACES],
        "adjacent_count": adjacent_count,
    }


def s_summary(session, host, port, ctx) -> StageResult:
    surfaces = ctx.get("exploit_surfaces", [])
    open_paths = ctx.get("open_paths", [])
    adjacent = ctx.get("adjacent", [])
    summary = summarize(surfaces, open_paths, len(adjacent))
    ctx["summary"] = summary

    if not open_paths and not surfaces:
        return StageResult("SUMMARY", FAIL, "no unauthenticated exposure found", detail=summary)

    bits: list[str] = []
    if open_paths:
        bits.append(f"{len(open_paths)} path(s) open without auth")
    if surfaces:
        bits.append(f"{len(surfaces)} exploit surface(s): {', '.join(surfaces)}")
    if adjacent:
        bits.append(f"{len(adjacent)} adjacent service(s)")
    status = OPEN if (open_paths or summary["high_impact"]) else PASS
    return StageResult("SUMMARY", status, " · ".join(bits), detail=summary)


# ── full chain ────────────────────────────────────────────────────────────────
Stage = Callable[[requests.Session, str, int, dict], StageResult]

CHAIN: list[tuple[str, Stage]] = [
    ("ENDPOINT", s_endpoint),
    ("SCHEMA", s_schema),
    ("AUTH", s_auth),
    ("ENUM", s_enum),
    ("INVENTORY", s_inventory),
    ("DATA", s_data),
    ("INFERENCE", s_inference),
    ("EXPLOIT-SURFACE", s_exploit_surface),
    ("CHAIN", s_chain),
    ("STORAGE", s_storage),
    ("MONITORING", s_monitoring),
    ("SUMMARY", s_summary),
]

STAGE_NAMES = [name for name, _ in CHAIN]


# ── auto-detect ──────────────────────────────────────────────────────────────────
# Order matters — more specific signatures before generic ones. vllm/llamacpp/
# kokoro/whisperx must precede prometheus (all expose /metrics).
DETECT_CHECKS = [
    ("kokoro", [("/v1/audio/voices", "af_"), ("/openapi.json", "Kokoro")]),
    ("whisperx", [("/", "WhisperX"), ("/queue-metrics", "serve_mode")]),
    ("cosyvoice", [("/speakers", "中文"), ("/model_info", "CosyVoice"), ("/", "gradio")]),
    ("subtitle", [("/api/v1/jobs", "job"), ("/api/v1/models", "whisperx")]),
    ("whisper-modern", [("/", "Modern Whisper"), ("/openapi.json", "diarize")]),
    ("lunary", [("/api/v1/health", "lunary"), ("/api/v1/health", "deployment_mode")]),
    ("vllm", [("/version", "vllm"), ("/v1/models", "vllm"), ("/openapi.json", "vllm")]),
    ("llamacpp", [("/slots", "id"), ("/props", "total_slots"),
                  ("/v1/models", "llama"), ("/openapi.json", "llama")]),
    ("prometheus", [("/api/v1/targets", "activeTargets"), ("/api/v1/status/config", "prometheus")]),
]


def detect(session, host, port, ctx) -> str:
    base = ctx.get("base", f"http://{host}:{port}")
    for svc, signals in DETECT_CHECKS:
        for path, kw in signals:
            r = get(session, base + path, timeout=4)
            if r and r.status_code == 200 and kw.lower() in r.text.lower():
                return svc
    return "generic"


# ── report persistence ───────────────────────────────────────────────────────────
def snake_home() -> str:
    """Report root. Override with SNAKE_HOME; defaults to ~/.snake."""
    return os.environ.get("SNAKE_HOME", os.path.expanduser("~/.snake"))


def report_dir() -> str:
    return os.path.join(snake_home(), "unified")


def build_report(host, port, service, results, elapsed, ctx) -> dict:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return {
        "host": host, "port": port, "service": service, "timestamp": ts,
        "elapsed_s": round(elapsed, 2),
        "active": bool(ctx.get("active")),
        "open_paths": ctx.get("open_paths", []),
        "exploit_surfaces": ctx.get("exploit_surfaces", []),
        "adjacent_count": len(ctx.get("adjacent", [])),
        "stages": [r.as_dict() for r in results],
    }


def save(host, port, service, results, elapsed, ctx) -> str:
    """Write the per-run report plus last.json. Returns the per-run path."""
    rdir = report_dir()
    os.makedirs(rdir, exist_ok=True)
    out = build_report(host, port, service, results, elapsed, ctx)
    fname = os.path.join(rdir, f"{host}_{port}_{out['timestamp']}.json")
    for path in (fname, os.path.join(snake_home(), "last.json")):
        with open(path, "w") as f:
            json.dump(out, f, indent=2)
    return fname


# ── port discovery sweep ──────────────────────────────────────────────────────
# Same default port set as aimap — keeps the two tools in sync so a no-arg
# snake call covers the same surface as an aimap scan.
AI_PORTS = [
    80, 443, 1984, 2379, 3000, 3001, 4000, 4040, 4200, 5000, 5001, 5678,
    6333, 7575, 7576, 7860, 8000, 8001, 8080, 8081, 8088, 8123, 8233, 8265,
    8443, 8501, 8787, 8888, 8889, 9000, 9090, 9091, 9200, 10000, 11434,
    15500, 18080, 18789, 19530, 30000, 51000, 55000,
]


def _probe_port(host: str, port: int, timeout: float) -> dict | None:
    """Try HTTPS then HTTP; return a port record on any HTTP response, else None."""
    s = make_session()
    for scheme in ("https", "http"):
        r = get(s, f"{scheme}://{host}:{port}/", timeout=timeout)
        if r is not None:
            return {
                "port": port,
                "scheme": scheme,
                "status": r.status_code,
                "server": r.headers.get("server", "—"),
            }
    return None


def sweep(host: str, ports: list[int] | None = None,
          timeout: float = 3.0, threads: int = 24) -> list[dict]:
    """Concurrent HTTP sweep over AI/ML ports; return live port records sorted by port."""
    if ports is None:
        ports = AI_PORTS
    live: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_probe_port, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            rec = fut.result()
            if rec is not None:
                live.append(rec)
    return sorted(live, key=lambda r: r["port"])


# ── runner ────────────────────────────────────────────────────────────────────
def run(host, port, service: str = "auto", active: bool = False):
    """Run the whole chain; return (results, elapsed, service, ctx)."""
    session = make_session()
    ctx: dict = {"active": active}
    results: list[StageResult] = []
    t0 = time.time()

    r = s_endpoint(session, host, port, ctx)
    results.append(r)
    if not r.passed():
        return results, time.time() - t0, service, ctx

    if service == "auto":
        service = detect(session, host, port, ctx)
    ctx["service"] = service

    for _, fn in CHAIN[1:]:
        results.append(fn(session, host, port, ctx))
    return results, time.time() - t0, service, ctx


def run_stream(host, port, service: str = "auto", active: bool = False) -> Iterator:
    """Generator: yield (StageResult, service, ctx) as each stage completes.

    Emits a single (None, service, ctx) sentinel once the service is detected.
    """
    session = make_session()
    ctx: dict = {"active": active}

    r = s_endpoint(session, host, port, ctx)
    yield r, service, ctx
    if not r.passed():
        return

    if service == "auto":
        service = detect(session, host, port, ctx)
    ctx["service"] = service
    yield None, service, ctx  # service-detected signal

    for _, fn in CHAIN[1:]:
        yield fn(session, host, port, ctx), service, ctx


# ── single-file self-reference ────────────────────────────────────────────────
# In the package, cli.py does `from . import engine` and calls `engine.*`. In this
# amalgamated build every symbol already lives in this module, so point `engine`
# at ourselves and pin the version that the package exposes via __init__.py.
engine = sys.modules[__name__]
__version__ = "1.0.0"

# detail keys worth surfacing under a stage line
_SHOW = {"open", "open_paths", "findings", "surfaces", "high_impact", "adjacent",
         "adjacent_count", "count", "n_paths", "sample", "jobs", "type", "bytes", "reachable"}

# significance of known paths — shown in the open-path table when AUTH is OPEN
_PATH_SIG: dict[str, str] = {
    "/v1/chat/completions":     "LLM inference — send arbitrary prompts",
    "/v1/completions":          "LLM completions (legacy OpenAI-compat)",
    "/v1/audio/speech":         "TTS synthesis — generate audio",
    "/v1/audio/transcriptions": "Audio → text transcription",
    "/v1/audio/voices":         "Voice inventory",
    "/transcribe":              "Transcription route",
    "/asr":                     "Speech recognition endpoint",
    "/v1/models":               "Model inventory — reveals loaded models",
    "/slots":                   "Inference slot state — active sessions side-channel",
    "/speakers":                "Speaker inventory — voice clone surface",
    "/actuator/env":            "Spring Boot actuator — env vars / potential creds",
    "/admin":                   "Admin panel",
    "/config":                  "Config dump",
    "/metrics":                 "Metrics endpoint",
    "/health":                  "Health / version info",
    "/openapi.json":            "API schema",
    "/api/v1/targets":          "Prometheus scrape targets — topology leak",
    "/queue-metrics":           "Job queue metrics",
    "/detect-language":         "Language detection",
}


def render(results, host, port, service, elapsed) -> str:
    """Render a completed run as a coloured terminal report."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = (f"\n{BOLD}🐍 SNAKE{RESET}  {c(CYAN, host)}:{c(CYAN, str(port))}"
              f"  {c(DIM, service)}  {c(DIM, ts)}")
    lines = [header, ""]

    # horizontal chain — compact two-row layout for 12 stages
    def seg(r):
        return f"{r.color()}{BOLD}[{r.name} {r.symbol()}]{RESET}"

    row1, row2 = results[:6], results[6:]
    lines.append("  " + f" {c(DIM, '→')} ".join(seg(r) for r in row1))
    if row2:
        lines.append("  " + " " * 3 + f" {c(DIM, '→')} ".join(seg(r) for r in row2))
    lines.append("")

    # evidence
    for r in results:
        col = r.color()
        label = f"{col}{BOLD}{r.name:<18}{RESET}"
        tag = f"{col}[{r.status}]{RESET}"
        lines.append(f"  {label} {tag}  {r.evidence}")
        if r.detail and r.status not in (FAIL, SKIP, ERROR):
            for k, v in r.detail.items():
                if k in _SHOW:
                    lines.append(f"  {' ' * 20}{c(DIM, k)}: {str(v)[:110]}")

    # open path significance table
    open_paths: list[str] = []
    for r in results:
        if r.name == "AUTH" and r.status == OPEN:
            open_paths = r.detail.get("open", [])
            break
    if open_paths:
        lines.append("")
        lines.append(f"  {BOLD}OPEN PATHS{RESET}  {c(DIM, '(no auth required)')}")
        col_w = max(len(p) for p in open_paths)
        for p in open_paths:
            pad = " " * (col_w - len(p) + 2)
            sig = _PATH_SIG.get(p, "—")
            lines.append(f"  {c(YELLOW, p)}{pad}{c(DIM, sig)}")

    # frontier
    last = results[-1]
    lines.append("")
    if last.name == "SUMMARY" and last.passed():
        lines.append(f"  {c(GREEN, BOLD + '◉ CHAIN COMPLETE' + RESET)}")
    else:
        lines.append(f"  {c(RED, BOLD + '◉ FRONTIER' + RESET)}  "
                     f"{c(RED, 'snake stopped at ' + last.name)}")
    lines.append(f"  {c(DIM, f'{len(results)} stages  {elapsed:.1f}s')}")
    return "\n".join(lines)


def _emit(text: str, use_color: bool) -> None:
    print(text if use_color else strip_ansi(text))


def run_batch(filepath, service="auto", active=False, use_color=True) -> None:
    """Run the chain over `host:port` lines in a file, then print a ranked summary."""
    with open(filepath) as f:
        targets = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    summary = []
    for t in targets:
        parts = t.rsplit(":", 1)
        if len(parts) != 2 or not parts[1].isdigit():
            print(f"  {c(GREY, 'skip malformed target: ' + t)}")
            continue
        host, port = parts[0], int(parts[1])
        _emit("\n" + "─" * 64, use_color)
        results, elapsed, svc, ctx = run(host, port, service, active=active)
        _emit(render(results, host, port, svc, elapsed), use_color)
        save(host, port, svc, results, elapsed, ctx)
        summary.append({"host": host, "port": port, "svc": svc,
                        "open": len(ctx.get("open_paths", [])),
                        "surfaces": ctx.get("exploit_surfaces", [])})

    _emit("\n" + "═" * 64, use_color)
    _emit(f"{BOLD}BATCH SUMMARY{RESET} — {len(summary)} hosts\n", use_color)
    # rank by exposure breadth: most surfaces first, then most open paths
    for s in sorted(summary, key=lambda x: (len(x["surfaces"]), x["open"]), reverse=True):
        exposed = s["open"] or s["surfaces"]
        flag = c(YELLOW, "OPEN") if exposed else c(GREY, "—   ")
        surfs = ", ".join(s["surfaces"][:3]) or "no surface classified"
        label = f"{s['host']}:{s['port']}"
        pad = " " * max(1, 24 - len(label))  # pad on visible length, not ANSI bytes
        _emit(f"  {c(CYAN, label)}{pad}{flag}  "
              f"{s['open']:>2} open  {c(DIM, surfs)}", use_color)


# aimap service name → snake --service choice
_AIMAP_SERVICE_MAP: dict[str, str] = {
    "whisper asr": "whisper-modern",
    "whisperx": "whisperx",
    "kokoro": "kokoro",
    "cosyvoice": "cosyvoice",
    "vllm": "vllm",
    "llama.cpp": "llamacpp",
    "llamacpp": "llamacpp",
    "rtp-llm": "generic",
    "chatterbox tts api": "generic",
    "chatterbox": "generic",
    "prometheus": "prometheus",
    "lunary": "lunary",
}


def _parse_aimap_targets(path: str) -> list[tuple[str, int, str]]:
    """Parse an aimap JSON report; return (host, port, snake_service) tuples."""
    with open(path) as f:
        data = _json.load(f)
    targets: dict[tuple[str, int], str] = {}

    # services[] — fingerprint-confirmed; carry the service hint forward
    for s in data.get("services", []):
        key = (s["host"], s["port"])
        targets[key] = _AIMAP_SERVICE_MAP.get(s["service"].lower(), "generic")

    # open_ports[] — any 200-responding port not already covered by services[]
    for p in data.get("open_ports", []):
        if p.get("status_code") == 200:
            key = (p["host"], p["port"])
            if key not in targets:
                targets[key] = "auto"

    return [(h, p, s) for (h, p), s in sorted(targets.items(), key=lambda x: x[0][1])]


def _ranked_summary(summary: list[dict], use_color: bool, title: str) -> None:
    _emit("\n" + "═" * 64, use_color)
    _emit(f"{BOLD}{title}{RESET} — {len(summary)} target(s)\n", use_color)
    for s in sorted(summary, key=lambda x: (len(x["surfaces"]), x["open"]), reverse=True):
        exposed = s["open"] or s["surfaces"]
        flag = c(YELLOW, "OPEN") if exposed else c(GREY, "—   ")
        surfs = ", ".join(s["surfaces"][:3]) or "no surface classified"
        label = f"{s['host']}:{s['port']}"
        pad = " " * max(1, 24 - len(label))
        _emit(f"  {c(CYAN, label)}{pad}{flag}  {s['open']:>2} open  {c(DIM, surfs)}", use_color)


def run_discover(host: str, service: str = "auto",
                 active: bool = False, use_color: bool = True) -> None:
    """Sweep AI/ML ports on `host`, then chain against each live port."""
    _emit(f"\n{BOLD}SWEEP{RESET}  {c(CYAN, host)}"
          f"  {c(DIM, str(len(engine.AI_PORTS)) + ' ports…')}", use_color)
    live = engine.sweep(host)
    if not live:
        _emit(f"  {c(GREY, 'no live HTTP ports found')}", use_color)
        return
    port_list = "  ".join(f":{r['port']}({r['status']})" for r in live)
    _emit(f"  {c(GREEN, str(len(live)) + ' live')}  {c(DIM, port_list)}\n", use_color)

    summary = []
    for rec in live:
        port = rec["port"]
        _emit("─" * 64, use_color)
        results, elapsed, svc, ctx = engine.run(host, port, service, active=active)
        _emit(render(results, host, port, svc, elapsed), use_color)
        engine.save(host, port, svc, results, elapsed, ctx)
        summary.append({"host": host, "port": port, "svc": svc,
                        "open": len(ctx.get("open_paths", [])),
                        "surfaces": ctx.get("exploit_surfaces", [])})

    _ranked_summary(summary, use_color, "DISCOVER SUMMARY")


def run_from_aimap(filepath: str, service_override: str = "auto",
                   active: bool = False, use_color: bool = True) -> None:
    """Run the chain against every service identified in an aimap JSON report."""
    targets = _parse_aimap_targets(filepath)
    if not targets:
        _emit(f"  {c(GREY, 'no targets found in aimap report')}", use_color)
        return
    _emit(f"\n{BOLD}FROM-AIMAP{RESET}  {c(DIM, filepath)}"
          f"  {c(GREEN, str(len(targets)) + ' target(s)')}\n", use_color)

    summary = []
    for host, port, aimap_svc in targets:
        svc = service_override if service_override != "auto" else aimap_svc
        _emit("─" * 64, use_color)
        _emit(f"  {c(DIM, 'aimap hint:')} {c(CYAN, host)}:{c(CYAN, str(port))}"
              f"  {c(DIM, aimap_svc + ' → ' + svc)}", use_color)
        results, elapsed, detected_svc, ctx = engine.run(host, port, svc, active=active)
        _emit(render(results, host, port, detected_svc, elapsed), use_color)
        engine.save(host, port, detected_svc, results, elapsed, ctx)
        summary.append({"host": host, "port": port, "svc": detected_svc,
                        "open": len(ctx.get("open_paths", [])),
                        "surfaces": ctx.get("exploit_surfaces", [])})

    _ranked_summary(summary, use_color, "AIMAP SUMMARY")


def _print_last_report() -> None:
    path = os.path.join(snake_home(), "last.json")
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print(f"No report: {e}")
        return
    surfaces = data.get("exploit_surfaces", [])
    opens = len(data.get("open_paths", []))
    print(f"\nLast: {data['host']}:{data['port']}  "
          f"{opens} open · {', '.join(surfaces) or 'no surface classified'}  {data['timestamp']}")
    for s in data["stages"]:
        print(f"  [{s['status']:<6}] {s['name']:<20} {s['evidence']}")


def _should_color(flag_no_color: bool) -> bool:
    if flag_no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="snake",
        description="Voice AI verification snake — 12-stage AI/ML service verification chain.",
        epilog="AUTHORIZED USE ONLY. Scan only infrastructure you own or are permitted to test.",
    )
    ap.add_argument("host", nargs="?", help="target IP or hostname")
    ap.add_argument("port", nargs="?", type=int, help="target port")
    ap.add_argument("--service", "-s", default="auto", choices=engine.SERVICE_CHOICES,
                    help="service type (default: auto-detect)")
    ap.add_argument("--active", action="store_true",
                    help="allow the INFERENCE stage to invoke the target's compute "
                         "(submits a minimal, non-retained probe). Off by default.")
    ap.add_argument("--batch", "-b", metavar="FILE", help="file of host:port lines")
    ap.add_argument("--from-aimap", metavar="FILE",
                    help="run chain against every service in an aimap JSON report")
    ap.add_argument("--report", metavar="last", help="print the last saved report")
    ap.add_argument("--json", "-j", action="store_true", help="emit JSON instead of a report")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    ap.add_argument("--version", "-V", action="version", version=f"%(prog)s {__version__}")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    use_color = _should_color(args.no_color)

    if args.report:
        _print_last_report()
        return 0

    if args.from_aimap:
        run_from_aimap(args.from_aimap, args.service, active=args.active, use_color=use_color)
        return 0

    if args.batch:
        run_batch(args.batch, args.service, active=args.active, use_color=use_color)
        return 0

    if not args.host:
        build_parser().print_help()
        return 1

    if not args.port:
        run_discover(args.host, args.service, active=args.active, use_color=use_color)
        return 0

    results, elapsed, service, ctx = run(args.host, args.port, args.service, active=args.active)

    if args.json:
        print(json.dumps(engine.build_report(args.host, args.port, service, results, elapsed, ctx), indent=2))
    else:
        _emit(render(results, args.host, args.port, service, elapsed), use_color)

    fname = save(args.host, args.port, service, results, elapsed, ctx)
    if not args.json:
        _emit(f"\n  {c(DIM, 'report → ' + fname)}\n", use_color)
    return 0


def entry() -> None:
    """Console-script entry point; translates Ctrl-C into a clean exit."""
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    entry()
