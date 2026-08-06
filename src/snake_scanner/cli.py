"""Command-line interface for the Voice AI verification snake.

Owns everything terminal-specific — ANSI rendering, the batch summary, argument
parsing — and delegates all probing to `engine`. The engine never prints; this
module decides how results appear on a terminal.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import __version__, engine
from .engine import (
    BOLD,
    CYAN,
    DIM,
    ERROR,
    FAIL,
    GREEN,
    GREY,
    OPEN,
    RED,
    RESET,
    SKIP,
    YELLOW,
    c,
    run,
    save,
    snake_home,
    strip_ansi,
)

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

    if args.batch:
        run_batch(args.batch, args.service, active=args.active, use_color=use_color)
        return 0

    if not args.host or not args.port:
        build_parser().print_help()
        return 1

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
