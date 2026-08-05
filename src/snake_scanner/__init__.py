"""Voice AI verification snake — a 12-stage service verification chain for AI/ML infrastructure.

Point it at a host:port; it probes each layer of the stack in sequence
(ENDPOINT → SCHEMA → AUTH → ENUM → INVENTORY → DATA → INFERENCE →
EXPLOIT-SURFACE → CHAIN → STORAGE → MONITORING → SUMMARY) and reports what is
exposed without authentication.

Public API:
    run(host, port, service="auto", active=False) -> (results, elapsed, service, ctx)
    run_stream(...)  -> generator of (StageResult, service, ctx)
    summarize(surfaces, open_paths, adjacent_count) -> dict roll-up of findings
    save(...)        -> path to the written JSON report
"""

from .engine import (
    ALL_SERVICES,
    CHAIN,
    SERVICE_CHOICES,
    STAGE_NAMES,
    StageResult,
    build_report,
    detect,
    run,
    run_stream,
    save,
    summarize,
)

__version__ = "1.0.0"
__tool_name__ = "Voice AI verification snake"

__all__ = [
    "run",
    "run_stream",
    "save",
    "summarize",
    "detect",
    "build_report",
    "StageResult",
    "CHAIN",
    "STAGE_NAMES",
    "SERVICE_CHOICES",
    "ALL_SERVICES",
    "__version__",
    "__tool_name__",
]
