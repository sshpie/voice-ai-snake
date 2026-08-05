"""The root snake.py is a generated amalgamation of the package; keep it honest.

These tests guard the zero-install single-file build: it must be byte-identical
to a fresh generation (so a stale copy fails CI) and must actually expose the
engine + CLI it claims to.
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec: @dataclass under `from __future__ import annotations`
    # resolves stringized annotations via sys.modules[cls.__module__].
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_committed_standalone_matches_fresh_build():
    builder = _load(ROOT / "tools" / "build_standalone.py", "snake_build")
    fresh = builder.build()
    committed = (ROOT / "snake.py").read_text()
    assert committed == fresh, (
        "snake.py is stale — run `python tools/build_standalone.py` and commit the result."
    )


def test_standalone_exposes_cli_and_engine_symbols():
    mod = _load(ROOT / "snake.py", "snake_standalone")
    assert hasattr(mod, "run")
    assert hasattr(mod, "main")
    assert hasattr(mod, "summarize")
    assert mod.STAGE_NAMES[-1] == "SUMMARY"  # scoreless chain ends at SUMMARY
