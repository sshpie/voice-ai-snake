#!/usr/bin/env python3
"""Generate the zero-install standalone `snake.py` from the package sources.

The package (`src/snake_scanner/`) is the single source of truth. The root
`snake.py` is a *derived* artifact: `engine.py` and `cli.py` amalgamated into one
self-contained file so someone can `python snake.py host port` without installing
anything (only `requests` is needed).

The amalgamation:
  * drops each module's leading docstring + `from __future__` line (one header
    is written here instead),
  * strips the `from . import ...` / `from .engine import (...)` package imports
    from cli.py — those names live in the same module after concatenation,
  * injects `engine = sys.modules[__name__]` so cli.py's `engine.*` calls resolve
    against this single module,
  * pins `__version__` read from the package `__init__.py`.

Run `python tools/build_standalone.py` to regenerate. `tests/test_standalone.py`
asserts the committed file matches a fresh build, so a stale copy fails CI.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "src" / "snake_scanner"
OUT = ROOT / "snake.py"

_FUTURE = "from __future__ import annotations\n"
# module-level import lines (col 0); indented imports inside functions won't match
_IMPORT_RE = re.compile(r"^(?:import |from )\S.*$", re.M)

HEADER = '''#!/usr/bin/env python3
"""Voice AI verification snake — standalone single-file build.

Zero-install: `python snake.py <host> <port> [--service NAME] [--active] [--json]`.
Requires only `requests`  (pip install requests).

GENERATED from src/snake_scanner/engine.py + cli.py by tools/build_standalone.py.
Do NOT edit by hand — edit the package and run `python tools/build_standalone.py`.
"""
from __future__ import annotations

{imports}
'''

MID = '''

# ── single-file self-reference ────────────────────────────────────────────────
# In the package, cli.py does `from . import engine` and calls `engine.*`. In this
# amalgamated build every symbol already lives in this module, so point `engine`
# at ourselves and pin the version that the package exposes via __init__.py.
engine = sys.modules[__name__]
__version__ = "{version}"
'''


def _body_after_future(src: str) -> str:
    """Return everything after the `from __future__` line (drops docstring too)."""
    if _FUTURE not in src:
        raise ValueError("expected a `from __future__ import annotations` line")
    return src.split(_FUTURE, 1)[1]


def _split_imports(body: str) -> tuple[list[str], str]:
    """Pull module-level import lines out of `body`; return (imports, remainder)."""
    imports = _IMPORT_RE.findall(body)
    remainder = _IMPORT_RE.sub("", body)
    return imports, remainder


def _sort_key(line: str) -> tuple:
    """isort-compatible order: plain `import x` before `from x import y`, then module."""
    return (0 if line.startswith("import ") else 1, line.split()[1])


def _merge_imports(*blocks: list[str]) -> str:
    """Dedupe (first-seen), group stdlib before third-party, in isort order."""
    seen: list[str] = []
    for block in blocks:
        for line in block:
            if line not in seen:
                seen.append(line)
    third_party = ("requests", "urllib3")
    stdlib = [ln for ln in seen if ln.split()[1].split(".")[0] not in third_party]
    third = [ln for ln in seen if ln.split()[1].split(".")[0] in third_party]
    return "\n".join(sorted(stdlib, key=_sort_key) + [""] + sorted(third, key=_sort_key))


def _read_version() -> str:
    init = (PKG / "__init__.py").read_text()
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init)
    if not m:
        raise ValueError("could not find __version__ in __init__.py")
    return m.group(1)


def build() -> str:
    engine_body = _body_after_future((PKG / "engine.py").read_text())
    cli_body = _body_after_future((PKG / "cli.py").read_text())

    # Drop the package imports — those names are defined in engine_body / hoisted.
    cli_body = re.sub(r"from \.engine import \([^)]*\)\n", "", cli_body)
    cli_body = re.sub(r"from \. import [^\n]*\n", "", cli_body)

    eng_imports, engine_body = _split_imports(engine_body)
    cli_imports, cli_body = _split_imports(cli_body)
    imports = _merge_imports(eng_imports, cli_imports)

    parts = [
        HEADER.format(imports=imports),
        engine_body.strip("\n"),
        MID.format(version=_read_version()),
        cli_body.strip("\n"),
    ]
    return "\n".join(parts).rstrip("\n") + "\n"


def main() -> int:
    OUT.write_text(build())
    OUT.chmod(0o755)
    print(f"wrote {OUT.relative_to(ROOT)}  ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
