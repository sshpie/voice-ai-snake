"""CLI-surface tests — parsing, rendering, colour stripping, exit codes."""

import pytest

from snake_scanner import cli
from snake_scanner.engine import PASS, StageResult, strip_ansi


def test_parser_defaults():
    args = cli.build_parser().parse_args(["1.2.3.4", "8880"])
    assert args.host == "1.2.3.4"
    assert args.port == 8880
    assert args.service == "auto"
    assert args.active is False


def test_parser_active_and_service():
    args = cli.build_parser().parse_args(["h", "80", "--active", "-s", "vllm"])
    assert args.active is True
    assert args.service == "vllm"


def test_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as e:
        cli.build_parser().parse_args(["--version"])
    assert e.value.code == 0


def test_no_args_prints_help_and_returns_one(capsys):
    assert cli.main([]) == 1
    assert "usage" in capsys.readouterr().out.lower()


def test_render_contains_stage_names_and_strips_clean():
    results = [
        StageResult("ENDPOINT", PASS, "https 200"),
        StageResult("SUMMARY", PASS, "2 path(s) open without auth"),
    ]
    out = cli.render(results, "h", 8880, "kokoro", 1.2)
    plain = strip_ansi(out)
    assert "ENDPOINT" in plain
    assert "SUMMARY" in plain
    assert "open without auth" in plain
    # strip_ansi must remove every escape sequence
    assert "\033[" not in plain


def test_report_missing_is_handled(snake_tmp_home, capsys):
    # SNAKE_HOME points at an empty temp dir -> no last.json.
    assert cli.main(["--report", "last"]) == 0
    assert "No report" in capsys.readouterr().out
