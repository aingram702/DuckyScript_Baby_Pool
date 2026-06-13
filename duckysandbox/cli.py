"""Command-line interface for the DuckyScript Behaviour Sandbox."""

from __future__ import annotations

import argparse
import sys

from . import analyzer
from .emulator import emulate
from .html_report import render_html
from .report import render_json, render_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="duckysandbox",
        description=(
            "Statically simulate a DuckyScript / BashBunny payload in a sandbox "
            "and report the processes, files, registry keys and network "
            "connections it would touch -- without running it on real hardware."
        ),
    )
    parser.add_argument(
        "payload",
        help="Path to a DuckyScript/BashBunny payload file, or '-' to read from stdin",
    )
    parser.add_argument(
        "--os", dest="target_os", choices=["windows", "macos", "linux"], default=None,
        help="Target OS to assume (default: auto-detect from the payload content)",
    )
    parser.add_argument(
        "--format", choices=["markdown", "json", "html"], default="markdown",
        help="Report format (default: markdown)",
    )
    parser.add_argument(
        "-o", "--out", metavar="FILE",
        help="Write the report to FILE instead of stdout",
    )
    parser.add_argument(
        "--json-out", metavar="FILE",
        help="Additionally write a JSON report to FILE regardless of --format",
    )
    parser.add_argument(
        "--fail-on", choices=["info", "low", "medium", "high", "critical"], default=None,
        help="Exit with status 1 if any finding's severity is at or above this level",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.payload == "-":
        text = sys.stdin.read()
        name = "stdin"
    else:
        try:
            with open(args.payload, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print(f"error: cannot read {args.payload}: {exc}", file=sys.stderr)
            return 2
        name = args.payload

    result = emulate(text, target_os=args.target_os, source_name=name)

    json_output = render_json(result, payload_name=name)
    if args.format == "json":
        output = json_output
    elif args.format == "html":
        output = render_html(result, payload_name=name)
    else:
        output = render_markdown(result, payload_name=name)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        print(output)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(json_output)

    if args.fail_on:
        threshold = analyzer.SEVERITY_RANK[args.fail_on]
        worst = max((analyzer.SEVERITY_RANK[f.severity] for f in result.findings), default=-1)
        if worst >= threshold:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
