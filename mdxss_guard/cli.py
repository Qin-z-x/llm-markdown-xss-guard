"""Command line interface for mdxss-guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import SEVERITY_RANK, VERSION, clean, report, scan, summarize

TOOL = "mdxss-guard"


def _read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _print_json(payload) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=True))


def _print_findings(path: str, text: str, findings) -> dict:
    summary = summarize(findings)
    print("%s %s  scan  %s  (%d lines, %d chars)" % (TOOL, VERSION, path, len(text.splitlines()), len(text)))
    for finding in findings:
        print("%-6s %-20s line %-4d col %-4d %s" % (finding.severity.upper(), finding.code, finding.line, finding.column, finding.message))
    print(
        "summary: %d finding(s): %d high, %d medium, %d low"
        % (summary["total"], summary["counts"]["high"], summary["counts"]["medium"], summary["counts"]["low"])
    )
    return summary


def _gate(findings, fail_on: str) -> int:
    if not fail_on:
        return 0
    threshold = SEVERITY_RANK[fail_on]
    count = sum(1 for finding in findings if SEVERITY_RANK[finding.severity] >= threshold)
    if count:
        print("FAIL: %d finding(s) at or above severity %r" % (count, fail_on), file=sys.stderr)
        return 1
    print("PASS: no finding at or above severity %r" % fail_on)
    return 0


def _cmd_scan(args) -> int:
    text = _read_text(args.path)
    findings = scan(text)
    if args.json:
        payload = report(text)
        payload["path"] = args.path
        _print_json(payload)
    else:
        _print_findings(args.path, text, findings)
    return _gate(findings, args.fail_on)


def _cmd_clean(args) -> int:
    text = _read_text(args.path)
    cleaned = clean(text, args.mode)
    findings_before = scan(text)
    findings_after = scan(cleaned)
    if args.json:
        _print_json(
            {
                "tool": TOOL,
                "version": VERSION,
                "path": args.path,
                "mode": args.mode,
                "findings_before": len(findings_before),
                "findings_after": len(findings_after),
                "output": cleaned,
            }
        )
        return 0
    if args.output and args.output != "-":
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(cleaned if cleaned.endswith("\n") else cleaned + "\n", encoding="utf-8", newline="\n")
        print(
            "wrote %s (mode=%s, findings before=%d, after=%d)"
            % (args.output, args.mode, len(findings_before), len(findings_after)),
            file=sys.stderr,
        )
    else:
        sys.stdout.write(cleaned if cleaned.endswith("\n") else cleaned + "\n")
    return _gate(findings_before, args.fail_on) if args.fail_on else 0


def _cmd_report(args) -> int:
    text = _read_text(args.path)
    payload = report(text)
    if args.json:
        _print_json(payload)
        return 0
    _print_findings(args.path, text, scan(text))
    if payload["findings"]:
        print("fix suggestions:")
        seen = set()
        for finding in payload["findings"]:
            if finding["code"] in seen:
                continue
            seen.add(finding["code"])
            print("  %-20s %s" % (finding["code"], finding["fix"]))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL,
        description="Detect and sanitize XSS carriers in rendered LLM Markdown output (stdlib-only).",
    )
    parser.add_argument("--version", action="version", version="%s %s" % (TOOL, VERSION))
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan Markdown for XSS carriers")
    scan_parser.add_argument("path", help="Markdown file, or - for stdin")
    scan_parser.add_argument("--json", action="store_true", help="emit JSON")
    scan_parser.add_argument("--fail-on", choices=["low", "medium", "high"], help="exit 1 when a finding at or above this severity exists")
    scan_parser.set_defaults(func=_cmd_scan)

    clean_parser = subparsers.add_parser("clean", help="sanitize Markdown; code blocks are left untouched")
    clean_parser.add_argument("path", help="Markdown file, or - for stdin")
    clean_parser.add_argument("--mode", choices=["strip", "escape"], default="strip")
    clean_parser.add_argument("--json", action="store_true", help="emit JSON instead of sanitized text")
    clean_parser.add_argument("-o", "--output", help="write the sanitized text to this file")
    clean_parser.add_argument("--fail-on", choices=["low", "medium", "high"], help="gate on the input findings")
    clean_parser.set_defaults(func=_cmd_clean)

    report_parser = subparsers.add_parser("report", help="findings plus concrete fix suggestions")
    report_parser.add_argument("path", help="Markdown file, or - for stdin")
    report_parser.add_argument("--json", action="store_true", help="emit JSON")
    report_parser.set_defaults(func=_cmd_report)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print("error: file not found: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except UnicodeDecodeError as exc:
        print("error: input is not valid UTF-8: %s" % exc, file=sys.stderr)
        return 2
