"""CLI behaviour tests for mdxss-guard."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import tempfile
import unittest

from mdxss_guard.cli import main

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"
POISONED = str(EXAMPLES / "poisoned_render.md")
CLEAN = str(EXAMPLES / "clean_render.md")


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_scan_json_reports_findings(self):
        code, out, _ = run(["scan", POISONED, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertGreaterEqual(payload["summary"]["counts"]["high"], 3)
        self.assertTrue(payload["findings"])
        self.assertIn("fix", payload["findings"][0])

    def test_scan_gate_blocks_poisoned(self):
        code, _, err = run(["scan", POISONED, "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertIn("FAIL", err)

    def test_scan_gate_passes_clean(self):
        code, _, _ = run(["scan", CLEAN, "--fail-on", "low"])
        self.assertEqual(code, 0)

    def test_clean_writes_file_and_rescan_is_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "cleaned.md"
            code, _, err = run(["clean", POISONED, "-o", str(target)])
            self.assertEqual(code, 0)
            self.assertIn("wrote", err)
            cleaned = target.read_text(encoding="utf-8")
            self.assertEqual(cleaned.count("onerror"), 1)  # only the documentation code block keeps it
            self.assertIn('<img src="x">', cleaned)
            code, _, _ = run(["scan", str(target), "--fail-on", "low"])
            self.assertEqual(code, 0)

    def test_clean_json_reports_zero_after(self):
        code, out, _ = run(["clean", POISONED, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertGreater(payload["findings_before"], 0)
        self.assertEqual(payload["findings_after"], 0)

    def test_clean_stdout_roundtrip(self):
        code, out, _ = run(["clean", POISONED])
        self.assertEqual(code, 0)
        outside_fence = out.split("```html")[0]
        self.assertNotIn("onerror", outside_fence)
        self.assertNotIn("javascript:", outside_fence)
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "out.md"
            target.write_text(out, encoding="utf-8")
            code, _, _ = run(["scan", str(target), "--fail-on", "low"])
            self.assertEqual(code, 0)

    def test_missing_file_exits_2(self):
        code, _, err = run(["scan", "does-not-exist.md"])
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_bad_mode_exits_2(self):
        with self.assertRaises(SystemExit) as context:
            run(["clean", POISONED, "--mode", "bogus"])
        self.assertEqual(context.exception.code, 2)

    def test_report_json_has_fix_suggestions(self):
        code, out, _ = run(["report", POISONED, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertFalse(payload["clean"])
        self.assertTrue(any(finding["fix"] for finding in payload["findings"]))

    def test_stdin_input(self):
        import sys

        original = sys.stdin
        sys.stdin = io.StringIO("[x](javascript:alert(1))")
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["scan", "-", "--json"])
        finally:
            sys.stdin = original
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["summary"]["counts"]["high"], 1)
