"""Unit tests for the mdxss_guard core."""

from __future__ import annotations

import pathlib
import unittest

from mdxss_guard import Finding, clean, report, scan, summarize

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"


def codes(findings):
    return [finding.code for finding in findings]


class DetectionTests(unittest.TestCase):
    def test_script_tag_is_high(self):
        findings = scan("<script>alert(1)</script>")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, "MDX-SCRIPT")
        self.assertEqual(findings[0].severity, "high")

    def test_event_handler_on_img_is_high(self):
        findings = scan('<img src="x" onerror="alert(1)">')
        self.assertEqual([finding.code for finding in findings], ["MDX-EVENT-HANDLER"])
        self.assertEqual(findings[0].severity, "high")

    def test_javascript_markdown_link_is_high(self):
        findings = scan("[click](javascript:alert(document.cookie))")
        self.assertEqual([finding.code for finding in findings], ["MDX-JS-URL"])
        self.assertEqual(findings[0].severity, "high")

    def test_javascript_html_attribute_is_high(self):
        findings = scan('<a href="javascript:alert(1)">x</a>')
        self.assertEqual(codes(findings), ["MDX-JS-URL"])

    def test_entity_encoded_javascript_url_is_high(self):
        findings = scan('<a href="java&#115;cript:alert(1)">x</a>')
        self.assertEqual(codes(findings), ["MDX-JS-URL"])

    def test_iframe_is_high(self):
        findings = scan('<iframe src="https://attacker.example/frame"></iframe>')
        self.assertEqual(codes(findings), ["MDX-FRAME"])
        self.assertEqual(findings[0].severity, "high")

    def test_data_html_url_is_high(self):
        findings = scan('<img src="data:text/html;base64,PHNjcmlwdD4=">')
        self.assertIn("MDX-DATA-URL", codes(findings))
        data_finding = [finding for finding in findings if finding.code == "MDX-DATA-URL"][0]
        self.assertEqual(data_finding.severity, "high")

    def test_svg_is_high(self):
        findings = scan('<svg onload="alert(1)"></svg>')
        self.assertIn("MDX-SVG", codes(findings))
        self.assertIn("MDX-EVENT-HANDLER", codes(findings))

    def test_unknown_raw_html_is_low(self):
        findings = scan("<div>hello</div>")
        self.assertEqual(codes(findings), ["MDX-RAW-HTML"])
        self.assertEqual(findings[0].severity, "low")

    def test_fenced_code_block_is_ignored(self):
        text = "```html\n<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n```"
        self.assertEqual(scan(text), [])

    def test_inline_code_is_ignored(self):
        self.assertEqual(scan("Use `<script>` and `<img onerror=x>` only in docs."), [])

    def test_clean_example_has_no_findings(self):
        text = (EXAMPLES / "clean_render.md").read_text(encoding="utf-8")
        self.assertEqual(scan(text), [])

    def test_poisoned_example_has_high_findings(self):
        text = (EXAMPLES / "poisoned_render.md").read_text(encoding="utf-8")
        findings = scan(text)
        summary = summarize(findings)
        self.assertGreaterEqual(summary["counts"]["high"], 3)
        self.assertFalse(report(text)["clean"])

    def test_line_number_is_accurate(self):
        text = "line one\nline two\n<img src=x onerror=alert(1)>\n"
        findings = scan(text)
        self.assertTrue(findings)
        self.assertEqual(findings[0].line, 3)

    def test_finding_to_dict_has_fix(self):
        finding = scan("<script>alert(1)</script>")[0]
        payload = finding.to_dict()
        self.assertIn("fix", payload)
        self.assertTrue(payload["fix"])


class SanitizerTests(unittest.TestCase):
    def test_code_fence_is_preserved_byte_for_byte(self):
        fence = "```html\n<script>x</script>\n```"
        self.assertEqual(clean(fence), fence)

    def test_allowed_markdown_is_unchanged(self):
        text = "**bold** and [link](https://example.com) plus `code`"
        self.assertEqual(clean(text), text)

    def test_event_handler_is_removed(self):
        cleaned = clean('<img src=x onerror="alert(1)">')
        self.assertNotIn("onerror", cleaned)
        self.assertEqual(scan(cleaned), [])

    def test_javascript_href_is_dropped(self):
        cleaned = clean('<a href="javascript:alert(1)">x</a>')
        self.assertNotIn("javascript:", cleaned)
        self.assertEqual(scan(cleaned), [])

    def test_script_content_is_removed(self):
        cleaned = clean("before <script>alert(1)</script> after")
        self.assertNotIn("<script", cleaned)
        self.assertIn("before", cleaned)
        self.assertIn("after", cleaned)

    def test_poisoned_example_scans_clean_after_sanitize(self):
        text = (EXAMPLES / "poisoned_render.md").read_text(encoding="utf-8")
        cleaned = clean(text)
        self.assertEqual(scan(cleaned), [])
        self.assertIn("legit example in docs", cleaned)

    def test_escape_mode_escapes_html_and_scans_clean(self):
        cleaned = clean("<b>hi</b><script>x</script>", "escape")
        self.assertIn("&lt;b&gt;", cleaned)
        self.assertEqual(scan(cleaned), [])

    def test_escape_mode_blocks_markdown_link_scheme(self):
        cleaned = clean("[x](javascript:alert(1))", "escape")
        self.assertEqual(scan(cleaned), [])

    def test_strip_mode_is_idempotent(self):
        text = (EXAMPLES / "poisoned_render.md").read_text(encoding="utf-8")
        once = clean(text)
        twice = clean(once)
        self.assertEqual(once, twice)

    def test_unknown_tag_is_escaped(self):
        self.assertIn("&lt;div&gt;", clean("<div>hello</div>"))

    def test_bad_mode_raises(self):
        with self.assertRaises(ValueError):
            clean("hello", "bogus")


class SummarizeTests(unittest.TestCase):
    def test_summary_counts_and_max_severity(self):
        findings = scan("<script>x</script>\n<div>y</div>")
        summary = summarize(findings)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["counts"]["high"], 1)
        self.assertEqual(summary["counts"]["low"], 1)
        self.assertEqual(summary["max_severity"], "high")

    def test_empty_summary(self):
        self.assertEqual(summarize([]), {"total": 0, "counts": {"low": 0, "medium": 0, "high": 0}, "max_severity": "none"})
