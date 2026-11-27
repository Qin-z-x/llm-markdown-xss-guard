#!/usr/bin/env python3
"""Build the self-contained demo chat pages for llm-markdown-xss-guard.

docs/demo_chat.html renders the poisoned model answer as raw HTML, so the
harmless payload really executes in a browser. docs/demo_clean.html renders the
sanitized answer; the same payload is neutralized and does not execute.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mdxss_guard import VERSION, clean, report, scan  # noqa: E402

MARKER = "XSS-EXECUTED-7C1A"
EXEC_HANDLER_RE = re.compile(r"<[A-Za-z][^>]*\son[a-z]+\s*=", re.S)
POISONED_PATH = ROOT / "examples" / "poisoned_render.md"
CHAT_PAGE = ROOT / "docs" / "demo_chat.html"
CLEAN_PAGE = ROOT / "docs" / "demo_clean.html"
RAW_JSON = ROOT / "evidence" / "raw" / "demo_build.json"


def escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def inline(text: str) -> str:
    text = escape_html(text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', text)
    return text


def render_markdown(text: str) -> str:
    out = []
    in_code = False
    code_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_code:
                out.append("<pre class='code'><code>" + escape_html("\n".join(code_lines)) + "</code></pre>")
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
            continue
        if not stripped:
            continue
        if stripped.startswith("<"):
            # Raw HTML from the model answer is inserted as HTML in the poisoned page.
            out.append(line)
            continue
        if stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            out.append("<h%d>%s</h%d>" % (level, inline(stripped[level:].strip()), level))
            continue
        if stripped.startswith("- "):
            out.append("<ul><li>" + inline(stripped[2:]) + "</li></ul>")
            continue
        out.append("<p>" + inline(stripped) + "</p>")
    if code_lines:
        out.append("<pre class='code'><code>" + escape_html("\n".join(code_lines)) + "</code></pre>")
    return "\n".join(out)


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>%(title)s - llm-markdown-xss-guard demo</title>
<style>
  :root { color-scheme: dark; }
  body { background: #111417; color: #e6edf3; font: 15px/1.55 "Segoe UI", system-ui, sans-serif; margin: 0; padding: 24px; }
  .wrap { max-width: 880px; margin: 0 auto; }
  .top { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
  .badge { font: 12px ui-monospace, monospace; background: #1f6feb33; border: 1px solid #1f6feb; color: #79c0ff; border-radius: 999px; padding: 2px 10px; }
  .alert { border-radius: 8px; padding: 12px 14px; margin: 12px 0 20px; border: 1px solid #3d444d; background: #161b22; color: #8b949e; font-family: ui-monospace, monospace; font-size: 13px; }
  .alert.fired { border-color: #f85149; background: #f851491f; color: #ff7b72; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 20px 24px; }
  .card h1, .card h2 { border-bottom: 1px solid #30363d; padding-bottom: 6px; }
  a { color: #58a6ff; }
  code { background: #21262d; padding: 1px 5px; border-radius: 4px; font-size: 13px; }
  pre.code { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 12px; overflow-x: auto; }
  .meta { color: #8b949e; font-size: 13px; margin-bottom: 8px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="top"><strong>llm-markdown-xss-guard</strong><span class="badge">%(badge)s</span></div>
  <p class="meta">%(intro)s</p>
  <div id="xss-alert" class="alert">%(alert)s</div>
  <div class="card">
%(content)s
  </div>
  <p class="meta">Built by scripts/build_demo.py from %(source)s. Version %(version)s.</p>
</div>
</body>
</html>
"""


def write_page(path: Path, title: str, badge: str, intro: str, alert: str, content: str, source: str) -> None:
    path.write_text(
        PAGE
        % {
            "title": title,
            "badge": badge,
            "intro": intro,
            "alert": alert,
            "content": content,
            "source": source,
            "version": VERSION,
        },
        encoding="utf-8",
        newline="\n",
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    poisoned = POISONED_PATH.read_text(encoding="utf-8")
    # The demo must run offline: rewrite the documentation URL inside the iframe
    # to about:blank so a headless browser never waits on a network request.
    demo_source = poisoned.replace("https://attacker.example/frame", "about:blank")
    cleaned = clean(demo_source, "strip")
    before = report(poisoned)
    after = report(cleaned)
    RAW_JSON.parent.mkdir(parents=True, exist_ok=True)

    poisoned_html = render_markdown(demo_source)
    cleaned_html = render_markdown(cleaned)
    write_page(
        CHAT_PAGE,
        "poisoned transcript",
        "UNSANITIZED raw HTML",
        "This is a model answer rendered with raw HTML enabled (a permissive chat UI). The injected payload is harmless: it only writes a marker into the red panel above.",
        "No script executed.",
        poisoned_html,
        "examples/poisoned_render.md",
    )
    write_page(
        CLEAN_PAGE,
        "sanitized transcript",
        "SANITIZED allowlist",
        "The same model answer after mdxss_guard.clean(strip). The payload was neutralized, so the panel above stays green and no marker appears.",
        "No script executed.",
        cleaned_html,
        "examples/poisoned_render.md (cleaned)",
    )

    assertions = {
        "poisoned_executable_handler": bool(EXEC_HANDLER_RE.search(poisoned_html)) and "onerror" in poisoned_html,
        "poisoned_contains_script_tag": "<script>" in poisoned_html,
        "clean_executable_handler": bool(EXEC_HANDLER_RE.search(cleaned_html)),
        "clean_contains_script_tag": "<script" in cleaned_html,
        "poisoned_findings": before["summary"]["total"],
        "poisoned_high": before["summary"]["counts"]["high"],
        "cleaned_findings": after["summary"]["total"],
        "marker": MARKER,
    }
    assertions["pass"] = (
        assertions["poisoned_executable_handler"]
        and assertions["poisoned_contains_script_tag"]
        and not assertions["clean_executable_handler"]
        and not assertions["clean_contains_script_tag"]
        and assertions["poisoned_findings"] > 0
        and assertions["cleaned_findings"] == 0
    )
    payload = {
        "version": VERSION,
        "marker": MARKER,
        "assertions": assertions,
        "pages": {
            "docs/demo_chat.html": {"sha256": sha256(CHAT_PAGE), "bytes": CHAT_PAGE.stat().st_size},
            "docs/demo_clean.html": {"sha256": sha256(CLEAN_PAGE), "bytes": CLEAN_PAGE.stat().st_size},
        },
        "cleaned_markdown_sha256": hashlib.sha256(cleaned.encode("utf-8")).hexdigest(),
    }
    RAW_JSON.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")

    print("poisoned page : docs/demo_chat.html  findings=%d high=%d  sha256=%s" % (before["summary"]["total"], before["summary"]["counts"]["high"], payload["pages"]["docs/demo_chat.html"]["sha256"][:16]))
    print("cleaned page  : docs/demo_clean.html  findings=%d  sha256=%s" % (after["summary"]["total"], payload["pages"]["docs/demo_clean.html"]["sha256"][:16]))
    print("assertions    : handler_in_poisoned=%s handler_in_clean=%s script_in_poisoned=%s script_in_clean=%s" % (
        assertions["poisoned_executable_handler"], assertions["clean_executable_handler"], assertions["poisoned_contains_script_tag"], assertions["clean_contains_script_tag"]))
    print("result        : %s" % ("PASS" if assertions["pass"] else "FAIL"))
    return 0 if assertions["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
