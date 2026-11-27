#!/usr/bin/env python3
"""Headless-browser check for the demo pages.

Renders docs/demo_chat.html (poisoned) and docs/demo_clean.html (sanitized) in
headless Microsoft Edge and checks whether the harmless XSS marker appeared in
the DOM. Makes no network requests; both pages are local files.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARKER = "XSS-EXECUTED-7C1A"
RAW_JSON = ROOT / "evidence" / "raw" / "browser_check.json"
CANDIDATES = [
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
]


def find_browser():
    for candidate in CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


def dump_dom(browser: Path, page: Path) -> str:
    profile = tempfile.mkdtemp(prefix="mdxss-edge-")
    command = [
        str(browser),
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--no-first-run",
        "--disable-extensions",
        "--user-data-dir=" + profile,
        "--dump-dom",
        page.as_uri(),
    ]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        return proc.stdout
    finally:
        shutil.rmtree(profile, ignore_errors=True)


def main() -> int:
    browser = find_browser()
    if browser is None:
        print("SKIPPED: Microsoft Edge not found in the standard install locations; browser execution check not performed.")
        return 0
    poisoned_dom = dump_dom(browser, ROOT / "docs" / "demo_chat.html")
    cleaned_dom = dump_dom(browser, ROOT / "docs" / "demo_clean.html")
    poisoned_fired = MARKER in poisoned_dom
    cleaned_fired = MARKER in cleaned_dom
    payload = {
        "browser": str(browser),
        "marker": MARKER,
        "poisoned_page": {"marker_in_dom": poisoned_fired, "dom_bytes": len(poisoned_dom.encode("utf-8", "replace"))},
        "cleaned_page": {"marker_in_dom": cleaned_fired, "dom_bytes": len(cleaned_dom.encode("utf-8", "replace"))},
        "result": "PASS" if (poisoned_fired and not cleaned_fired) else "FAIL",
    }
    RAW_JSON.parent.mkdir(parents=True, exist_ok=True)
    RAW_JSON.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("browser       : %s" % browser)
    print("poisoned page : marker in DOM = %s" % poisoned_fired)
    print("cleaned page  : marker in DOM = %s" % cleaned_fired)
    print("result        : %s" % payload["result"])
    return 0 if payload["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
