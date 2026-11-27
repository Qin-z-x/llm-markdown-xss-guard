# llm-markdown-xss-guard

[![CI](https://github.com/Qin-z-x/llm-markdown-xss-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Qin-z-x/llm-markdown-xss-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![stdlib-only core](https://img.shields.io/badge/core-stdlib%20only-brightgreen.svg)](scripts/check_core_deps.py)

**Detect and sanitize XSS carriers in rendered LLM Markdown output.** Chat UIs
render model answers as Markdown, and many of them also pass raw HTML through or
use a permissive sanitizer. A model answer (or a poisoned RAG document) that
contains `<img src=x onerror=...>`, `<script>`, `<iframe>`, `javascript:` link
destinations, `data:text/html` URLs or SVG can execute JavaScript in the user's
browser. This project is a standard-library-only detector, allowlist sanitizer
and a reproducible local demo.

```console
$ python -m mdxss_guard scan examples/poisoned_render.md
mdxss-guard 0.1.0  scan  examples/poisoned_render.md  (24 lines, 1080 chars)
HIGH   MDX-EVENT-HANDLER    line 5 col 1  Inline event handler attribute 'onerror' on <img>
HIGH   MDX-SCRIPT           line 7 col 1  Inline <script> element in rendered Markdown executes JavaScript
HIGH   MDX-JS-URL           line 9 col 1  Markdown link destination uses a javascript: URL
HIGH   MDX-JS-URL           line 11 col 1  href attribute uses a javascript:/vbscript: URL
HIGH   MDX-FRAME            line 13 col 1  <iframe> is an active content container
HIGH   MDX-SVG              line 15 col 1  <svg> can carry active content (script, onload)
HIGH   MDX-EVENT-HANDLER    line 15 col 1  Inline event handler attribute 'onload' on <svg>
summary: 7 finding(s): 7 high, 0 medium, 0 low
```

The fenced code block in the example contains the same payloads **as
documentation**; it is not flagged and `clean` leaves it byte-for-byte. After
`clean`, the whole file scans clean:

```console
$ python -m mdxss_guard clean examples/poisoned_render.md -o cleaned.md
wrote cleaned.md (mode=strip, findings before=7, after=0)
$ python -m mdxss_guard scan cleaned.md --fail-on low
PASS: no finding at or above severity 'low'
```

## Why this matters

| Carrier | Example | Why it is dangerous in a chat UI |
| --- | --- | --- |
| Inline event handler | `<img src=x onerror="...">` | executes on load/error without a click; classic transcript-injection sink |
| `<script>` / `<iframe>` / `<object>` | `<script>...</script>` | direct JavaScript execution or embedded attacker page |
| `javascript:` / `vbscript:` URL | `[x](javascript:alert(1))` | executes when the user clicks a link in the rendered answer |
| `data:` URL | `<img src="data:text/html;base64,...">` | bypasses naive URL allowlists; `data:text/html`/SVG execute |
| SVG / MathML | `<svg onload=...>` | active content hidden in a "vector image" |
| Raw HTML outside the allowlist | `<div onclick=...>` | sanitizer-bypass surface and UI spoofing |

Public prior art: OWASP Cross Site Scripting, the DOMPurify project (why
mutation-XSS is hard), and the long history of Markdown/HTML injection in chat
and issue trackers. This project adds a small, dependency-free linter and an
allowlist sanitizer for the specific "LLM output rendered as Markdown" pipeline.

## Install

```bash
git clone https://github.com/Qin-z-x/llm-markdown-xss-guard.git
cd llm-markdown-xss-guard
python -m pip install -e .        # optional: installs the mdxss-guard CLI
```

No runtime dependencies. Python 3.10+.

## CLI

```text
python -m mdxss_guard scan   <file|-> [--json] [--fail-on {low,medium,high}]
python -m mdxss_guard clean  <file|-> [--mode {strip,escape}] [--json] [-o OUT]
python -m mdxss_guard report <file|-> [--json]
```

| Exit code | Meaning |
| --- | --- |
| `0` | success; for `scan`, no finding at or above `--fail-on` |
| `1` | `scan --fail-on` threshold reached (CI gate) |
| `2` | usage error, missing file, invalid UTF-8 or internal failure |

Examples:

```bash
# CI gate: fail a content pipeline that renders untrusted model output
python -m mdxss_guard scan model_answer.md --fail-on high

# Machine-readable report with a fix suggestion per finding
python -m mdxss_guard scan model_answer.md --json

# Strict allowlist sanitizer (code blocks untouched)
python -m mdxss_guard clean model_answer.md -o model_answer.safe.md

# Escape every non-code HTML construct to visible text
python -m mdxss_guard clean model_answer.md --mode escape
```

## Rules

| Rule | Severity | Detects |
| --- | --- | --- |
| `MDX-SCRIPT` | high | `<script>` elements |
| `MDX-FRAME` | high | `iframe` / `object` / `embed` / `frame` / `frameset` / `applet` |
| `MDX-EVENT-HANDLER` | high | any inline `on*=` attribute |
| `MDX-JS-URL` | high | `javascript:` / `vbscript:` in HTML URL attributes and Markdown links (including entity-encoded forms) |
| `MDX-DATA-URL` | high / medium | `data:` URLs in URL attributes (`text/html`, SVG and XML are high) |
| `MDX-SVG` | high | `svg` / `math` elements (active-content vectors) |
| `MDX-SRCDOC` | high | `srcdoc` attribute |
| `MDX-DANGEROUS-TAG` | medium | `style` / `link` / `meta` / `base` / `form` |
| `MDX-RAW-HTML` | low | raw HTML tag outside the allowlist (signal that the UI permits raw HTML) |
| `MDX-ATTR` | low | attribute outside the allowlist |

Fenced code blocks and inline code are **data**: the scanner ignores them and
`clean` keeps them exactly as written. This is tested explicitly, because
security documentation legitimately contains XSS payloads.

## Python API

```python
from mdxss_guard import clean, report, scan

findings = scan(untrusted_markdown)       # list[Finding], deterministic order
report(untrusted_markdown)                # dict: summary + findings + fixes
safe = clean(untrusted_markdown)          # allowlist sanitizer, code untouched
visible = clean(untrusted_markdown, "escape")
```

`Finding` fields: `code`, `severity`, `message`, `line`, `column`, `data`;
`to_dict()` also includes a concrete `fix` suggestion.

## Demo and evidence

* [`docs/demo_chat.html`](docs/demo_chat.html) renders a poisoned model answer
  with raw HTML enabled: the harmless `<img onerror>` and `<script>` payloads
  really execute (they set a visible marker in the page).
* [`docs/demo_clean.html`](docs/demo_clean.html) renders the same answer after
  `clean`: no marker, no handler, no script.
* Both pages are generated deterministically by `python scripts/build_demo.py`.
* `python scripts/browser_check.py` renders both pages in headless Microsoft Edge
  and records whether the marker reached the DOM (see `docs/screenshots/terminal_browser.txt`).
* Real CLI runs, hashes and the test output: [`docs/EVIDENCE.md`](docs/EVIDENCE.md).
* Console captures for video use: [`docs/screenshots/`](docs/screenshots/) and
  [`docs/video_assets.md`](docs/video_assets.md).

## Tests and CI

```bash
python scripts/check_core_deps.py          # stdlib-only core check
python -m unittest discover -s tests -t .  # 38 tests
python scripts/build_demo.py               # regenerate docs/demo*.html
python scripts/capture_evidence.py         # regenerate docs/EVIDENCE.md + captures
```

CI (`.github/workflows/ci.yml`) runs on GitHub Actions for Python 3.10 and 3.12:
stdlib-only check, the unit tests, a JSON smoke test, sanitize-then-rescan, a
code-block preservation check and both expected outcomes of the `--fail-on high` gate.

## Honest scope and limits

* This is a **defence-in-depth linter and sanitizer**, not a guarantee. It does
  not disclose a new vulnerability and does not claim a new CVE; XSS is public
  prior art.
* Detection is heuristic and renderer-dependent. A UI that never renders raw
  HTML has much smaller exposure; a different Markdown renderer may allow
  constructs this tool does not model.
* Mutation-XSS and DOM-clobbering gadgets are out of scope: the sanitizer works
  on the HTML/Markdown text, not on a live DOM.
* The allowlist is intentionally strict; benign tags outside it are escaped
  (visible as text). That trade-off is documented in
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
* Pair this with a Content-Security-Policy and a battle-tested DOM sanitizer in
  the rendering layer. Do not use it to build attacks; the demo only writes a
  harmless DOM marker.

## Suggested GitHub topics

`security`, `llm`, `xss`, `markdown`, `sanitizer`, `prompt-injection`, `python`,
`cli`, `ai-safety`, `web-security`

## 中文简介

**llm-markdown-xss-guard** 用于检测与清理“大模型 Markdown 输出被渲染时”的 XSS 载体：
`<script>` / `<iframe>` / `onerror` 等事件属性、`javascript:` / `data:` URL、SVG/MathML
活动内容以及白名单之外的原始 HTML。核心库**仅使用 Python 标准库**，提供
`scan` / `clean` / `report` 三个 API 和同名 CLI，支持 `--json` 与 `--fail-on` CI 门禁
（发现高危时退出码为 1）。代码块（fenced/inline code）被视为数据：扫描器不误报，
清理器逐字节保留——安全文档里出现 payload 示例不会被误伤。

可复现演示：`python scripts/build_demo.py` 生成 `docs/demo_chat.html`（未清理，注入的
`<img onerror>` 会真实执行并写入无害标记）与 `docs/demo_clean.html`（清理后不再执行）；
无头 Edge 检查见 `docs/screenshots/terminal_browser.txt`。真实输出与哈希见
[`docs/EVIDENCE.md`](docs/EVIDENCE.md)。本项目是防御工具与本地演示，不声称发现新漏洞或新 CVE。
## License

MIT -- see [LICENSE](LICENSE). Prior art acknowledged: OWASP XSS prevention, DOMPurify, and public
Markdown/HTML injection reports in chat and issue-tracker UIs.
