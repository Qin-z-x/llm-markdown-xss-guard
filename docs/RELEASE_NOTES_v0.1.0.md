## llm-markdown-xss-guard v0.1.0

Detect and sanitize XSS carriers in rendered LLM Markdown output, stdlib-only.

### Included

- `python -m mdxss_guard scan|clean|report` with `--json` and
  `--fail-on {low,medium,high}` CI gating (exit 0/1/2).
- Rules for `<script>`, active containers (`iframe`/`object`/`embed`/frame),
  inline `on*=` handlers, `javascript:`/`vbscript:`/`data:` URLs (including
  entity-encoded variants), SVG/MathML, raw HTML outside an allowlist and
  Markdown link destinations with dangerous schemes.
- Allowlist sanitizer (`clean --mode strip`) and full escaping (`--mode escape`).
  Fenced and inline code are data: the scanner ignores them and the sanitizer
  keeps them byte-for-byte.
- 38 unit tests, GitHub Actions CI on Python 3.10/3.12, captured evidence with
  real CLI runs, and a self-contained demo chat page where an injected
  `<img onerror>` really executes while the cleaned page does not.

### Honest notes

- This is a defensive linter/sanitizer and a local demonstration. It does not
  disclose a new vulnerability and does not claim a new CVE; XSS and Markdown
  rendering flaws are public prior art.
- Detection is heuristic and renderer-dependent: a UI that never renders raw
  HTML has a much smaller exposure, and a permissive sanitizer can reintroduce
  mutation-XSS. The sanitizer is a defence-in-depth layer, not a browser sandbox.
- The demo payload only writes a marker into the page DOM; no real exfiltration
  or cookie access is performed (that is why the call is visible in the page
  source as a harmless marker).
