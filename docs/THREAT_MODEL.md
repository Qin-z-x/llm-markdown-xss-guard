# Threat model: XSS in rendered LLM Markdown output

## Honesty statement

This project is a **defensive detection and sanitization tool plus a local
demonstration**. It does not disclose a new vulnerability, does not claim a new
CVE, and does not assert that any particular chat product is vulnerable. XSS in
rendered Markdown and permissive HTML sanitizers is long-standing public prior
art (OWASP, DOMPurify issue history, public chat/issue-tracker injection reports).
The demo payload only writes a marker into the page DOM; it does not read cookies
and does not make network requests.

## 1. Where the injection enters

An LLM application typically renders the model answer as Markdown. Untrusted text
that can reach that answer includes:

* the model's own output (jailbroken, prompt-injected or simply quoting a payload);
* retrieved RAG documents, web pages, tool results and MCP server output that the
  model paraphrases or copies verbatim;
* user messages echoed back in "quote and answer" UIs;
* model-generated code blocks that a UI previews as rendered HTML.

The rendering layer is the sink. If it accepts raw HTML (or allows values outside
a strict allowlist), model output becomes executable content in the user's
browser. The user only sees a normal chat answer.

## 2. Carrier classes covered

| Class | Example | Why it executes |
| --- | --- | --- |
| `<script>` | `<script>fetch(...)</script>` | direct JavaScript execution |
| Event handlers | `<img src=x onerror=...>` | runs on load/error with no user click |
| Active containers | `<iframe srcdoc=...>`, `<object>`, `<embed>` | embeds attacker-controlled pages/plugins |
| `javascript:`/`vbscript:` URLs | `[click](javascript:...)`, `<a href=...>` | executes on click |
| `data:` URLs | `<img src="data:text/html;base64,...">` | bypasses scheme allowlists; HTML/SVG payloads execute |
| SVG / MathML | `<svg onload=...>` | active content behind an image-like syntax |
| Raw HTML | `<div onclick=...>`, `<form>` | sanitizer-bypass and UI-spoofing surface |

Severity mapping: anything that can execute without a further user gesture
(script, event handler) or that directly creates an execution context (iframe,
SVG, data:text/html, srcdoc) is **high**. Active tags that only sometimes execute
(`data:` image URLs, `<style>`/`<link>`/`<base>`) are **high** or **medium** as
documented in the README rule table. Signals that the renderer permits raw HTML
at all (`<div>`, unknown attributes) are **low**: they are not an exploit by
themselves, but they widen the attack surface and are exactly what a strict
allowlist should neutralize.

## 3. The sanitizer decision model

`clean` splits the document into code and non-code segments. Code segments are
left byte-for-byte untouched. Non-code segments get one of two passes:

* `strip` (default): complete `<script>` and active-container blocks are removed;
  individual blocked tags are replaced by a visible `[tag removed]` marker;
  allowed tags are rebuilt from an attribute allowlist (and unsafe URL values are
  dropped entirely); raw tags outside the allowlist are escaped to text; Markdown
  link destinations with `javascript:`/`vbscript:`/`data:` are neutralized.
* `escape`: every `<`, `>` and `&` outside code is escaped so the model output is
  shown as literal text; dangerous Markdown link schemes are neutralized.

The output of `strip` is checked with `scan` in tests and in the gate run: it must
produce zero findings, including at the strictest `--fail-on low` level.

## 4. What this does not claim

* Not a browser sandbox and not a full HTML sanitizer. Mutation-XSS, DOM
  clobbering, CSS-based exfiltration and browser-specific parser quirks are out of
  scope; use a maintained DOM sanitizer (e.g. DOMPurify) plus CSP in the UI.
* Detection is heuristic: custom encodings, unusual renderer extensions and
  Markdown dialects not modelled here can evade it.
* The tool does not decide whether a given product is vulnerable. Whether raw
  HTML is rendered at all is an application design decision.
* No new CVE and no coordinated disclosure process: this is a general hardening
  helper for the "LLM output -> Markdown -> browser" pipeline.

## 5. Limitations, explicitly

* Fenced code and single-backtick inline code are treated as data. Multi-backtick
  inline code and unusual fence syntaxes are approximated; verify against your
  renderer.
* `strip` is deliberately strict: allowed tags outside the allowlist become
  visible escaped text. This is a usability trade-off chosen for safety.
* Entity-encoded attribute values are decoded before the scheme check, but novel
  encoding tricks are an arms race; the allowlist is the primary control.
* The scanner reports, it does not block. Wire it into CI or a content pipeline
  with `--fail-on`.
* The demo intentionally includes real-looking payloads as documentation in its
  fenced code block; they do not execute there. Run the demo locally only.

## 6. Prior art

* OWASP Cross Site Scripting Prevention Cheat Sheet and the OWASP XSS Filter
  Evasion Cheat Sheet.
* DOMPurify (Cure53) and its issue history, which documents why HTML sanitizers
  are hard (mutation-XSS, namespace confusion).
* Public reports of Markdown/HTML injection in chat and issue-tracker UIs.
* General LLM prompt-injection and indirect-injection literature (the upstream
  source of hostile text in model answers).
