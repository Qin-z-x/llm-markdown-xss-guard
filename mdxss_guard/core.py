"""mdxss_guard core: detect and sanitize XSS-bearing HTML inside Markdown.

Rendered LLM output is Markdown, and many chat UIs render raw HTML or pass it
through a permissive sanitizer. This module implements:

* ``scan``   -- rule-based detection of XSS carriers outside code;
* ``clean``  -- an allowlist sanitizer (``strip``) or full escaping (``escape``);
* ``report`` -- machine-readable findings with concrete fixes.

Fenced code blocks and inline code are data: the scanner ignores them and the
sanitizer leaves them byte-for-byte untouched.
"""

from __future__ import annotations

import html as _html
import re
from bisect import bisect_right
from dataclasses import dataclass, field

VERSION = "0.1.0"

SEVERITIES = ("low", "medium", "high")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES, start=1)}

ALLOWED_TAGS = frozenset(
    {
        "a", "b", "blockquote", "br", "code", "del", "em", "h1", "h2", "h3", "h4", "h5", "h6",
        "hr", "i", "img", "ins", "kbd", "li", "ol", "p", "pre", "s", "strong", "sub", "sup",
        "table", "tbody", "td", "th", "thead", "tr", "u", "ul",
    }
)
ALLOWED_ATTRS = frozenset({"alt", "class", "href", "id", "src", "title"})
URL_ATTRS = frozenset({"href", "src"})
EXTRA_URL_ATTRS = frozenset({"action", "background", "formaction", "poster", "xlink:href"})
BLOCKED_CONTAINERS = frozenset({"applet", "embed", "frame", "frameset", "iframe", "object"})
BLOCKED_TAGS = BLOCKED_CONTAINERS | frozenset({"base", "form", "link", "math", "meta", "script", "style", "svg"})
ACTIVE_TAGS = frozenset({"math", "svg"})

TAG_RE = re.compile(r"<(/)?([A-Za-z][A-Za-z0-9:-]*)((?:\s+[^<>]*?)?)(/?)>")
ATTR_RE = re.compile(r"""([A-Za-z_:][A-Za-z0-9_:.\-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?""")
EVENT_ATTR_RE = re.compile(r"(?i)\bon[a-z]{3,20}\s*=")
SCRIPT_BLOCK_RE = re.compile(r"(?is)<script\b[^>]*>.*?</script\s*>")
SCRIPT_OPEN_RE = re.compile(r"(?is)<script\b[^>]*>")
ACTIVE_CONTAINER_RE = re.compile(r"(?is)<(iframe|object|embed|frame|frameset|applet)\b[^>]*>.*?</\1\s*>")
INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
MD_LINK_RE = re.compile(r"(?i)\]\s*\(\s*(javascript|vbscript|data)\s*:")
MD_REF_LINK_RE = re.compile(r"(?im)^(\s*\[[^\]]+\]:\s*)(javascript|vbscript|data)\s*:")
DANGEROUS_SCHEME_RE = re.compile(r"^(?:javascript|vbscript)\s*:")
DATA_URL_RE = re.compile(r"^data:")

FIXES = {
    "MDX-SCRIPT": "Remove the <script> element or render the answer as text in a sandboxed frame; never insert model output with innerHTML.",
    "MDX-FRAME": "Drop active containers (iframe/object/embed/frame/applet); use a vetted embed component with a URL allowlist instead.",
    "MDX-DANGEROUS-TAG": "Remove <style>/<link>/<meta>/<base>/<form> from rendered output; put styling and metadata in the application, not the model answer.",
    "MDX-SVG": "Render SVG as an image through a dedicated sanitizer or strip it; SVG and MathML can carry script and event handlers.",
    "MDX-EVENT-HANDLER": "Strip every on* attribute and attach behaviour in application code, never through model-supplied HTML.",
    "MDX-JS-URL": "Allow only http(s):, mailto: and relative URLs; reject javascript:, vbscript: and data: link destinations.",
    "MDX-DATA-URL": "Block data: URLs (data:text/html and SVG data URLs execute script); serve images from a trusted origin instead.",
    "MDX-SRCDOC": "Drop the srcdoc attribute; it embeds a full HTML document that bypasses attribute sanitizers.",
    "MDX-RAW-HTML": "Either render Markdown with HTML disabled or run it through a strict allowlist sanitizer before insertion.",
    "MDX-ATTR": "Keep an attribute allowlist (href/src/alt/title/class/id) and drop everything else.",
}

__all__ = ["Finding", "scan", "clean", "report", "summarize", "split_markdown", "ALLOWED_TAGS", "FIXES", "VERSION"]


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    line: int = 1
    column: int = 1
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "fix": FIXES.get(self.code, ""),
            "data": self.data,
        }


def split_markdown(text: str) -> list:
    """Split Markdown into (is_code, chunk) segments; code is fenced or inline code."""
    segments = []
    buffer = []
    fence = None
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if fence is None and len(stripped) >= 3 and stripped[:3] in ("```", "~~~"):
            if buffer:
                segments.append((False, "".join(buffer)))
                buffer = []
            fence = stripped[:3]
            buffer.append(line)
            continue
        if fence is not None:
            buffer.append(line)
            if stripped.startswith(fence):
                segments.append((True, "".join(buffer)))
                buffer = []
                fence = None
            continue
        buffer.append(line)
    if buffer:
        segments.append((fence is not None, "".join(buffer)))
    result = []
    for is_code, chunk in segments:
        if is_code:
            result.append((True, chunk))
            continue
        position = 0
        for match in INLINE_CODE_RE.finditer(chunk):
            if match.start() > position:
                result.append((False, chunk[position:match.start()]))
            result.append((True, match.group(0)))
            position = match.end()
        if position < len(chunk):
            result.append((False, chunk[position:]))
    return result


def _mask_code(text: str) -> str:
    out = []
    for is_code, chunk in split_markdown(text):
        if is_code:
            out.append(re.sub(r"[^\n]", " ", chunk))
        else:
            out.append(chunk)
    return "".join(out)


def _line_starts(text: str) -> list:
    starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            starts.append(index + 1)
    return starts


def _line_col(starts: list, offset: int) -> tuple:
    line_index = bisect_right(starts, offset) - 1
    return line_index + 1, offset - starts[line_index] + 1


def _is_unsafe_url(lowered: str) -> bool:
    return bool(DANGEROUS_SCHEME_RE.match(lowered) or DATA_URL_RE.match(lowered))


def scan(text: str) -> list:
    """Return findings for XSS carriers in non-code Markdown, sorted by position."""
    masked = _mask_code(text)
    starts = _line_starts(text)
    findings = []

    def add(code: str, severity: str, message: str, offset: int, data: dict = None) -> None:
        line, column = _line_col(starts, offset)
        findings.append(Finding(code=code, severity=severity, message=message, line=line, column=column, data=data or {}))

    for match in SCRIPT_OPEN_RE.finditer(masked):
        add("MDX-SCRIPT", "high", "Inline <script> element in rendered Markdown executes JavaScript", match.start())
    for match in MD_LINK_RE.finditer(masked):
        add("MDX-JS-URL", "high", "Markdown link destination uses a %s: URL" % match.group(1).lower(), match.start())
    for match in MD_REF_LINK_RE.finditer(masked):
        add("MDX-JS-URL", "high", "Markdown reference link definition uses a %s: URL" % match.group(2).lower(), match.start())

    for match in TAG_RE.finditer(masked):
        closing, name, attrs, selfclose = match.groups()
        lowered_name = name.lower()
        if lowered_name == "script":
            continue
        if not closing:
            if lowered_name in BLOCKED_CONTAINERS:
                add("MDX-FRAME", "high", "<%s> is an active content container" % lowered_name, match.start())
            elif lowered_name in ("style", "link", "meta", "base", "form"):
                add("MDX-DANGEROUS-TAG", "medium", "<%s> is not in the rendering allowlist" % lowered_name, match.start())
            elif lowered_name in ACTIVE_TAGS:
                add("MDX-SVG", "high", "<%s> can carry active content (script, onload)" % lowered_name, match.start())
        if attrs:
            event_match = EVENT_ATTR_RE.search(attrs)
            if event_match:
                event_name = event_match.group(0).rstrip("= ").strip()
                add("MDX-EVENT-HANDLER", "high", "Inline event handler attribute %r on <%s>" % (event_name, lowered_name), match.start())
            for attr_match in ATTR_RE.finditer(attrs):
                attr_name = attr_match.group(1).lower()
                value = attr_match.group(2)
                if value is None:
                    value = attr_match.group(3)
                if value is None:
                    value = attr_match.group(4)
                if value is None:
                    continue
                decoded = _html.unescape(value).strip()
                lowered_value = decoded.lower()
                if attr_name in URL_ATTRS or attr_name in EXTRA_URL_ATTRS:
                    if DANGEROUS_SCHEME_RE.match(lowered_value):
                        add("MDX-JS-URL", "high", "%s attribute uses a javascript:/vbscript: URL" % attr_name, match.start())
                    elif DATA_URL_RE.match(lowered_value):
                        severe = "high" if ("text/html" in lowered_value or "svg" in lowered_value or "xml" in lowered_value) else "medium"
                        add("MDX-DATA-URL", severe, "%s attribute uses a data: URL" % attr_name, match.start())
                elif attr_name == "srcdoc":
                    add("MDX-SRCDOC", "high", "srcdoc embeds a full HTML document", match.start())
                elif attr_name not in ALLOWED_ATTRS and not attr_name.startswith("on"):
                    add("MDX-ATTR", "low", "Attribute %r is not in the rendering allowlist" % attr_name, match.start())
        if not closing and lowered_name not in ALLOWED_TAGS and lowered_name not in BLOCKED_TAGS:
            add("MDX-RAW-HTML", "low", "Raw HTML <%s> is outside the rendering allowlist" % lowered_name, match.start())

    findings.sort(key=lambda finding: (finding.line, finding.column, finding.code))
    return findings


def summarize(findings: list) -> dict:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    max_severity = "none"
    for severity in SEVERITIES:
        if counts[severity]:
            max_severity = severity
    return {"total": len(findings), "counts": counts, "max_severity": max_severity}


def report(text: str) -> dict:
    findings = scan(text)
    summary = summarize(findings)
    return {
        "tool": "mdxss-guard",
        "version": VERSION,
        "summary": summary,
        "clean": not findings,
        "findings": [finding.to_dict() for finding in findings],
    }


def _escape_html(chunk: str) -> str:
    return chunk.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _neutralize_md_links(chunk: str) -> str:
    chunk = MD_LINK_RE.sub("](blocked:", chunk)
    return re.sub(r"(?im)^(\s*\[[^\]]+\]:\s*)(?:javascript|vbscript|data)\s*:", r"\1blocked:", chunk)


def _sanitize_tag(match) -> str:
    closing, name, attrs, selfclose = match.groups()
    lowered_name = name.lower()
    if lowered_name in BLOCKED_TAGS:
        return "" if closing else "[%s removed]" % lowered_name
    if lowered_name not in ALLOWED_TAGS:
        return _html.escape(match.group(0), quote=False)
    if closing:
        return "</%s>" % lowered_name
    kept = []
    if attrs:
        for attr_match in ATTR_RE.finditer(attrs):
            attr_name = attr_match.group(1).lower()
            if attr_name not in ALLOWED_ATTRS:
                continue
            value = attr_match.group(2)
            if value is None:
                value = attr_match.group(3)
            if value is None:
                value = attr_match.group(4)
            if value is None:
                continue
            decoded = _html.unescape(value).strip()
            if attr_name in URL_ATTRS and _is_unsafe_url(decoded.lower()):
                continue
            kept.append('%s="%s"' % (attr_name, _html.escape(decoded, quote=True)))
    tail = " /" if selfclose else ""
    return "<%s%s%s>" % (lowered_name, ((" " + " ".join(kept)) if kept else ""), tail)


def _sanitize_chunk(chunk: str) -> str:
    chunk = _neutralize_md_links(chunk)
    chunk = SCRIPT_BLOCK_RE.sub("[script removed]", chunk)
    chunk = SCRIPT_OPEN_RE.sub("[script removed]", chunk)
    chunk = ACTIVE_CONTAINER_RE.sub("[active element removed]", chunk)
    return TAG_RE.sub(_sanitize_tag, chunk)


def clean(text: str, mode: str = "strip") -> str:
    """Sanitize Markdown while leaving fenced and inline code untouched.

    ``strip`` keeps allowlisted HTML and neutralizes everything else; ``escape``
    escapes all HTML outside code and also neutralizes Markdown links with
    dangerous schemes.
    """
    if mode not in ("strip", "escape"):
        raise ValueError("mode must be 'strip' or 'escape'")
    out = []
    for is_code, chunk in split_markdown(text):
        if is_code:
            out.append(chunk)
        elif mode == "escape":
            out.append(_neutralize_md_links(_escape_html(chunk)))
        else:
            out.append(_sanitize_chunk(chunk))
    return "".join(out)
