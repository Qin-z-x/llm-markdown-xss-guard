"""mdxss-guard: detect and sanitize XSS carriers in rendered LLM Markdown."""

from .core import ALLOWED_TAGS, FIXES, Finding, VERSION, clean, report, scan, summarize

__version__ = VERSION
__all__ = ["ALLOWED_TAGS", "FIXES", "Finding", "VERSION", "clean", "report", "scan", "summarize", "__version__"]
