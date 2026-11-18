"""Snippet Scanner - a lightweight OWASP Top 10 (2021) pattern scanner."""

from .scanner import scan_content

__version__ = "2.0.0"
__all__ = ["scan_content", "__version__"]
