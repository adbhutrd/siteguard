"""
SiteGuard — Free Website Security Scanner
===========================================

One command to scan any website for security vulnerabilities.
Built for small businesses who can't afford expensive audits.

Usage:
    >>> from siteguard import scan
    >>> results = scan("example.com")
    >>> print(results.summary())

CLI:
    $ siteguard scan example.com
    $ siteguard scan example.com --output report.html
    $ siteguard scan example.com --check ssl,headers,owasp
"""

__version__ = "1.0.0"
__author__ = "Enish Shah"
__license__ = "MIT"

from siteguard.scanner import SecurityScanner, ScanResult

__all__ = ["SecurityScanner", "ScanResult", "__version__"]
