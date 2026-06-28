#!/usr/bin/env python3
"""
SiteGuard CLI — Free Website Security Scanner
===============================================

One command to scan any website for security vulnerabilities.

Usage:
    siteguard scan example.com
    siteguard scan https://example.com --output report.html
    siteguard scan example.com --check ssl,headers
"""

import sys
import argparse
import logging
from pathlib import Path

# Ensure package is importable when running as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from siteguard.scanner import SecurityScanner, ScanSummary
from siteguard.reporter import generate_terminal_report, generate_html_report


def main():
    parser = argparse.ArgumentParser(
        description="SiteGuard — Free Website Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  siteguard scan example.com                    Full scan, terminal output
  siteguard scan https://mysite.com -o rpt.html Full scan, save HTML report
  siteguard scan example.com --check ssl         SSL/TLS only
  siteguard scan example.com --check headers     Security headers only
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a website")
    scan_parser.add_argument("target", help="Domain or URL to scan (e.g., example.com)")
    scan_parser.add_argument(
        "--check", "-c",
        help="Checks to run: ssl,headers,owasp,exposed (comma-separated, default: all)",
        default="ssl,headers,owasp,exposed",
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Save HTML report to file (e.g., report.html)",
        default=None,
    )
    scan_parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Show only the score, no detailed output",
    )

    # version command
    subparsers.add_parser("version", help="Show version")

    args = parser.parse_args()

    if args.command == "version":
        from siteguard import __version__
        print(f"SiteGuard v{__version__}")
        return

    if args.command != "scan":
        parser.print_help()
        return

    # Parse checks
    checks = [c.strip() for c in args.check.split(",")]

    print(f"\n🔍 SiteGuard v1.0.0 — Scanning {args.target}...\n")

    # Run scanner
    scanner = SecurityScanner(args.target, checks=checks)
    summary = scanner.run_all()

    # Print terminal report
    if not args.quiet:
        print(generate_terminal_report(summary))

    # Save HTML report
    if args.output:
        html = generate_html_report(summary)
        output_path = Path(args.output)
        output_path.write_text(html)
        print(f"📄 HTML report saved to: {output_path.absolute()}")
    elif not args.quiet:
        print(f"💡 Tip: Use --output report.html to save a detailed HTML report")

    # Exit with appropriate code
    if summary.failed > 0 and summary.grade in ("D", "F"):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
