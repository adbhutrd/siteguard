#!/usr/bin/env python3
"""
SiteGuard Core Scanner
=======================
Orchestrates all security checks and produces results.
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("siteguard")


@dataclass
class ScanResult:
    """Result from a single security check."""
    check_name: str
    category: str  # ssl, headers, owasp, exposed
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    remediation: str
    passed: bool = False
    evidence: str = ""

    def severity_color(self) -> str:
        colors = {
            "critical": "red",
            "high": "orange",
            "medium": "yellow",
            "low": "blue",
            "info": "green",
        }
        return colors.get(self.severity, "white")


@dataclass
class ScanSummary:
    """Complete scan summary."""
    target: str
    scan_time: str
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    results: list = field(default_factory=list)
    score: str = "N/A"
    grade: str = "N/A"

    def calculate_score(self):
        """Calculate security score from A+ to F."""
        self.total_checks = len(self.results)
        self.passed = sum(1 for r in self.results if r.passed)
        self.failed = self.total_checks - self.passed

        if self.total_checks == 0:
            self.score = "0/100"
            self.grade = "N/A"
            return

        pct = (self.passed / self.total_checks) * 100
        self.score = f"{int(pct)}/100"

        if pct >= 95:
            self.grade = "A+"
        elif pct >= 85:
            self.grade = "A"
        elif pct >= 75:
            self.grade = "B"
        elif pct >= 65:
            self.grade = "C"
        elif pct >= 50:
            self.grade = "D"
        else:
            self.grade = "F"


class SecurityScanner:
    """Main security scanner that orchestrates all checks.

    Usage:
        scanner = SecurityScanner("example.com")
        results = scanner.run_all()
    """

    def __init__(self, target: str, checks: Optional[list] = None):
        """Initialize scanner for a target domain.

        Args:
            target: Domain to scan (e.g., example.com or https://example.com)
            checks: Optional list of check categories to run
        """
        # Normalize target
        target = target.strip().lower()
        parsed = urlparse(target)
        if parsed.netloc:
            self.domain = parsed.netloc
            self.base_url = target.rstrip("/")
        else:
            self.domain = target
            self.base_url = f"https://{target}"

        self.checks_to_run = checks or ["ssl", "headers", "owasp", "exposed"]
        self.results: list[ScanResult] = []

    def run_all(self) -> ScanSummary:
        """Run all enabled security checks.

        Returns:
            ScanSummary with complete results and score.
        """
        start_time = time.time()
        logger.info(f"🔍 Starting SiteGuard scan for: {self.domain}")

        summary = ScanSummary(
            target=self.domain,
            scan_time=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            results=self.results,
        )

        # SSL/TLS checks
        if "ssl" in self.checks_to_run:
            logger.info("  🔒 Checking SSL/TLS...")
            from siteguard.checks.ssl_check import SSLChecker
            ssl_checker = SSLChecker(self.base_url, self.domain)
            self.results.extend(ssl_checker.run_all())

        # Security headers
        if "headers" in self.checks_to_run:
            logger.info("  📋 Checking security headers...")
            from siteguard.checks.headers_check import HeaderChecker
            header_checker = HeaderChecker(self.base_url, self.domain)
            self.results.extend(header_checker.run_all())

        # OWASP Top 10 surface checks
        if "owasp" in self.checks_to_run:
            logger.info("  🛡️ Checking OWASP Top 10...")
            from siteguard.checks.owasp_check import OWASPChecker
            owasp_checker = OWASPChecker(self.base_url, self.domain)
            self.results.extend(owasp_checker.run_all())

        # Exposed files/directories
        if "exposed" in self.checks_to_run:
            logger.info("  📁 Checking exposed files...")
            from siteguard.checks.exposed_check import ExposedChecker
            exposed_checker = ExposedChecker(self.base_url, self.domain)
            self.results.extend(exposed_checker.run_all())

        summary.calculate_score()
        elapsed = time.time() - start_time
        logger.info(f"✅ Scan complete in {elapsed:.1f}s — Grade: {summary.grade} ({summary.score})")

        return summary
