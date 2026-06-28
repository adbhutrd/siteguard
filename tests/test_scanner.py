"""Tests for SiteGuard security scanner."""

import pytest
from unittest.mock import patch, MagicMock
from siteguard.scanner import SecurityScanner, ScanResult, ScanSummary


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_severity_colors(self):
        """Severity colors should return valid strings."""
        r = ScanResult(
            check_name="test", category="ssl", severity="critical",
            title="Test", description="Test", remediation="Fix", passed=False,
        )
        assert r.severity_color() == "red"

        r2 = ScanResult(
            check_name="test", category="ssl", severity="info",
            title="Test", description="Test", remediation="", passed=True,
        )
        assert r2.severity_color() == "green"


class TestScanSummary:
    """Test ScanSummary scoring."""

    def test_all_passed_is_a_plus(self):
        """All passing should give A+."""
        summary = ScanSummary(target="example.com", scan_time="test")
        summary.results = [
            ScanResult("t1", "ssl", "info", "OK", "", "", True),
            ScanResult("t2", "headers", "info", "OK", "", "", True),
            ScanResult("t3", "owasp", "info", "OK", "", "", True),
            ScanResult("t4", "exposed", "info", "OK", "", "", True),
        ]
        summary.calculate_score()
        assert summary.grade == "A+"
        assert summary.score == "100/100"

    def test_all_failed_is_f(self):
        """All failing should give F."""
        summary = ScanSummary(target="example.com", scan_time="test")
        summary.results = [
            ScanResult("t1", "ssl", "critical", "Fail", "", "Fix", False),
            ScanResult("t2", "headers", "high", "Fail", "", "Fix", False),
        ]
        summary.calculate_score()
        assert summary.grade == "F"
        assert summary.passed == 0

    def test_mixed_gives_b(self):
        """75% pass should give B."""
        summary = ScanSummary(target="example.com", scan_time="test")
        summary.results = [
            ScanResult("t1", "", "", "", "", "", True),
            ScanResult("t2", "", "", "", "", "", True),
            ScanResult("t3", "", "", "", "", "", True),
            ScanResult("t4", "", "", "", "", "", False),
        ]
        summary.calculate_score()
        assert summary.grade == "B"


class TestSecurityScanner:
    """Test SecurityScanner initialization."""

    def test_normalize_domain(self):
        """Should normalize domain from URL."""
        scanner = SecurityScanner("https://example.com/path")
        assert scanner.domain == "example.com"
        assert scanner.base_url == "https://example.com"

    def test_bare_domain(self):
        """Should handle bare domain."""
        scanner = SecurityScanner("example.com")
        assert scanner.domain == "example.com"
        assert scanner.base_url == "https://example.com"

    def test_default_checks(self):
        """Default should include all check categories."""
        scanner = SecurityScanner("example.com")
        assert "ssl" in scanner.checks_to_run
        assert "headers" in scanner.checks_to_run
        assert "owasp" in scanner.checks_to_run
        assert "exposed" in scanner.checks_to_run

    def test_custom_checks(self):
        """Should respect custom check list."""
        scanner = SecurityScanner("example.com", checks=["ssl", "owasp"])
        assert scanner.checks_to_run == ["ssl", "owasp"]
        assert "headers" not in scanner.checks_to_run


class TestCLI:
    """Test CLI entry point."""

    def test_help_command(self):
        """CLI should accept --help."""
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "siteguard.cli", "scan", "--help"],
            capture_output=True, text=True, timeout=10,
            cwd=str(__import__("pathlib").Path(__file__).parent.parent)
        )
        assert result.returncode == 0
        assert "scan" in result.stdout.lower()

    def test_version(self):
        """CLI should show version."""
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "siteguard.cli", "version"],
            capture_output=True, text=True, timeout=10,
            cwd=str(__import__("pathlib").Path(__file__).parent.parent)
        )
        assert "1.0.0" in result.stdout
