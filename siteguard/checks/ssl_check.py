"""SSL/TLS security checker for SiteGuard."""

import ssl
import socket
from siteguard.scanner import ScanResult


class SSLChecker:
    """Check SSL/TLS configuration for security issues."""

    def __init__(self, base_url: str, domain: str):
        self.base_url = base_url
        self.domain = domain

    def run_all(self) -> list[ScanResult]:
        """Run all SSL/TLS checks."""
        results = []

        # Check if HTTPS works
        results.append(self._check_https_available())

        # Check certificate validity
        cert_info = self._get_certificate_info()
        if cert_info:
            results.append(self._check_cert_expiry(cert_info))
            results.append(self._check_tls_version(cert_info))
        else:
            results.append(ScanResult(
                check_name="ssl_certificate",
                category="ssl",
                severity="critical",
                title="SSL Certificate Unavailable",
                description="Could not retrieve SSL certificate. The site may not support HTTPS.",
                remediation="Install a valid SSL/TLS certificate. Use Let's Encrypt for a free certificate.",
                passed=False,
                evidence="Connection failed or timed out"
            ))

        # HSTS check (done in headers, skip here)

        return results

    def _check_https_available(self) -> ScanResult:
        """Check if HTTPS is available."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        return ScanResult(
                            check_name="https_available",
                            category="ssl",
                            severity="info",
                            title="HTTPS Available",
                            description="HTTPS is properly configured and a valid SSL certificate is present.",
                            remediation="",
                            passed=True,
                            evidence=f"Certificate issued to {cert.get('subject', 'N/A')}"
                        )
        except Exception as e:
            return ScanResult(
                check_name="https_available",
                category="ssl",
                severity="critical",
                title="HTTPS Not Available",
                description=f"Could not establish HTTPS connection. Error: {str(e)[:100]}",
                remediation="Enable HTTPS on your server. Use Let's Encrypt for a free SSL certificate.",
                passed=False,
                evidence=str(e)[:200]
            )
        return ScanResult(
            check_name="https_available",
            category="ssl",
            severity="critical",
            title="HTTPS Not Available",
            description="Site does not support HTTPS connections.",
            remediation="Enable HTTPS immediately. All websites should use HTTPS.",
            passed=False,
        )

    def _get_certificate_info(self) -> dict | None:
        """Get SSL certificate details."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    return ssock.getpeercert()
        except Exception:
            return None

    def _check_cert_expiry(self, cert_info: dict) -> ScanResult:
        """Check if certificate is about to expire."""
        import datetime
        not_after = cert_info.get("notAfter", "")
        if not not_after:
            return ScanResult(
                check_name="cert_expiry",
                category="ssl",
                severity="medium",
                title="Certificate Expiry Unknown",
                description="Could not determine certificate expiration date.",
                remediation="Verify your SSL certificate has not expired.",
                passed=False,
            )

        # Parse the date
        try:
            # Format: 'Jun 28 12:00:00 2026 GMT'
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days

            if days_left < 0:
                return ScanResult(
                    check_name="cert_expiry",
                    category="ssl",
                    severity="critical",
                    title="SSL Certificate EXPIRED",
                    description=f"Certificate expired {abs(days_left)} days ago on {not_after}",
                    remediation="Renew your SSL certificate immediately!",
                    passed=False,
                    evidence=f"Expired: {not_after}"
                )
            elif days_left < 30:
                return ScanResult(
                    check_name="cert_expiry",
                    category="ssl",
                    severity="high",
                    title=f"SSL Certificate Expires Soon ({days_left} days)",
                    description=f"Certificate expires in {days_left} days on {not_after}.",
                    remediation="Renew your SSL certificate now to avoid downtime.",
                    passed=False,
                    evidence=f"Expires: {not_after} ({days_left} days)"
                )
            else:
                return ScanResult(
                    check_name="cert_expiry",
                    category="ssl",
                    severity="info",
                    title=f"Certificate Valid ({days_left} days remaining)",
                    description=f"SSL certificate is valid and expires in {days_left} days.",
                    remediation="",
                    passed=True,
                    evidence=f"Expires: {not_after}"
                )
        except Exception:
            return ScanResult(
                check_name="cert_expiry",
                category="ssl",
                severity="medium",
                title="Certificate Expiry Parse Error",
                description=f"Could not parse certificate expiry: {not_after}",
                remediation="Check your SSL certificate validity manually.",
                passed=False,
            )

    def _check_tls_version(self, cert_info: dict) -> ScanResult:
        """Check TLS version support (basic check)."""
        try:
            ctx = ssl.create_default_context()
            # Try TLS 1.2+
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain):
                    return ScanResult(
                        check_name="tls_version",
                        category="ssl",
                        severity="info",
                        title="TLS 1.2+ Supported",
                        description="Server supports TLS 1.2 or higher, which is currently secure.",
                        remediation="",
                        passed=True,
                        evidence="TLS 1.2+ connection successful"
                    )
        except Exception:
            return ScanResult(
                check_name="tls_version",
                category="ssl",
                severity="critical",
                title="TLS Version Outdated",
                description="Server may not support TLS 1.2+. Older TLS versions (1.0, 1.1) are vulnerable.",
                remediation="Configure your server to support only TLS 1.2 and TLS 1.3. Disable TLS 1.0 and 1.1.",
                passed=False,
            )
