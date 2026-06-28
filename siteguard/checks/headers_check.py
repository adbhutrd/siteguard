"""Security headers checker for SiteGuard."""

import requests
from siteguard.scanner import ScanResult


class HeaderChecker:
    """Check HTTP security headers for best practices."""

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "high",
            "title": "HSTS (HTTP Strict Transport Security)",
            "description": "Forces browsers to use HTTPS, preventing downgrade attacks.",
            "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        },
        "Content-Security-Policy": {
            "severity": "high",
            "title": "Content Security Policy (CSP)",
            "description": "Prevents XSS attacks by controlling which resources can be loaded.",
            "remediation": "Add a CSP header: Content-Security-Policy: default-src 'self'; script-src 'self'",
        },
        "X-Content-Type-Options": {
            "severity": "medium",
            "title": "X-Content-Type-Options",
            "description": "Prevents MIME type sniffing which can lead to XSS.",
            "remediation": "Add header: X-Content-Type-Options: nosniff",
        },
        "X-Frame-Options": {
            "severity": "medium",
            "title": "X-Frame-Options (Clickjacking Protection)",
            "description": "Prevents your site from being embedded in iframes on malicious sites.",
            "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
        },
        "X-XSS-Protection": {
            "severity": "low",
            "title": "X-XSS-Protection",
            "description": "Enables browser's built-in XSS filter (legacy, CSP is better).",
            "remediation": "Add header: X-XSS-Protection: 1; mode=block",
        },
        "Referrer-Policy": {
            "severity": "low",
            "title": "Referrer Policy",
            "description": "Controls how much referrer information is sent with requests.",
            "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "severity": "low",
            "title": "Permissions Policy",
            "description": "Controls which browser features/APIs can be used.",
            "remediation": "Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        },
        "Cross-Origin-Opener-Policy": {
            "severity": "low",
            "title": "Cross-Origin Opener Policy",
            "description": "Prevents cross-origin attacks by isolating browsing contexts.",
            "remediation": "Add header: Cross-Origin-Opener-Policy: same-origin",
        },
    }

    def __init__(self, base_url: str, domain: str):
        self.base_url = base_url
        self.domain = domain
        self.response_headers = {}

    def run_all(self) -> list[ScanResult]:
        """Run all security header checks."""
        results = []

        # Fetch headers
        try:
            resp = requests.get(
                self.base_url,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "SiteGuard/1.0 Security Scanner"},
                verify=True,
            )
            self.response_headers = {k.lower(): v for k, v in resp.headers.items()}
            results.append(ScanResult(
                check_name="site_accessible",
                category="headers",
                severity="info",
                title="Site Accessible",
                description=f"Successfully connected to {self.base_url} (HTTP {resp.status_code})",
                remediation="",
                passed=True,
                evidence=f"Status: {resp.status_code}, Redirects: {len(resp.history)}"
            ))
        except requests.exceptions.SSLError:
            results.append(ScanResult(
                check_name="site_accessible",
                category="headers",
                severity="critical",
                title="SSL Certificate Error",
                description="Cannot connect due to SSL certificate error.",
                remediation="Fix your SSL certificate or use a valid one from Let's Encrypt.",
                passed=False,
            ))
            return results
        except Exception as e:
            results.append(ScanResult(
                check_name="site_accessible",
                category="headers",
                severity="critical",
                title="Site Not Accessible",
                description=f"Could not connect: {str(e)[:100]}",
                remediation="Ensure the website is online and accessible.",
                passed=False,
            ))
            return results

        # Check each security header
        for header_name, info in self.SECURITY_HEADERS.items():
            header_lower = header_name.lower()
            if header_lower in self.response_headers:
                results.append(ScanResult(
                    check_name=f"header_{header_lower.replace('-', '_')}",
                    category="headers",
                    severity="info",
                    title=f"{info['title']} — Present",
                    description=f"{info['description']}",
                    remediation="",
                    passed=True,
                    evidence=f"Value: {self.response_headers[header_lower][:100]}"
                ))
            else:
                results.append(ScanResult(
                    check_name=f"header_{header_lower.replace('-', '_')}",
                    category="headers",
                    severity=info["severity"],
                    title=f"{info['title']} — MISSING",
                    description=f"{info['description']}",
                    remediation=info["remediation"],
                    passed=False,
                ))

        return results
