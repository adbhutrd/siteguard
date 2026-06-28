"""OWASP Top 10 surface checks for SiteGuard."""

import requests
from siteguard.scanner import ScanResult


class OWASPChecker:
    """Check for common OWASP Top 10 vulnerabilities (surface-level)."""

    # Common sensitive paths to check
    SENSITIVE_PATHS = [
        "/.env",
        "/.git/config",
        "/wp-config.php",
        "/.DS_Store",
        "/backup",
        "/admin",
        "/phpinfo.php",
        "/server-status",
        "/.htaccess",
        "/debug",
        "/console",
        "/api-docs",
        "/swagger.json",
        "/graphql",
        "/actuator/health",
    ]

    def __init__(self, base_url: str, domain: str):
        self.base_url = base_url
        self.domain = domain

    def run_all(self) -> list[ScanResult]:
        """Run all OWASP checks."""
        results = []

        # Check for information disclosure via common paths
        results.append(self._check_sensitive_paths())

        # Check for server information disclosure
        results.append(self._check_server_info())

        # Check for missing security.txt
        results.append(self._check_security_txt())

        return results

    def _check_sensitive_paths(self) -> ScanResult:
        """Check if sensitive files/paths are exposed."""
        exposed = []
        checked = 0

        for path in self.SENSITIVE_PATHS[:5]:  # Limit to avoid too many requests
            try:
                url = f"{self.base_url.rstrip('/')}{path}"
                resp = requests.get(url, timeout=5, allow_redirects=False,
                                    headers={"User-Agent": "SiteGuard/1.0"})
                checked += 1
                if resp.status_code == 200 and len(resp.text) > 10:
                    exposed.append(path)
            except Exception:
                pass

        if exposed:
            return ScanResult(
                check_name="sensitive_paths",
                category="owasp",
                severity="high",
                title=f"Potentially Sensitive Files Exposed ({len(exposed)} found)",
                description=f"The following files/paths returned HTTP 200 and may expose sensitive data: {', '.join(exposed)}",
                remediation="Restrict access to these paths via server configuration (.htaccess, nginx config). Never expose .env, .git, or debug endpoints.",
                passed=False,
                evidence=f"Paths found: {', '.join(exposed)}"
            )
        else:
            return ScanResult(
                check_name="sensitive_paths",
                category="owasp",
                severity="info",
                title="No Sensitive Files Exposed (Surface Scan)",
                description=f"Checked {checked} common sensitive paths — none returned HTTP 200.",
                remediation="",
                passed=True,
                evidence="No sensitive paths found"
            )

    def _check_server_info(self) -> ScanResult:
        """Check for server information leakage in headers."""
        try:
            resp = requests.get(
                self.base_url, timeout=10, allow_redirects=True,
                headers={"User-Agent": "SiteGuard/1.0"}
            )
            leaky_headers = {}
            info_headers = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

            for h in info_headers:
                if h in {k.lower(): v for k, v in resp.headers.items()}:
                    leaky_headers[h] = {k.lower(): v for k, v in resp.headers.items()}[h]

            if leaky_headers:
                leak_detail = ", ".join(f"{k}: {v}" for k, v in leaky_headers.items())
                return ScanResult(
                    check_name="server_info_leak",
                    category="owasp",
                    severity="medium",
                    title="Server Information Leaked in Headers",
                    description=f"The server reveals technology details in HTTP headers: {leak_detail}",
                    remediation="Remove or mask server information headers (Server, X-Powered-By, etc.) in your web server config.",
                    passed=False,
                    evidence=leak_detail
                )
            else:
                return ScanResult(
                    check_name="server_info_leak",
                    category="owasp",
                    severity="info",
                    title="No Server Info Leaked",
                    description="No server technology information was found in HTTP headers.",
                    remediation="",
                    passed=True,
                )
        except Exception:
            return ScanResult(
                check_name="server_info_leak",
                category="owasp",
                severity="low",
                title="Server Info Check Skipped",
                description="Could not complete server info check.",
                remediation="",
                passed=False,
            )

    def _check_security_txt(self) -> ScanResult:
        """Check for security.txt file (RFC 9116)."""
        security_txt_urls = [
            f"{self.base_url.rstrip('/')}/.well-known/security.txt",
            f"{self.base_url.rstrip('/')}/security.txt",
        ]

        for url in security_txt_urls:
            try:
                resp = requests.get(url, timeout=5, allow_redirects=True,
                                    headers={"User-Agent": "SiteGuard/1.0"})
                if resp.status_code == 200 and "contact:" in resp.text.lower():
                    return ScanResult(
                        check_name="security_txt",
                        category="owasp",
                        severity="info",
                        title="security.txt Present",
                        description="A security.txt file (RFC 9116) is present — good for vulnerability disclosure.",
                        remediation="",
                        passed=True,
                        evidence=f"Found at: {url}"
                    )
            except Exception:
                pass

        return ScanResult(
            check_name="security_txt",
            category="owasp",
            severity="low",
            title="security.txt Missing",
            description="No security.txt file found. This makes it harder for researchers to report vulnerabilities responsibly.",
            remediation="Create a security.txt file at /.well-known/security.txt with contact information for security researchers.",
            passed=False,
        )
