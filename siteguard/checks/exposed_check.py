"""Exposed files & directories checker for SiteGuard."""

import requests
from siteguard.scanner import ScanResult


class ExposedChecker:
    """Check for exposed files, directories, and common misconfigurations."""

    # Directories often left exposed
    EXPOSED_PATHS = [
        "/robots.txt",
        "/sitemap.xml",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/.well-known/",
    ]

    def __init__(self, base_url: str, domain: str):
        self.base_url = base_url
        self.domain = domain

    def run_all(self) -> list[ScanResult]:
        """Run all exposed file checks."""
        results = []

        results.append(self._check_directory_listing())
        results.append(self._check_robots_txt())
        results.append(self._check_cors_header())

        return results

    def _check_directory_listing(self) -> ScanResult:
        """Check if directory listing is enabled."""
        # Test a few common paths for directory listing
        test_paths = ["/assets/", "/images/", "/css/", "/js/"]
        checked = 0

        for path in test_paths:
            try:
                url = f"{self.base_url.rstrip('/')}{path}"
                resp = requests.get(url, timeout=5, allow_redirects=False,
                                    headers={"User-Agent": "SiteGuard/1.0"})
                checked += 1
                text = resp.text.lower() if resp.text else ""
                if resp.status_code == 200 and ("index of" in text or "parent directory" in text):
                    return ScanResult(
                        check_name="directory_listing",
                        category="exposed",
                        severity="medium",
                        title="Directory Listing Enabled",
                        description=f"Directory listing is enabled at {url}. Attackers can browse your file structure.",
                        remediation="Disable directory listing in your web server config. Nginx: 'autoindex off'. Apache: 'Options -Indexes'.",
                        passed=False,
                        evidence=f"Directory listing detected at: {url}"
                    )
            except Exception:
                pass

        return ScanResult(
            check_name="directory_listing",
            category="exposed",
            severity="info",
            title="No Directory Listing Detected",
            description=f"Checked {checked} common paths — no directory listing found.",
            remediation="",
            passed=True,
        )

    def _check_robots_txt(self) -> ScanResult:
        """Check for robots.txt and analyze it."""
        try:
            url = f"{self.base_url.rstrip('/')}/robots.txt"
            resp = requests.get(url, timeout=5, allow_redirects=True,
                                headers={"User-Agent": "SiteGuard/1.0"})
            if resp.status_code == 200:
                content = resp.text.lower()
                # Check if robots.txt is leaking sensitive paths
                sensitive_keywords = ["admin", "backup", "config", "private", "secret", "staging"]
                leaks = [kw for kw in sensitive_keywords if kw in content]

                if leaks:
                    return ScanResult(
                        check_name="robots_txt",
                        category="exposed",
                        severity="medium",
                        title="Sensitive Paths in robots.txt",
                        description=f"robots.txt may reveal sensitive paths. Keywords found: {', '.join(leaks)}",
                        remediation="Remove sensitive paths from robots.txt. Disallow patterns don't hide them — they reveal them to attackers.",
                        passed=False,
                        evidence=f"Sensitive keywords: {', '.join(leaks)}"
                    )
                else:
                    return ScanResult(
                        check_name="robots_txt",
                        category="exposed",
                        severity="info",
                        title="robots.txt Present (No Sensitive Paths)",
                        description="robots.txt found but does not appear to reveal sensitive paths.",
                        remediation="",
                        passed=True,
                    )

            return ScanResult(
                check_name="robots_txt",
                category="exposed",
                severity="info",
                title="No robots.txt",
                description="No robots.txt file found. Consider adding one to guide well-behaved crawlers.",
                remediation="Create a robots.txt file if you want to control search engine crawling.",
                passed=True,
            )
        except Exception:
            return ScanResult(
                check_name="robots_txt",
                category="exposed",
                severity="low",
                title="robots.txt Check Failed",
                description="Could not check robots.txt.",
                remediation="",
                passed=False,
            )

    def _check_cors_header(self) -> ScanResult:
        """Check for overly permissive CORS settings."""
        try:
            resp = requests.get(
                self.base_url,
                timeout=10,
                headers={
                    "User-Agent": "SiteGuard/1.0",
                    "Origin": "https://evil.com",
                }
            )
            cors_headers = {
                k.lower(): v for k, v in resp.headers.items()
                if k.lower().startswith("access-control")
            }

            acao = cors_headers.get("access-control-allow-origin", "")
            if acao == "*":
                return ScanResult(
                    check_name="cors_wildcard",
                    category="exposed",
                    severity="medium",
                    title="CORS — Wildcard Allowed Origin",
                    description="Access-Control-Allow-Origin is set to '*', allowing any website to make requests.",
                    remediation="Restrict CORS to specific trusted origins. Avoid using '*' except for public APIs with no sensitive data.",
                    passed=False,
                    evidence="Access-Control-Allow-Origin: *"
                )
            elif acao:
                return ScanResult(
                    check_name="cors_configured",
                    category="exposed",
                    severity="info",
                    title="CORS Configured (Restricted)",
                    description=f"CORS is configured with a specific origin: {acao}",
                    remediation="",
                    passed=True,
                    evidence=f"Access-Control-Allow-Origin: {acao}"
                )
            else:
                return ScanResult(
                    check_name="cors_none",
                    category="exposed",
                    severity="info",
                    title="No CORS Headers",
                    description="No CORS headers set (default same-origin). This is secure.",
                    remediation="",
                    passed=True,
                )
        except Exception:
            return ScanResult(
                check_name="cors_check",
                category="exposed",
                severity="low",
                title="CORS Check Failed",
                description="Could not check CORS settings.",
                remediation="",
                passed=False,
            )
