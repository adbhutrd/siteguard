# 🛡️ SiteGuard — Free Website Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License MIT">
  <img src="https://img.shields.io/badge/free-forever-brightgreen.svg" alt="Free Forever">
  <img src="https://github.com/adbhutrd/siteguard/actions/workflows/tests.yml/badge.svg" alt="Tests">
</p>

<p align="center">
  <b>One command. Complete security audit. Beautiful report.</b><br>
  Scan any website for SSL, security headers, OWASP Top 10 vulnerabilities, and exposed files — in seconds.
</p>

---

## ⚡ The Problem

**60% of small business websites have critical security vulnerabilities** — but most can't afford a $2,000+ security audit. SiteGuard gives everyone a free, professional-grade security scan in one command.

## 🚀 Quick Start

```bash
# Install
pip install siteguard

# Scan any website
siteguard scan example.com

# Save a beautiful HTML report
siteguard scan mysite.com --output report.html

# Check only SSL/TLS
siteguard scan mysite.com --check ssl

# Scan and see your security grade
siteguard scan shopify.com

# Show version
siteguard version
```

## 🎯 What It Checks

```
🔒 SSL/TLS
├── HTTPS availability
├── Certificate validity & expiry
└── TLS version support (1.2+)

📋 Security Headers
├── HSTS (Strict Transport Security)
├── Content Security Policy (CSP)
├── X-Content-Type-Options
├── X-Frame-Options (Clickjacking)
├── X-XSS-Protection
├── Referrer Policy
├── Permissions Policy
└── Cross-Origin Opener Policy

🛡️ OWASP Top 10 (Surface)
├── Sensitive file exposure (.env, .git, etc.)
├── Server information leakage
└── security.txt presence (RFC 9116)

📁 Exposed Files
├── Directory listing detection
├── robots.txt analysis (sensitive path leaks)
└── CORS misconfiguration (wildcard origin)
```

## 📊 Example Output

```
$ siteguard scan example.com

🔍 SiteGuard v1.0.0 — Scanning example.com...

══════════════════════════════════════════════════════════
  🛡️  SITEGUARD SECURITY REPORT
══════════════════════════════════════════════════════════

  Target:      example.com
  Scan Time:   2026-06-28 12:00:00 UTC
  Checks Run:  18
  Grade:       B
  Score:       78/100

▸ 🔒 SSL/TLS
  ✅ PASS  HTTPS Available
  ✅ PASS  Certificate Valid (320 days remaining)
  ✅ PASS  TLS 1.2+ Supported

▸ 📋 Security Headers
  ❌ FAIL  HSTS — MISSING
  ❌ FAIL  Content Security Policy — MISSING
  ❌ FAIL  X-Frame-Options — MISSING
  ✅ PASS  X-Content-Type-Options — Present
  ✅ PASS  X-XSS-Protection — Present

▸ 🛡️ OWASP Top 10
  ✅ PASS  No Sensitive Files Exposed
  ❌ FAIL  Server Information Leaked (Server: nginx/1.24)
  ❌ FAIL  security.txt Missing

▸ 📁 Exposed Files
  ✅ PASS  No Directory Listing
  ✅ PASS  No Sensitive Paths in robots.txt
  ✅ PASS  CORS Configured (Restricted)

══════════════════════════════════════════════════════════
  ✅ Passed: 14  |  ❌ Failed: 4
  Overall Grade: B
══════════════════════════════════════════════════════════

💡 Tip: Use --output report.html to save a detailed HTML report
```

## 📄 HTML Report

Generate beautiful, shareable HTML reports:

```bash
siteguard scan example.com --output security-report.html
```

The HTML report includes:
- 🎯 **Security grade** with visual score circle
- 📊 **Pass/Fail breakdown** with counts
- 📋 **Detailed findings** sorted by severity
- 🔧 **Fix instructions** for every failed check
- 🎨 **Professional dark theme** ready to share

## 🏆 Security Grades

| Grade | Score | Status |
|-------|-------|--------|
| **A+** | 95-100% | Excellent — all checks pass |
| **A** | 85-94% | Very good — minor issues |
| **B** | 75-84% | Good — some improvements needed |
| **C** | 65-74% | Needs attention |
| **D** | 50-64% | Significant issues |
| **F** | <50% | Critical — fix immediately |

## 🛠️ Use Cases

### Small Business Owner
```bash
siteguard scan mybusiness.com --output report.html
# → Get a professional security report to show clients
```

### Web Developer
```bash
siteguard scan staging.example.com
# → Check security before deploying to production
```

### Security Researcher
```bash
siteguard scan target.com --check ssl,headers
# → Quick surface reconnaissance before deeper testing
```

### DevOps / CI Pipeline
```bash
siteguard scan $DEPLOY_URL --quiet
# → Fail the pipeline if grade is D or F
```

## 🔧 Configuration

SiteGuard works out of the box with zero configuration. No API keys needed. No accounts required.

For advanced users:
```python
from siteguard import SecurityScanner

# Custom scan
scanner = SecurityScanner("example.com", checks=["ssl", "headers"])
summary = scanner.run_all()

print(f"Grade: {summary.grade}")
print(f"Score: {summary.score}")
```

## 🧪 Running Tests

```bash
pip install -e ".[dev]"
pytest --cov=siteguard --cov-report=term-missing
```

## 🌍 Why SiteGuard?

| Feature | SiteGuard | SSL Labs | SecurityHeaders | Manual Audit |
|---------|-----------|----------|----------------|--------------|
| SSL/TLS | ✅ | ✅ | ❌ | ❌ |
| Security Headers | ✅ | ❌ | ✅ | ❌ |
| OWASP Surface | ✅ | ❌ | ❌ | ✅ ($2k+) |
| Exposed Files | ✅ | ❌ | ❌ | ✅ ($2k+) |
| HTML Report | ✅ | ✅ | ✅ | ❌ |
| CLI / CI-friendly | ✅ | ❌ | ❌ | ❌ |
| Free | ✅ | ✅ | ✅ | ❌ |
| One command | ✅ | ❌ | ❌ | ❌ |

**SiteGuard is the only tool that combines all security checks in one free command.**

## 🤝 Contributing

Contributions welcome! Help make the internet safer for small businesses.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/new-check`)
3. Commit (`git commit -m 'Add awesome check'`)
4. Push (`git push origin feature/new-check`)
5. Open a Pull Request

## 📚 Inspiration

- **SSL Labs** — For SSL/TLS testing methodology
- **SecurityHeaders.com** — For security header analysis
- **OWASP Top 10** — For vulnerability classification
- **Mozilla Observatory** — For web security best practices

## 📄 License

MIT License — free forever. See [LICENSE](LICENSE).

---

<p align="center">
  <b>Built with ❤️ by <a href="https://github.com/adbhutrd">Enish Shah</a></b><br>
  MSc Cyber Security (Distinction)<br>
  <i>Making security accessible to everyone.</i>
</p>
