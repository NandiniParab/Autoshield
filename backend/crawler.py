from urllib.parse import urlparse

from playwright.async_api import async_playwright


HEADER_CHECKS = {
    "content-security-policy": {
        "title": "Missing Content-Security-Policy",
        "severity": "HIGH",
        "recommendation": "Add a strict Content-Security-Policy header.",
    },
    "strict-transport-security": {
        "title": "Missing Strict-Transport-Security",
        "severity": "HIGH",
        "recommendation": "Serve the site over HTTPS and add HSTS with an appropriate max-age.",
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options",
        "severity": "MEDIUM",
        "recommendation": "Add X-Frame-Options: DENY/SAMEORIGIN or use frame-ancestors in CSP.",
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options",
        "severity": "MEDIUM",
        "recommendation": "Add X-Content-Type-Options: nosniff.",
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy",
        "severity": "LOW",
        "recommendation": "Add a Referrer-Policy such as strict-origin-when-cross-origin.",
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy",
        "severity": "LOW",
        "recommendation": "Add a Permissions-Policy limiting powerful browser APIs.",
    },
}

SEVERITY_WEIGHTS = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 9, "LOW": 4, "INFO": 0}


def _issue(category, title, severity, recommendation, *, owasp="A05: Security Misconfiguration", evidence=""):
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "owasp": owasp,
        "recommendation": recommendation,
        "evidence": evidence,
    }


def _score(issues):
    penalty = sum(SEVERITY_WEIGHTS.get(i.get("severity", "LOW"), 4) for i in issues)
    return max(0, min(100, 100 - penalty))


def _to_vulnerability_rows(url, issues):
    return [
        {
            "tool": "crawler",
            "file_path": url,
            "line": 0,
            "message": issue["title"],
            "severity": issue["severity"],
        }
        for issue in issues
    ]


async def scan_website_runtime(url: str):
    report = await scan_website_compliance(url)
    return _to_vulnerability_rows(url, report["issues"])


async def scan_website_compliance(url: str):
    issues = []
    observed = {"headers": {}, "cookies": [], "scripts": []}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        try:
            response = await page.goto(url, timeout=60000, wait_until="domcontentloaded")
            headers = {k.lower(): v for k, v in (response.headers if response else {}).items()}
            observed["headers"] = headers

            parsed = urlparse(url)
            is_https = parsed.scheme == "https"
            if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
                issues.append(_issue(
                    "Transport Security",
                    "HTTP instead of HTTPS",
                    "HIGH",
                    "Serve production pages over HTTPS and redirect HTTP to HTTPS.",
                    evidence=url,
                ))

            for header, details in HEADER_CHECKS.items():
                if header == "strict-transport-security" and not is_https:
                    continue
                if header not in headers:
                    issues.append(_issue(
                        "Security Headers",
                        details["title"],
                        details["severity"],
                        details["recommendation"],
                    ))

            acao = headers.get("access-control-allow-origin", "")
            if acao.strip() == "*":
                issues.append(_issue(
                    "CORS",
                    "Insecure CORS wildcard",
                    "HIGH",
                    "Return a specific trusted origin instead of Access-Control-Allow-Origin: *.",
                    evidence="Access-Control-Allow-Origin: *",
                ))

            scripts = await page.evaluate(
                """() => Array.from(document.scripts).map((s, i) => ({
                    index: i,
                    src: s.src || "",
                    inline: !s.src && !!s.textContent.trim(),
                    snippet: (s.textContent || "").slice(0, 500),
                    integrity: s.getAttribute("integrity") || "",
                    isExternal: !!s.src && new URL(s.src, location.href).origin !== location.origin
                }))"""
            )
            observed["scripts"] = scripts

            if is_https:
                for script in scripts:
                    if script.get("src", "").startswith("http://"):
                        issues.append(_issue(
                            "Mixed Content",
                            "Mixed content HTTP script",
                            "HIGH",
                            "Load scripts over HTTPS only.",
                            evidence=script["src"],
                        ))

            inline_scripts = [s for s in scripts if s.get("inline")]
            if inline_scripts:
                issues.append(_issue(
                    "Content Security Policy",
                    "Inline scripts detected",
                    "MEDIUM",
                    "Move inline JavaScript to external files and enforce CSP without unsafe-inline.",
                    evidence=f"{len(inline_scripts)} inline script(s)",
                ))

            eval_scripts = [s for s in scripts if "eval(" in s.get("snippet", "") or "new Function" in s.get("snippet", "")]
            if eval_scripts:
                issues.append(_issue(
                    "Code Execution",
                    "eval usage detected",
                    "HIGH",
                    "Remove eval/new Function and use structured parsing or safe dispatch tables.",
                    evidence=f"{len(eval_scripts)} script block(s)",
                    owasp="A03: Injection",
                ))

            external_no_sri = [s for s in scripts if s.get("isExternal") and not s.get("integrity")]
            if external_no_sri:
                issues.append(_issue(
                    "Supply Chain",
                    "Third-party scripts without integrity",
                    "MEDIUM",
                    "Add Subresource Integrity and crossorigin attributes to third-party script tags.",
                    evidence=f"{len(external_no_sri)} script(s)",
                    owasp="A08: Software and Data Integrity Failures",
                ))

            exposed = await page.evaluate(
                """() => {
                    const text = document.documentElement.innerHTML.slice(0, 500000);
                    const matches = text.match(/(api[_-]?key|secret|token|client[_-]?secret|access[_-]?key)\\s*[:=]\\s*['"][^'"]{8,}['"]/ig) || [];
                    return matches.slice(0, 10);
                }"""
            )
            if exposed:
                issues.append(_issue(
                    "Secrets",
                    "Exposed frontend secrets",
                    "HIGH",
                    "Remove secrets from frontend code and rotate any exposed credentials.",
                    evidence=", ".join(exposed[:3]),
                    owasp="A07: Identification and Authentication Failures",
                ))

            cookies = await context.cookies()
            observed["cookies"] = cookies
            for cookie in cookies:
                missing = []
                if not cookie.get("httpOnly"):
                    missing.append("HttpOnly")
                if is_https and not cookie.get("secure"):
                    missing.append("Secure")
                if (cookie.get("sameSite") or "").lower() not in ("lax", "strict"):
                    missing.append("SameSite")
                if missing:
                    issues.append(_issue(
                        "Cookies",
                        f"Insecure cookie missing {', '.join(missing)}",
                        "MEDIUM",
                        "Set HttpOnly, Secure, and SameSite=Lax or Strict for session cookies.",
                        evidence=cookie.get("name", "cookie"),
                    ))

        except Exception as e:
            issues.append(_issue(
                "Crawler",
                "Runtime crawl failed",
                "LOW",
                "Verify the target URL is reachable and retry the scan.",
                evidence=str(e),
            ))
        finally:
            await browser.close()

    return {
        "compliance_score": _score(issues),
        "issues": issues,
        "observed": observed,
    }
