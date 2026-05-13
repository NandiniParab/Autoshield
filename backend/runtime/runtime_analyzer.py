import re
from typing import Any, Dict, List
from urllib.parse import urlparse


class RuntimeAnalyzer:
    REQUIRED_HEADERS = {
        "content-security-policy": {
            "title": "Missing Content-Security-Policy header",
            "severity": "HIGH",
            "cwe": "CWE-693",
            "recommendation": "Add a strict Content-Security-Policy header.",
        },
        "strict-transport-security": {
            "title": "Missing Strict-Transport-Security header",
            "severity": "HIGH",
            "cwe": "CWE-319",
            "recommendation": "Add Strict-Transport-Security on HTTPS responses.",
        },
        "x-frame-options": {
            "title": "Missing X-Frame-Options header",
            "severity": "MEDIUM",
            "cwe": "CWE-1021",
            "recommendation": "Add X-Frame-Options or a CSP frame-ancestors directive.",
        },
        "x-content-type-options": {
            "title": "Missing X-Content-Type-Options header",
            "severity": "MEDIUM",
            "cwe": "CWE-693",
            "recommendation": "Add X-Content-Type-Options: nosniff.",
        },
        "referrer-policy": {
            "title": "Missing Referrer-Policy header",
            "severity": "LOW",
            "cwe": "CWE-200",
            "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin.",
        },
        "permissions-policy": {
            "title": "Missing Permissions-Policy header",
            "severity": "LOW",
            "cwe": "CWE-693",
            "recommendation": "Add a restrictive Permissions-Policy header.",
        },
    }

    SECRET_RE = re.compile(
        r"(?i)(api[_-]?key|secret|token|jwt|sk_live_[A-Za-z0-9_\\-]+|"
        r"sk_test_[A-Za-z0-9_\\-]+|pk_live_[A-Za-z0-9_\\-]+|"
        r"ghp_[A-Za-z0-9_]+|xoxb-[A-Za-z0-9\\-]+|bearer\\s+[A-Za-z0-9._\\-]+)"
    )

    def analyze_page(
        self,
        url: str,
        page_data: Dict[str, Any],
        headers: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        headers = self._normalize_headers(headers or {})
        issues: List[Dict[str, Any]] = []
        parsed = urlparse(url or page_data.get("url", ""))
        is_https = parsed.scheme == "https"

        issues.extend(self._check_headers(headers, is_https))
        issues.extend(self._check_mixed_content(url, page_data))
        issues.extend(self._check_http_external_scripts(url, page_data))
        issues.extend(self._check_inline_scripts(page_data))
        issues.extend(self._check_external_scripts(page_data))
        issues.extend(self._check_cookies(page_data, headers))
        issues.extend(self._check_secrets(page_data))

        summary = {"high": 0, "medium": 0, "low": 0}
        for issue in issues:
            sev = str(issue.get("severity", "LOW")).lower()
            if sev in summary:
                summary[sev] += 1

        score = 100
        for issue in issues:
            severity = str(issue.get("severity", "LOW")).upper()
            if severity == "HIGH":
                score -= 15
            elif severity == "MEDIUM":
                score -= 8
            else:
                score -= 3

        return {
            "url": url or page_data.get("url", ""),
            "runtime_score": max(0, score),
            "issues_count": len(issues),
            "issues": issues,
            "summary": summary,
        }

    def _check_headers(self, headers: Dict[str, str], is_https: bool) -> List[Dict[str, Any]]:
        issues = []
        for header, spec in self.REQUIRED_HEADERS.items():
            if header == "strict-transport-security" and not is_https:
                issues.append(
                    self._issue(
                        "Strict-Transport-Security not applicable on HTTP",
                        "LOW",
                        "Security Headers",
                        "CWE-319",
                        "Current page is not HTTPS, so HSTS cannot be enforced for this response.",
                        "Serve the site over HTTPS and add Strict-Transport-Security.",
                    )
                )
                continue
            if not headers.get(header):
                issues.append(
                    self._issue(
                        spec["title"],
                        spec["severity"],
                        "Security Headers",
                        spec["cwe"],
                        f"Header `{header}` was not present in collected response headers.",
                        spec["recommendation"],
                    )
                )
        return issues

    def _check_mixed_content(self, url: str, page_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not str(url or page_data.get("url", "")).lower().startswith("https://"):
            return []

        resources = []
        for key in ("scripts", "stylesheets", "images", "iframes"):
            for item in page_data.get(key, []) or []:
                resource_url = item.get("src") or item.get("href") or item.get("url") or ""
                if str(resource_url).lower().startswith("http://"):
                    resources.append(resource_url)

        for item in page_data.get("mixed_content", []) or []:
            resource_url = item.get("url") or item.get("src") or ""
            if str(resource_url).lower().startswith("http://"):
                resources.append(resource_url)

        if not resources:
            return []
        return [
            self._issue(
                "Mixed content HTTP resources detected",
                "HIGH",
                "Mixed Content",
                "CWE-319",
                "; ".join(resources[:5]),
                "Load all scripts, images, styles, and frames over HTTPS.",
            )
        ]

    def _check_http_external_scripts(self, url: str, page_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        if str(url or page_data.get("url", "")).lower().startswith("https://"):
            return []

        insecure_scripts = [
            script.get("src")
            for script in page_data.get("scripts", []) or []
            if script.get("src") and str(script.get("src")).lower().startswith("http://")
        ]
        if not insecure_scripts:
            return []

        return [
            self._issue(
                "External script loaded over HTTP",
                "MEDIUM",
                "Transport Security",
                "CWE-319",
                "; ".join(insecure_scripts[:5]),
                "Load external scripts over HTTPS.",
            )
        ]

    def _check_inline_scripts(self, page_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        issues = []
        inline_scripts = page_data.get("inline_scripts", []) or []
        if inline_scripts:
            issues.append(
                self._issue(
                    "Inline scripts detected",
                    "MEDIUM",
                    "Content Security Policy",
                    "CWE-693",
                    f"{len(inline_scripts)} inline script block(s) found.",
                    "Move inline scripts into external files and enforce CSP without unsafe-inline.",
                )
            )

        eval_hits = []
        for script in inline_scripts:
            sample = script.get("content_sample") or script.get("snippet") or ""
            if script.get("contains_eval") or re.search(r"\beval\s*\(|new\s+Function\s*\(", sample):
                eval_hits.append(sample[:160])
        if page_data.get("has_eval"):
            eval_hits.append("Page-level eval/new Function indicator was true.")

        if eval_hits:
            issues.append(
                self._issue(
                    "eval or new Function usage detected",
                    "HIGH",
                    "Code Execution",
                    "CWE-95",
                    "; ".join(eval_hits[:3]),
                    "Remove eval/new Function and use safe parsing or explicit dispatch.",
                )
            )
        return issues

    def _check_external_scripts(self, page_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        scripts = page_data.get("scripts", []) or []
        missing = [
            script.get("src")
            for script in scripts
            if script.get("src") and not script.get("is_inline") and not script.get("integrity")
        ]
        if not missing:
            return []
        return [
            self._issue(
                "External scripts without integrity attribute",
                "MEDIUM",
                "Supply Chain",
                "CWE-829",
                "; ".join(missing[:5]),
                "Add Subresource Integrity and crossorigin to third-party scripts.",
            )
        ]

    def _check_cookies(self, page_data: Dict[str, Any], headers: Dict[str, str]) -> List[Dict[str, Any]]:
        issues = []
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            lower = set_cookie.lower()
            if "secure" not in lower:
                issues.append(self._cookie_issue("Cookies missing Secure attribute", "MEDIUM", "Set-Cookie header lacks Secure."))
            if "samesite" not in lower:
                issues.append(self._cookie_issue("Cookies missing SameSite attribute", "MEDIUM", "Set-Cookie header lacks SameSite."))
            if "httponly" not in lower:
                issues.append(self._cookie_issue("Cookies missing HttpOnly attribute", "MEDIUM", "Set-Cookie header lacks HttpOnly."))
            return issues

        cookies = page_data.get("cookies", []) or []
        if cookies:
            issues.append(
                self._issue(
                    "Cookie HttpOnly/Secure/SameSite attributes cannot be verified",
                    "LOW",
                    "Cookie Security",
                    "CWE-1004",
                    f"Visible cookie names: {', '.join(cookies[:10])}",
                    "Set sensitive cookies with Secure, HttpOnly, and SameSite attributes server-side.",
                )
            )
        return issues

    def _check_secrets(self, page_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        sources = []
        for script in page_data.get("inline_scripts", []) or []:
            sources.append(("inline script", script.get("content_sample") or script.get("snippet") or ""))
        for key, sample in (page_data.get("local_storage_samples", {}) or {}).items():
            sources.append((f"localStorage:{key}", f"{key}={sample}"))
        for key, sample in (page_data.get("session_storage_samples", {}) or {}).items():
            sources.append((f"sessionStorage:{key}", f"{key}={sample}"))
        sources.append(("page text", page_data.get("page_text_sample", "")))

        hits = []
        for source, text in sources:
            match = self.SECRET_RE.search(str(text or ""))
            if match:
                hits.append(f"{source}: {self._redact(match.group(0))}")

        if not hits:
            return []
        return [
            self._issue(
                "Possible frontend secret exposure",
                "HIGH",
                "Secrets Exposure",
                "CWE-798",
                "; ".join(hits[:5]),
                "Remove secrets from frontend code/storage and rotate exposed credentials.",
            )
        ]

    def _cookie_issue(self, title: str, severity: str, evidence: str) -> Dict[str, Any]:
        return self._issue(
            title,
            severity,
            "Cookie Security",
            "CWE-614",
            evidence,
            "Set sensitive cookies with Secure, HttpOnly, and SameSite attributes.",
        )

    def _issue(
        self,
        title: str,
        severity: str,
        category: str,
        cwe: str,
        evidence: str,
        recommendation: str,
    ) -> Dict[str, Any]:
        return {
            "title": title,
            "severity": severity,
            "category": category,
            "owasp": "A05: Security Misconfiguration" if category != "Secrets Exposure" else "A07: Identification and Authentication Failures",
            "cwe": cwe,
            "evidence": evidence,
            "recommendation": recommendation,
        }

    def _normalize_headers(self, headers: Dict[str, Any]) -> Dict[str, str]:
        return {str(key).lower(): str(value) for key, value in headers.items() if value is not None}

    def _redact(self, value: str) -> str:
        if len(value) <= 8:
            return value[:2] + "***"
        return value[:4] + "***" + value[-4:]
