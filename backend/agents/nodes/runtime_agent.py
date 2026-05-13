from typing import Any, Dict


try:
    from runtime.runtime_analyzer import RuntimeAnalyzer
except Exception:
    RuntimeAnalyzer = None


def runtime_agent_node(state: Dict[str, Any]) -> Dict[str, Any]:
    runtime_url = state.get("runtime_url")
    page_data = state.get("runtime_page_data", {}) or {}
    headers = state.get("runtime_headers", {}) or {}
    errors = list(state.get("errors", []))

    if not runtime_url or RuntimeAnalyzer is None:
        return {
            "runtime_findings": [],
            "errors": errors,
            "agent_trace": state.get("agent_trace", [])
            + [
                {
                    "agent": "Runtime Agent",
                    "status": "skipped",
                    "reason": "No runtime URL or analyzer unavailable",
                }
            ],
        }

    try:
        analyzer = RuntimeAnalyzer()
        result = analyzer.analyze_page(
            url=runtime_url,
            page_data=page_data,
            headers=headers,
        )

        findings = []
        for issue in result.get("issues", []):
            title = issue.get("title", "runtime-issue")
            findings.append(
                {
                    "tool": "runtime-browser",
                    "rule_id": issue.get("type") or _slugify_rule_id(title),
                    "message": title,
                    "severity": issue.get("severity", "MEDIUM"),
                    "file": runtime_url,
                    "file_path": runtime_url,
                    "line": 1,
                    "column": 1,
                    "cwe": issue.get("cwe", "CWE-Unknown"),
                    "cwe_id": issue.get("cwe", "CWE-Unknown"),
                    "owasp": issue.get("owasp", "A05: Security Misconfiguration"),
                    "category": issue.get("category", "Runtime Security"),
                    "code_snippet": issue.get("evidence", ""),
                    "recommendation": issue.get("recommendation", ""),
                    "raw": issue,
                }
            )

        return {
            "runtime_findings": findings,
            "agent_trace": state.get("agent_trace", [])
            + [
                {
                    "agent": "Runtime Agent",
                    "status": "completed",
                    "findings_added": len(findings),
                }
            ],
        }
    except Exception as exc:
        return {
            "runtime_findings": [],
            "errors": errors + [f"Runtime scan failed: {_short_error(exc)}"],
            "agent_trace": state.get("agent_trace", [])
            + [
                {
                    "agent": "Runtime Agent",
                    "status": "failed",
                    "error": _short_error(exc),
                }
            ],
        }


def _slugify_rule_id(value: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value))
    slug = "-".join(part for part in slug.split("-") if part)
    return f"runtime-{slug or 'issue'}"


def _short_error(exc: Exception) -> str:
    lines = [line.strip() for line in str(exc).splitlines() if line.strip()]
    return lines[-1] if lines else exc.__class__.__name__
