from typing import Any, Dict, List


AGENT_NAME = "Report Agent"


def calculate_risk_score(findings: List[Dict[str, Any]]) -> int:
    score = 100

    for finding in findings:
        severity = str(finding.get("severity", "")).upper()
        confidence = str(finding.get("validation", {}).get("confidence", "")).upper()

        if severity in ["CRITICAL"]:
            score -= 20
        elif severity in ["HIGH", "ERROR"]:
            score -= 15
        elif severity in ["MEDIUM", "WARNING"]:
            score -= 8
        elif severity in ["LOW"]:
            score -= 3

        if confidence == "LOW":
            score += 3
        elif confidence == "HIGH":
            score -= 2

    return max(min(score, 100), 0)


def get_risk_level(score: int) -> str:
    if score >= 85:
        return "LOW"
    if score >= 60:
        return "MEDIUM"
    if score >= 35:
        return "HIGH"
    return "CRITICAL"


def group_findings(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    by_source: Dict[str, int] = {}
    by_confidence: Dict[str, int] = {}
    by_category: Dict[str, int] = {}

    for finding in findings:
        source = finding.get("tool", "unknown")
        confidence = finding.get("validation", {}).get("confidence", "UNKNOWN")
        category = finding.get("category", "Security Issue")

        by_source[source] = by_source.get(source, 0) + 1
        by_confidence[confidence] = by_confidence.get(confidence, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1

    return {
        "by_source": by_source,
        "by_confidence": by_confidence,
        "by_category": by_category,
    }


def get_top_issues(findings: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    severity_rank = {
        "CRITICAL": 4,
        "ERROR": 3,
        "HIGH": 3,
        "WARNING": 2,
        "MEDIUM": 2,
        "LOW": 1,
    }

    sorted_findings = sorted(
        findings,
        key=lambda finding: severity_rank.get(str(finding.get("severity", "")).upper(), 0),
        reverse=True,
    )

    return [
        {
            "category": finding.get("category"),
            "message": finding.get("message"),
            "severity": finding.get("severity"),
            "confidence": finding.get("validation", {}).get("confidence"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "cwe": finding.get("cwe"),
            "owasp": finding.get("owasp"),
        }
        for finding in sorted_findings[:limit]
    ]


def build_remediation_plan(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups = group_findings(findings)
    categories = groups.get("by_category", {})
    plan = []

    if categories.get("SQL Injection"):
        plan.append(
            {
                "priority": "P0",
                "category": "SQL Injection",
                "action": "Replace dynamic SQL construction with parameterized queries or prepared statements.",
            }
        )

    if categories.get("Code Execution") or categories.get("Command Injection"):
        plan.append(
            {
                "priority": "P0",
                "category": "Unsafe Code Execution",
                "action": "Remove eval/exec-style execution paths and replace them with safe parsing or allowlisted dispatch.",
            }
        )

    if categories.get("Secrets Exposure") or categories.get("Hardcoded Secret"):
        plan.append(
            {
                "priority": "P0",
                "category": "Secrets",
                "action": "Move secrets out of source/browser storage, rotate exposed credentials, and use environment or secret-manager storage.",
            }
        )

    if categories.get("Vulnerable Dependency"):
        plan.append(
            {
                "priority": "P1",
                "category": "Dependencies",
                "action": "Upgrade vulnerable packages to fixed versions and rerun dependency scanning.",
            }
        )

    if categories.get("Security Headers") or categories.get("Content Security Policy"):
        plan.append(
            {
                "priority": "P1",
                "category": "Security Headers",
                "action": "Add CSP, X-Frame-Options or frame-ancestors, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.",
            }
        )

    if categories.get("Cookie Security"):
        plan.append(
            {
                "priority": "P1",
                "category": "Cookies",
                "action": "Set Secure, HttpOnly, and SameSite attributes on session cookies where applicable.",
            }
        )

    if not plan and findings:
        plan.append(
            {
                "priority": "P2",
                "category": "General",
                "action": "Review top findings, apply recommended fixes, then rerun AutoShield to confirm risk reduction.",
            }
        )

    return plan
