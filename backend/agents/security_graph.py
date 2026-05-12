import os
from typing import Any, Dict, List

from langgraph.graph import END, StateGraph

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

from agents.state import SecurityGraphState
from rag.services.self_rag import SelfRAG
from rag.services.vulnerability_validator import VulnerabilityValidator

try:
    from scanners.semgrep_runner import run_semgrep
except Exception:
    run_semgrep = None

try:
    from scanners.eslint_runner import run_eslint
except Exception:
    run_eslint = None

try:
    from scanners.dependency_runner import run_dependency_scan
except Exception:
    run_dependency_scan = None


class GraphExplanationLLM:
    """Local, deterministic LLM adapter for orchestration v1."""

    def invoke(self, prompt: str) -> str:
        query_part = prompt.split("User query:", 1)[-1] if "User query:" in prompt else prompt[-600:]
        query_part = query_part.split("Answer in this format:", 1)[0].strip()
        fields = _parse_query_fields(query_part)
        category = fields.get("Category", "Security Issue")
        cwe = fields.get("CWE", "CWE-Unknown")
        owasp = fields.get("OWASP", "Unknown")
        message = fields.get("Message", "Static analysis reported this issue.")
        severity = fields.get("Severity", "unknown")
        return (
            "1. Vulnerability Summary\n"
            f"{category} was reported by static analysis with severity {severity}.\n\n"
            "2. Evidence Used\n"
            f"Scanner message: {message}\n\n"
            "3. Security Mapping\n"
            f"CWE: {cwe}. OWASP: {owasp}.\n\n"
            "4. Exploit Scenario\n"
            f"An attacker may exploit this {category.lower()} pattern if the affected value is controllable or exposed.\n\n"
            "5. Recommended Fix\n"
            f"Apply the standard remediation for {category}, then rerun AutoShield and relevant tests.\n\n"
            "6. Confidence Level\n"
            "LOW if RAG evidence is unavailable or unrelated; HIGH only when static, RAG, and answer support the same issue."
        )


def scan_node(state: SecurityGraphState) -> Dict[str, Any]:
    project_path = state.get("project_path")
    findings: List[Dict[str, Any]] = []
    errors = list(state.get("errors", []))

    if not project_path:
        return {"raw_findings": [], "errors": errors + ["project_path missing"]}

    if run_semgrep:
        try:
            findings.extend(run_semgrep(project_path) or [])
        except Exception as exc:
            errors.append(f"Semgrep failed: {_short_error(exc)}")

    if os.getenv("AUTOSHIELD_ENABLE_ESLINT", "").lower() in ("1", "true", "yes") and run_eslint:
        try:
            findings.extend(run_eslint(project_path) or [])
        except Exception as exc:
            errors.append(f"ESLint failed: {_short_error(exc)}")

    if run_dependency_scan:
        try:
            findings.extend(run_dependency_scan(project_path) or [])
        except Exception as exc:
            errors.append(f"Dependency scan failed: {_short_error(exc)}")

    if not findings:
        try:
            import scanner

            findings.extend(scanner.run_scanners(project_path) or [])
        except Exception as exc:
            errors.append(f"Fallback scanner failed: {_short_error(exc)}")

    return {"raw_findings": findings, "errors": errors}


def normalize_node(state: SecurityGraphState) -> Dict[str, Any]:
    raw_findings = state.get("raw_findings", [])
    normalized: List[Dict[str, Any]] = []

    for finding in raw_findings:
        metadata = finding.get("metadata", {}) or {}
        extra = finding.get("extra", {}) or {}
        start = finding.get("start", {}) or {}

        rule_id = (
            finding.get("rule_id")
            or finding.get("check_id")
            or finding.get("code")
            or "unknown-rule"
        )
        message = finding.get("message") or extra.get("message") or "Security issue detected"
        severity = finding.get("severity") or extra.get("severity") or "WARNING"
        file_path = (
            finding.get("file")
            or finding.get("file_path")
            or finding.get("path")
            or finding.get("resource")
            or ""
        )
        line = finding.get("line") or start.get("line") or finding.get("startLineNumber") or 1
        column = finding.get("column") or start.get("col") or finding.get("startColumn") or 1
        cwe = finding.get("cwe") or finding.get("cwe_id") or metadata.get("cwe") or metadata.get("cwe_id") or "CWE-Unknown"
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else "CWE-Unknown"
        owasp = finding.get("owasp") or metadata.get("owasp") or metadata.get("owasp_id") or "Unknown"
        if isinstance(owasp, list):
            owasp = ", ".join(str(value) for value in owasp)
        category = finding.get("category") or metadata.get("category") or infer_category(message, rule_id, cwe)

        normalized_item = {
            "tool": finding.get("tool", "scanner"),
            "rule_id": rule_id,
            "message": message,
            "severity": severity,
            "file": file_path,
            "file_path": file_path,
            "line": line,
            "column": column,
            "cwe": cwe,
            "cwe_id": cwe,
            "owasp": owasp,
            "category": category,
            "code_snippet": finding.get("code_snippet") or finding.get("lines") or extra.get("lines", ""),
            "raw": finding,
        }
        for key in ("package", "installed_version", "fixed_version", "url"):
            value = finding.get(key)
            if value:
                normalized_item[key] = value

        normalized.append(normalized_item)

    return {
        "normalized_findings": normalized,
        "current_finding_index": 0,
        "enriched_findings": [],
    }


def select_finding_node(state: SecurityGraphState) -> Dict[str, Any]:
    findings = state.get("normalized_findings", [])
    index = state.get("current_finding_index", 0)

    if index >= len(findings):
        return {}

    return {
        "current_finding": findings[index],
        "rag_query": "",
        "rag_docs": [],
        "rag_quality": {},
        "rag_attempts": 0,
        "max_rag_attempts": 2,
        "validation": {},
        "explanation": "",
    }


def rag_node(state: SecurityGraphState) -> Dict[str, Any]:
    finding = state.get("current_finding", {})
    query = state.get("rag_query") or build_rag_query(finding)

    try:
        rag = SelfRAG(llm=GraphExplanationLLM())
        rag_result = rag.run(query, static_findings=[finding])
        return {
            "rag_query": query,
            "rag_docs": rag_result.get("documents_used", []),
            "explanation": rag_result.get("answer", ""),
            "validation": rag_result.get("validation", {}),
        }
    except Exception as exc:
        fallback_explanation = build_fallback_explanation(finding, str(exc))
        return {
            "rag_query": query,
            "rag_docs": [],
            "explanation": fallback_explanation,
            "validation": {},
        }


def grade_rag_node(state: SecurityGraphState) -> Dict[str, Any]:
    finding = state.get("current_finding", {})
    docs = state.get("rag_docs", [])
    quality = grade_rag_evidence(finding, docs)
    return {"rag_quality": quality}


def rewrite_rag_query_node(state: SecurityGraphState) -> Dict[str, Any]:
    finding = state.get("current_finding", {})
    previous_query = state.get("rag_query", "")
    attempts = state.get("rag_attempts", 0) + 1

    return {
        "rag_query": strengthen_rag_query(finding, previous_query),
        "rag_attempts": attempts,
        "validation": {},
        "explanation": "",
    }


def validate_node(state: SecurityGraphState) -> Dict[str, Any]:
    existing_validation = state.get("validation", {})
    if existing_validation:
        validation = _apply_rag_quality_downgrade(existing_validation, state.get("rag_quality", {}))
        return {"validation": validation}

    finding = state.get("current_finding", {})
    rag_docs = state.get("rag_docs", [])
    explanation = state.get("explanation", "")
    validator = VulnerabilityValidator()

    validation = validator.validate(
        query=build_rag_query(finding),
        docs=rag_docs,
        static_findings=[finding],
        llm_answer=explanation,
    )

    validation = _apply_rag_quality_downgrade(validation, state.get("rag_quality", {}))

    return {"validation": validation}


def enrich_finding_node(state: SecurityGraphState) -> Dict[str, Any]:
    enriched = list(state.get("enriched_findings", []))
    finding = state.get("current_finding", {})

    enriched.append(
        {
            **finding,
            "rag_query": state.get("rag_query", ""),
            "rag_docs": state.get("rag_docs", []),
            "rag_quality": state.get("rag_quality", {}),
            "validation": state.get("validation", {}),
            "explanation": state.get("explanation", ""),
        }
    )

    return {
        "enriched_findings": enriched,
        "current_finding_index": state.get("current_finding_index", 0) + 1,
        "current_finding": {},
        "rag_query": "",
        "rag_docs": [],
        "rag_quality": {},
        "rag_attempts": 0,
        "validation": {},
        "explanation": "",
    }


def report_node(state: SecurityGraphState) -> Dict[str, Any]:
    enriched = state.get("enriched_findings", [])
    errors = state.get("errors", [])
    summary = {"high": 0, "medium": 0, "low": 0}

    for item in enriched:
        confidence = item.get("validation", {}).get("confidence", "LOW").upper()
        if confidence == "HIGH":
            summary["high"] += 1
        elif confidence == "MEDIUM":
            summary["medium"] += 1
        else:
            summary["low"] += 1

    return {
        "report": {
            "project_path": state.get("project_path"),
            "total_findings": len(enriched),
            "confidence_summary": summary,
            "findings": enriched,
            "errors": errors,
        }
    }


def should_continue_findings(state: SecurityGraphState) -> str:
    findings = state.get("normalized_findings", [])
    index = state.get("current_finding_index", 0)
    return "continue" if index < len(findings) else "report"


def should_retry_rag(state: SecurityGraphState) -> str:
    quality = state.get("rag_quality", {})
    attempts = state.get("rag_attempts", 0)
    max_attempts = state.get("max_rag_attempts", 2)

    if quality.get("passed"):
        return "validate"
    if attempts < max_attempts:
        return "retry"
    return "validate"


def grade_rag_evidence(finding: Dict[str, Any], docs: List[Dict[str, Any]]) -> Dict[str, Any]:
    expected_cwe = (finding.get("cwe") or finding.get("cwe_id") or "").upper()
    expected_category = str(finding.get("category", "")).lower()

    if not docs:
        return {
            "passed": False,
            "reason": "No RAG documents retrieved",
            "exact_cwe_match": False,
            "category_match": False,
            "best_similarity": 0,
            "expected_cwe": expected_cwe,
            "expected_category": expected_category,
        }

    similarities = [doc.get("similarity", 0) or 0 for doc in docs]
    best_similarity = max(similarities) if similarities else 0
    combined = " ".join(
        str(doc.get("text", "")) + " " + str(doc.get("metadata", {}))
        for doc in docs
    )
    combined_upper = combined.upper()
    combined_lower = combined.lower()
    exact_cwe_match = bool(expected_cwe and expected_cwe in combined_upper)

    category_match = False
    if expected_category:
        category_terms = [term for term in expected_category.split() if len(term) > 2]
        category_match = any(term in combined_lower for term in category_terms)

    if exact_cwe_match:
        passed = True
        reason = "Exact CWE match found in RAG evidence"
    elif category_match and best_similarity >= 0.75:
        passed = True
        reason = "Category match with strong similarity"
    else:
        passed = False
        reason = "RAG evidence does not strongly match expected CWE/category"

    return {
        "passed": passed,
        "reason": reason,
        "exact_cwe_match": exact_cwe_match,
        "category_match": category_match,
        "best_similarity": best_similarity,
        "expected_cwe": expected_cwe,
        "expected_category": expected_category,
    }


def strengthen_rag_query(finding: Dict[str, Any], previous_query: str) -> str:
    category = finding.get("category", "")
    cwe = finding.get("cwe") or finding.get("cwe_id") or ""
    owasp = finding.get("owasp", "")
    message = finding.get("message", "")
    rule_id = finding.get("rule_id", "")
    severity = finding.get("severity", "")
    code = finding.get("code_snippet", "")

    if "CWE-798" in cwe or "hardcoded" in category.lower():
        retrieval_terms = (
            "CWE-798 Use of Hard-coded Credentials Hardcoded Secret "
            "hardcoded API key token credential password exposure "
            "OWASP A07 Identification and Authentication Failures"
        )
    elif "CWE-327" in cwe or "weak cryptography" in category.lower():
        retrieval_terms = (
            "CWE-327 Use of Broken Cryptographic Algorithm "
            "weak cryptography MD5 SHA1 insecure hashing OWASP A02"
        )
    elif "CWE-89" in cwe or "sql injection" in category.lower():
        retrieval_terms = (
            "CWE-89 SQL Injection OWASP A03 Injection "
            "parameterized queries prepared statements SQL query user input"
        )
    elif "CWE-79" in cwe or "xss" in category.lower():
        retrieval_terms = (
            "CWE-79 Cross Site Scripting XSS OWASP A03 "
            "innerHTML output encoding sanitization"
        )
    elif "CWE-1104" in cwe or "vulnerable dependency" in category.lower():
        retrieval_terms = (
            "CWE-1104 Use of Unmaintained Third Party Components "
            "vulnerable dependency outdated component npm audit package vulnerability OWASP A06"
        )
    else:
        retrieval_terms = f"{cwe} {category} {owasp} {message} secure coding vulnerability remediation"

    return f"""
Retrieval Terms: {retrieval_terms}
Category: {category}
CWE: {cwe}
OWASP: {owasp}
Message: {message}
Rule: {rule_id}
Severity: {severity}
Code: {code}
Package: {finding.get("package", "")}
"""


def _apply_rag_quality_downgrade(
    validation: Dict[str, Any], rag_quality: Dict[str, Any]
) -> Dict[str, Any]:
    if rag_quality.get("passed"):
        return validation

    downgraded = dict(validation)
    evidence = dict(downgraded.get("evidence", {}))
    evidence["rag_supported"] = False
    downgraded["evidence"] = evidence
    if downgraded.get("confidence", "").upper() == "HIGH":
        downgraded["confidence"] = "MEDIUM"
    downgraded["final_decision"] = "Likely vulnerability - static scan supports it, but RAG evidence is weak"
    return downgraded


def infer_category(message: str, rule_id: str, cwe: str) -> str:
    text = f"{message} {rule_id} {cwe}".lower()

    if "sql injection" in text or "cwe-89" in text:
        return "SQL Injection"
    if "xss" in text or "cross-site scripting" in text or "innerhtml" in text or "cwe-79" in text:
        return "Cross-Site Scripting"
    if "command injection" in text or "exec" in text or "cwe-78" in text:
        return "Command Injection"
    if "eval" in text or "code injection" in text or "cwe-95" in text:
        return "Code Injection"
    if "secret" in text or "api key" in text or "token" in text or "cwe-798" in text:
        return "Hardcoded Secret"
    if "md5" in text or "sha1" in text or "crypto" in text or "cwe-327" in text:
        return "Weak Cryptography"
    if "cors" in text or "cwe-942" in text:
        return "Insecure CORS"
    if "path traversal" in text or "cwe-22" in text:
        return "Path Traversal"
    if "dependency" in text or "npm-audit" in text or "vulnerable package" in text or "outdated component" in text:
        return "Vulnerable Dependency"
    if "rate limit" in text or "cwe-307" in text:
        return "Missing Rate Limiting"

    return "Security Issue"


def build_rag_query(finding: Dict[str, Any]) -> str:
    category = finding.get("category", "Security Issue")
    cwe = finding.get("cwe", "CWE-Unknown")
    retrieval_terms = {
        "Hardcoded Secret": "CWE-798 Hardcoded Secret hardcoded API key credential exposure secret token environment variables",
        "SQL Injection": "CWE-89 SQL Injection prepared statements parameterized queries injection prevention",
        "Cross-Site Scripting": "CWE-79 Cross-Site Scripting XSS output encoding sanitization textContent",
        "Command Injection": "CWE-78 OS Command Injection shell injection safe subprocess execFile",
        "Code Injection": "CWE-95 Code Injection eval Function constructor unsafe code execution",
        "Weak Cryptography": "CWE-327 Weak Cryptography MD5 SHA1 weak hashing secure algorithms",
        "Insecure CORS": "CWE-942 Insecure CORS wildcard origin cross-origin resource sharing",
        "Path Traversal": "CWE-22 Path Traversal directory traversal canonicalization safe path",
        "Missing Rate Limiting": "CWE-307 Missing Rate Limiting brute force login rate limit",
        "Vulnerable Dependency": "CWE-1104 Vulnerable Dependency outdated component vulnerable package npm audit third party component OWASP A06",
    }.get(category, f"{category} {cwe}")

    return f"""
Retrieval Terms: {retrieval_terms}
Category: {category}
CWE: {cwe}
OWASP: {finding.get("owasp", "Unknown")}
Message: {finding.get("message", "")}
Rule: {finding.get("rule_id", "")}
Severity: {finding.get("severity", "")}
Code: {finding.get("code_snippet", "")}
Package: {finding.get("package", "")}
"""


def build_fallback_explanation(finding: Dict[str, Any], reason: str) -> str:
    category = finding.get("category", "Security Issue")
    cwe = finding.get("cwe", "CWE-Unknown")
    message = finding.get("message", "")
    return (
        f"{category} ({cwe}) was reported by static analysis. "
        f"Scanner message: {message}. "
        f"RAG evidence retrieval was unavailable, so confidence should remain LOW "
        f"unless another evidence layer confirms it. Retrieval error: {reason}"
    )


def _parse_query_fields(query: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for line in query.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            fields[key] = value
    return fields


def _short_error(exc: Exception) -> str:
    lines = [line.strip() for line in str(exc).splitlines() if line.strip()]
    return lines[-1] if lines else exc.__class__.__name__


def build_security_graph():
    graph = StateGraph(SecurityGraphState)

    graph.add_node("scan", scan_node)
    graph.add_node("normalize", normalize_node)
    graph.add_node("select_finding", select_finding_node)
    graph.add_node("rag", rag_node)
    graph.add_node("grade_rag", grade_rag_node)
    graph.add_node("rewrite_rag_query", rewrite_rag_query_node)
    graph.add_node("validate", validate_node)
    graph.add_node("enrich_finding", enrich_finding_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("scan")
    graph.add_edge("scan", "normalize")
    graph.add_conditional_edges(
        "normalize",
        should_continue_findings,
        {"continue": "select_finding", "report": "report"},
    )
    graph.add_edge("select_finding", "rag")
    graph.add_edge("rag", "grade_rag")
    graph.add_conditional_edges(
        "grade_rag",
        should_retry_rag,
        {"retry": "rewrite_rag_query", "validate": "validate"},
    )
    graph.add_edge("rewrite_rag_query", "rag")
    graph.add_edge("validate", "enrich_finding")
    graph.add_conditional_edges(
        "enrich_finding",
        should_continue_findings,
        {"continue": "select_finding", "report": "report"},
    )
    graph.add_edge("report", END)

    return graph.compile()


security_graph = build_security_graph()
