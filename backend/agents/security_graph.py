import os
from typing import Any, Dict, List

from langgraph.graph import END, StateGraph

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

from agents.state import SecurityGraphState
from agents.nodes.context_agent import context_agent_node
from agents.nodes.data_flow_agent import data_flow_agent_node
from agents.nodes.report_agent import (
    build_remediation_plan,
    calculate_risk_score,
    get_risk_level,
    get_top_issues,
    group_findings,
)
from agents.nodes.runtime_agent import runtime_agent_node
from agents.nodes.scanner_agent import scanner_agent_node
from rag.services.self_rag import SelfRAG
from rag.services.vulnerability_validator import VulnerabilityValidator

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
        for key in ("package", "installed_version", "fixed_version", "url", "detected_by"):
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
        "cross_file_context": {},
        "data_flow": {},
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
    context = state.get("cross_file_context", {})
    flow = state.get("data_flow", {})
    query = state.get("rag_query") or build_rag_query(finding, context, flow)

    try:
        rag = SelfRAG(llm=GraphExplanationLLM())
        rag_result = rag.run(query, static_findings=[finding])
        return {
            "rag_query": query,
            "rag_docs": rag_result.get("documents_used", []),
            "explanation": rag_result.get("answer", ""),
            "validation": rag_result.get("validation", {}),
            "agent_trace": state.get("agent_trace", [])
            + [
                {
                    "agent": "RAG Agent",
                    "status": "completed",
                    "documents_used": len(rag_result.get("documents_used", [])),
                }
            ],
        }
    except Exception as exc:
        fallback_explanation = build_fallback_explanation(finding, str(exc))
        return {
            "rag_query": query,
            "rag_docs": [],
            "explanation": fallback_explanation,
            "validation": {},
            "agent_trace": state.get("agent_trace", [])
            + [
                {
                    "agent": "RAG Agent",
                    "status": "failed",
                    "error": _short_error(exc),
                }
            ],
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
        validation = _apply_runtime_validation(
            existing_validation,
            state.get("current_finding", {}),
            state.get("rag_quality", {}),
        )
        validation = _apply_rag_quality_downgrade(validation, state.get("rag_quality", {}))
        validation = _apply_data_flow_validation(validation, state.get("data_flow", {}))
        return {
            "validation": validation,
            "agent_trace": state.get("agent_trace", [])
            + [
                {
                    "agent": "Validation Agent",
                    "status": "completed",
                    "confidence": validation.get("confidence", "UNKNOWN"),
                }
            ],
        }

    finding = state.get("current_finding", {})
    rag_docs = state.get("rag_docs", [])
    explanation = state.get("explanation", "")
    validator = VulnerabilityValidator()

    validation = validator.validate(
        query=build_rag_query(
            finding,
            state.get("cross_file_context", {}),
            state.get("data_flow", {}),
        ),
        docs=rag_docs,
        static_findings=[finding],
        llm_answer=explanation,
    )

    validation = _apply_runtime_validation(validation, finding, state.get("rag_quality", {}))
    validation = _apply_rag_quality_downgrade(validation, state.get("rag_quality", {}))
    validation = _apply_data_flow_validation(validation, state.get("data_flow", {}))

    return {
        "validation": validation,
        "agent_trace": state.get("agent_trace", [])
        + [
            {
                "agent": "Validation Agent",
                "status": "completed",
                "confidence": validation.get("confidence", "UNKNOWN"),
            }
        ],
    }


def enrich_finding_node(state: SecurityGraphState) -> Dict[str, Any]:
    enriched = list(state.get("enriched_findings", []))
    finding = state.get("current_finding", {})

    enriched.append(
        {
            **finding,
            "rag_query": state.get("rag_query", ""),
            "rag_docs": state.get("rag_docs", []),
            "rag_quality": state.get("rag_quality", {}),
            "cross_file_context": state.get("cross_file_context", {}),
            "data_flow": state.get("data_flow", {}),
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
        "cross_file_context": {},
        "data_flow": {},
        "rag_attempts": 0,
        "validation": {},
        "explanation": "",
    }


def report_node(state: SecurityGraphState) -> Dict[str, Any]:
    enriched = state.get("enriched_findings", [])
    errors = state.get("errors", [])
    summary = {"high": 0, "medium": 0, "low": 0}
    agent_trace = state.get("agent_trace", []) + [
        {
            "agent": "Report Agent",
            "status": "completed",
            "findings_reported": len(enriched),
        }
    ]
    risk_score = calculate_risk_score(enriched)
    risk_level = get_risk_level(risk_score)
    groups = group_findings(enriched)
    top_issues = get_top_issues(enriched)
    remediation_plan = build_remediation_plan(enriched)

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
            "runtime_url": state.get("runtime_url"),
            "overall_risk_score": risk_score,
            "overall_risk_level": risk_level,
            "total_findings": len(enriched),
            "confidence_summary": summary,
            "grouped_summary": groups,
            "top_issues": top_issues,
            "remediation_plan": remediation_plan,
            "agent_trace": agent_trace,
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
    elif finding.get("tool") == "runtime-browser" and best_similarity >= 0.6:
        passed = True
        reason = "Runtime evidence supported by strong RAG similarity"
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


def _apply_runtime_validation(
    validation: Dict[str, Any],
    finding: Dict[str, Any],
    rag_quality: Dict[str, Any],
) -> Dict[str, Any]:
    if finding.get("tool") != "runtime-browser" or not rag_quality.get("passed"):
        return validation

    severity = str(finding.get("severity", "MEDIUM")).upper()
    confidence = "HIGH" if severity in ("HIGH", "CRITICAL", "MEDIUM") else "MEDIUM"
    return {
        **validation,
        "vulnerability_type": finding.get("category", validation.get("vulnerability_type", "Runtime Security")),
        "is_valid": True,
        "confidence": confidence,
        "evidence": {
            "static_scan_supported": True,
            "rag_supported": True,
            "llm_supported": True,
        },
        "final_decision": "Confirmed runtime finding - browser evidence and RAG context agree",
    }


def _apply_data_flow_validation(
    validation: Dict[str, Any],
    data_flow: Dict[str, Any],
) -> Dict[str, Any]:
    if not data_flow.get("confirmed"):
        return validation

    updated = dict(validation)
    evidence = dict(updated.get("evidence", {}))
    evidence["data_flow_supported"] = True
    updated["evidence"] = evidence

    if str(updated.get("confidence", "")).upper() == "MEDIUM":
        updated["confidence"] = "HIGH"
        updated["final_decision"] = (
            "Confirmed vulnerability - static scan, RAG, and data-flow evidence agree"
        )

    return updated


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
    if "security header" in text or "content-security-policy" in text or "x-frame-options" in text or "permissions-policy" in text:
        return "Security Headers"
    if "mixed content" in text or "external script loaded over http" in text:
        return "Mixed Content"
    if "inline script" in text or "content security policy" in text:
        return "Inline Script"
    if "external scripts without integrity" in text or "subresource integrity" in text or "sri" in text:
        return "Missing SRI"
    if "cookie" in text:
        return "Cookie Security"
    if "secret exposure" in text or "frontend secret" in text:
        return "Exposed Frontend Secret"
    if "rate limit" in text or "cwe-307" in text:
        return "Missing Rate Limiting"

    return "Security Issue"


def build_rag_query(
    finding: Dict[str, Any],
    context: Dict[str, Any] = None,
    flow: Dict[str, Any] = None,
) -> str:
    category = finding.get("category", "Security Issue")
    cwe = finding.get("cwe", "CWE-Unknown")
    context = context or {}
    flow = flow or {}
    related = context.get("related_files", [])
    sources = context.get("sources", [])
    sinks = context.get("sinks", [])
    call_chain_hints = context.get("call_chain_hints", [])
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
        "Security Headers": "CWE-693 Security Headers Content Security Policy X-Frame-Options Referrer-Policy Permissions-Policy OWASP A05",
        "Mixed Content": "CWE-319 Mixed Content HTTP resource loaded on HTTPS transport security OWASP A05",
        "Inline Script": "CWE-693 Inline Script Content Security Policy unsafe-inline OWASP A05",
        "Missing SRI": "CWE-829 Subresource Integrity external script without integrity supply chain OWASP A05",
        "Cookie Security": "CWE-614 Cookie Secure HttpOnly SameSite session cookie OWASP A05",
        "Secrets Exposure": "CWE-798 Exposed frontend secret API key token localStorage sessionStorage OWASP A07",
        "Exposed Frontend Secret": "CWE-798 Exposed frontend secret API key token localStorage sessionStorage OWASP A07",
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

Cross-file context:
Related files: {related}
Sources found: {sources}
Sinks found: {sinks}
Call chain hints: {call_chain_hints}

Data flow evidence:
{flow}
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

    graph.add_node("scan", scanner_agent_node)
    graph.add_node("runtime_scan", runtime_agent_node)
    graph.add_node("normalize", normalize_node)
    graph.add_node("select_finding", select_finding_node)
    graph.add_node("context", context_agent_node)
    graph.add_node("data_flow", data_flow_agent_node)
    graph.add_node("rag", rag_node)
    graph.add_node("grade_rag", grade_rag_node)
    graph.add_node("rewrite_rag_query", rewrite_rag_query_node)
    graph.add_node("validate", validate_node)
    graph.add_node("enrich_finding", enrich_finding_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("runtime_scan")
    graph.add_edge("runtime_scan", "scan")
    graph.add_edge("scan", "normalize")
    graph.add_conditional_edges(
        "normalize",
        should_continue_findings,
        {"continue": "select_finding", "report": "report"},
    )
    graph.add_edge("select_finding", "context")
    graph.add_edge("context", "data_flow")
    graph.add_edge("data_flow", "rag")
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
