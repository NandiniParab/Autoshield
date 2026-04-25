# rag/services/rag_service.py
# Orchestrates the full Tri-Layer + Triple-Path analysis.
#
# Path A: Static tools (inputs from caller)
# Path B: RAG retrieval (this file)
# Path C: LLM reasoning (llm_service.py)
# Fusion: conflict_resolver.py → risk_engine.py

from typing import Dict, List, Optional
from rag.retrieval.retriever import retrieve_context
from rag.services.llm_service import analyze_with_llm
from rag.services.conflict_resolver import resolve, normalize_severity
from rag.services.risk_engine import build_final_verdict
from rag.config import config


# Maps CVSS score ranges to exploitability labels
SEVERITY_EXPLOITABILITY = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

# OWASP ID → category name lookup
OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}


def extract_owasp_category(results: List[Dict]) -> str:
    for r in results:
        if r["metadata"].get("source") == "OWASP":
            cat = r["metadata"].get("category", "")
            if cat:
                return cat
    for r in results:
        owasp_id = r["metadata"].get("owasp_id", "")
        if owasp_id in OWASP_CATEGORIES:
            return OWASP_CATEGORIES[owasp_id]
    return "Unknown"


def extract_related_cves(results: List[Dict], max_cves: int = 3) -> List[Dict]:
    cves = []
    for r in results:
        meta = r["metadata"]
        if meta.get("source") == "CVE":
            cves.append({
                "cve_id": meta.get("cve_id", "N/A"),
                "severity": meta.get("severity", "unknown"),
                "cvss_score": meta.get("cvss_score", "N/A"),
                "summary": r["text"][:300],
                "similarity": r["similarity"],
            })
        if len(cves) >= max_cves:
            break
    return cves


def compute_confidence(results: List[Dict]) -> float:
    if not results:
        return 0.0
    top3 = results[:3]
    avg = sum(r["similarity"] for r in top3) / len(top3)
    return round(min(0.99, avg), 2)


def analyze_vulnerability(
    code_snippet: str,
    cwe_id: str,
    severity: str,
    vuln_type: str = "",
    # Optional static context for richer LLM prompting
    static_findings: Optional[List[Dict]] = None,
    file_path: str = "unknown",
    line: int = 0,
    tool: str = "unknown",
    use_llm: bool = True,
) -> Dict:
    """
    Full Tri-Layer analysis pipeline.

    Path A (static) → Path B (RAG) → Path C (LLM)
    → Conflict Resolution → Risk Scoring → Final Verdict

    Args:
        use_llm: Set False to skip LLM (faster, cheaper, for batch scanning)
    """
    severity = normalize_severity(severity)

    # ── Path B: RAG Retrieval ─────────────────────────────────────────
    rag_raw = retrieve_context(
        code_snippet=code_snippet,
        cwe_id=cwe_id,
        severity=severity,
        vuln_type=vuln_type,
        top_k=config.TOP_K_RESULTS,
    )

    if not rag_raw:
        # No RAG results — build minimal response
        from rag.services.llm_service import _fallback_response
        llm_result = _fallback_response(severity, "No RAG context available")
        rag_result = {
            "owasp_category": "Unknown",
            "related_cves": [],
            "exploitability": SEVERITY_EXPLOITABILITY.get(severity, "medium"),
            "confidence": 0.0,
            "context_chunks": [],
        }
    else:
        rag_result = {
            "owasp_category": extract_owasp_category(rag_raw),
            "related_cves": extract_related_cves(rag_raw),
            "exploitability": SEVERITY_EXPLOITABILITY.get(severity, "medium"),
            "confidence": compute_confidence(rag_raw),
            "context_chunks": [
                {
                    "text": r["text"],
                    "source": r["metadata"].get("source"),
                    "similarity": r["similarity"],
                }
                for r in rag_raw[:3]
            ],
        }

        # ── Path C: LLM Reasoning ─────────────────────────────────────
        if use_llm:
            llm_result = analyze_with_llm(
                code_snippet=code_snippet,
                cwe_id=cwe_id,
                severity=severity,
                vuln_type=vuln_type,
                rag_context=rag_result["context_chunks"],
                static_findings=static_findings,
            )
        else:
            from rag.services.llm_service import _fallback_response
            llm_result = _fallback_response(severity, "LLM disabled for this request")

    # ── Conflict Resolution ────────────────────────────────────────────
    conflict_resolution = resolve(
        static_severity=severity,
        llm_result=llm_result,
        rag_context=rag_result.get("context_chunks", []),
        owasp_category=rag_result.get("owasp_category", "Unknown"),
        exploitability=rag_result.get("exploitability", "medium"),
    )

    # ── Final Verdict ──────────────────────────────────────────────────
    return build_final_verdict(
        code_snippet=code_snippet,
        cwe_id=cwe_id,
        static_severity=severity,
        vuln_type=vuln_type,
        file_path=file_path,
        line=line,
        tool=tool,
        rag_result=rag_result,
        llm_result=llm_result,
        conflict_resolution=conflict_resolution,
    )


def analyze_batch(findings: List[Dict], use_llm: bool = True) -> List[Dict]:
    """
    Runs full analysis on a list of static findings.
    Used by the /analyze-full endpoint.

    Each finding should have: tool, file_path, line, message, severity
    The caller provides cwe_id and vuln_type if known.
    """
    results = []
    for finding in findings:
        try:
            verdict = analyze_vulnerability(
                code_snippet=finding.get("message", ""),  # best available context
                cwe_id=finding.get("cwe_id", "CWE-Unknown"),
                severity=finding.get("severity", "medium"),
                vuln_type=finding.get("vuln_type", finding.get("message", "")),
                static_findings=[finding],
                file_path=finding.get("file_path", "unknown"),
                line=finding.get("line", 0),
                tool=finding.get("tool", "unknown"),
                use_llm=use_llm,
            )
            results.append(verdict)
        except Exception as e:
            print(f"[RAGService] Error analyzing finding: {e}")
            # Include a minimal error entry so we don't drop findings silently
            results.append({
                "vulnerability_id": f"error::{finding.get('file_path', '')}:{finding.get('line', 0)}",
                "file_path": finding.get("file_path", "unknown"),
                "line": finding.get("line", 0),
                "tool": finding.get("tool", "unknown"),
                "final_severity": normalize_severity(finding.get("severity", "medium")),
                "risk_score": 50.0,
                "risk_category": "MEDIUM",
                "error": str(e),
            })
    return results