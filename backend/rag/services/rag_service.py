# rag/services/rag_service.py
# Orchestrates retrieval and formats the final output.
# This is the ONLY layer the API routes should talk to.

from typing import Dict, List
from rag.retrieval.retriever import retrieve_context
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
    """
    Extract the most relevant OWASP category from retrieved results.
    Priority: OWASP source > CWE with owasp_id > fallback.
    """
    # First: look for direct OWASP source hit
    for r in results:
        if r["metadata"].get("source") == "OWASP":
            cat = r["metadata"].get("category", "")
            if cat:
                return cat

    # Second: look for CWE with owasp_id
    for r in results:
        owasp_id = r["metadata"].get("owasp_id", "")
        if owasp_id in OWASP_CATEGORIES:
            return OWASP_CATEGORIES[owasp_id]

    return "Unknown"


def extract_related_cves(results: List[Dict], max_cves: int = 3) -> List[Dict]:
    """Extract CVE references from retrieved results."""
    cves = []
    for r in results:
        meta = r["metadata"]
        if meta.get("source") == "CVE":
            cves.append({
                "cve_id": meta.get("cve_id", "N/A"),
                "severity": meta.get("severity", "unknown"),
                "cvss_score": meta.get("cvss_score", "N/A"),
                "summary": r["text"][:300],  # short preview
                "similarity": r["similarity"],
            })
        if len(cves) >= max_cves:
            break
    return cves


def compute_confidence(results: List[Dict]) -> float:
    """
    Confidence = average similarity of top-3 results.
    Capped at 0.99 to avoid false certainty.
    """
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
) -> Dict:
    """
    Main service method. Call this from API routes.
    
    Returns structured RAG context for a given vulnerability.
    """
    severity = severity.lower().strip()

    # Retrieve relevant security knowledge
    results = retrieve_context(
        code_snippet=code_snippet,
        cwe_id=cwe_id,
        severity=severity,
        vuln_type=vuln_type,
        top_k=config.TOP_K_RESULTS,
    )

    if not results:
        return {
            "owasp_category": "Unknown",
            "related_cves": [],
            "exploitability": "unknown",
            "confidence": 0.0,
            "context_chunks": [],
        }

    return {
        "owasp_category": extract_owasp_category(results),
        "related_cves": extract_related_cves(results),
        "exploitability": SEVERITY_EXPLOITABILITY.get(severity, "medium"),
        "confidence": compute_confidence(results),
        "context_chunks": [  # Include top 3 chunks for LLM later
            {"text": r["text"], "source": r["metadata"].get("source"), "similarity": r["similarity"]}
            for r in results[:3]
        ],
    }