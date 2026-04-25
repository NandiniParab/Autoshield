# rag/services/conflict_resolver.py
# Conflict Resolution Engine — the main research innovation.
#
# Three paths produce verdicts:
#   Path A: Static tools (Semgrep, ESLint)        → deterministic
#   Path B: RAG context (OWASP, CVE, CWE)         → knowledge-based
#   Path C: LLM reasoning                          → probabilistic
#
# This engine fuses all three and resolves conflicts.
# LLM is an "expert witness" — NOT the final judge.

from typing import Dict, List, Optional

# Severity ordering for comparison
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_FROM_INT = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


def normalize_severity(sev: str) -> str:
    """Normalizes severity string to lowercase standard."""
    sev = (sev or "medium").lower().strip()
    mapping = {
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "info": "info",
        "informational": "info",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    return mapping.get(sev, "medium")


def severities_agree(sev_a: str, sev_b: str, tolerance: int = 1) -> bool:
    """
    Returns True if two severities are within `tolerance` levels of each other.
    e.g., "high" and "medium" agree with tolerance=1
    """
    a = SEVERITY_ORDER.get(normalize_severity(sev_a), 2)
    b = SEVERITY_ORDER.get(normalize_severity(sev_b), 2)
    return abs(a - b) <= tolerance


def resolve(
    static_severity: str,
    llm_result: Dict,
    rag_context: List[Dict],
    owasp_category: str,
    exploitability: str,
) -> Dict:
    """
    Main conflict resolution logic.

    Resolution rules (in priority order):
    1. If static + LLM agree → accept result directly
    2. If LLM flags false positive with high confidence → reduce severity
    3. If RAG shows high exploitability → trust static scanner
    4. If LLM increases severity with high confidence → elevate
    5. Default → trust static scanner (conservative approach)

    Returns a resolution dict with final_severity and resolution_path.
    """
    static_sev = normalize_severity(static_severity)
    llm_sev = normalize_severity(llm_result.get("severity_assessment", static_sev))
    llm_confidence = float(llm_result.get("confidence", 0.5))
    llm_available = llm_result.get("llm_available", False)
    false_positive_likelihood = float(llm_result.get("false_positive_likelihood", 0.2))
    llm_adjustment = int(llm_result.get("severity_adjustment", 0))
    rag_exploitability = exploitability or llm_result.get("exploitability", "medium")

    resolution_path = []

    # ── Rule 1: Agreement ──────────────────────────────────────────────
    if llm_available and severities_agree(static_sev, llm_sev, tolerance=1):
        resolution_path.append("RULE_1_AGREEMENT")
        final_sev = static_sev  # Static wins on ties (deterministic)
        conflict = False

    # ── Rule 2: LLM flags false positive with high confidence ──────────
    elif llm_available and false_positive_likelihood > 0.7 and llm_confidence > 0.75:
        resolution_path.append("RULE_2_FALSE_POSITIVE_SUPPRESSED")
        final_sev = "low"  # Downgrade but don't eliminate
        conflict = True

    # ── Rule 3: High exploitability from RAG → trust static ───────────
    elif rag_exploitability in ("high",) and static_sev in ("high", "critical"):
        resolution_path.append("RULE_3_RAG_EXPLOITABILITY_CONFIRMS_STATIC")
        final_sev = static_sev
        conflict = llm_available and not severities_agree(static_sev, llm_sev)

    # ── Rule 4: LLM increases severity with high confidence ───────────
    elif llm_available and llm_adjustment >= 1 and llm_confidence > 0.8:
        static_int = SEVERITY_ORDER.get(static_sev, 2)
        elevated_int = min(4, static_int + llm_adjustment)
        final_sev = SEVERITY_FROM_INT[elevated_int]
        resolution_path.append(f"RULE_4_LLM_ELEVATED_TO_{final_sev.upper()}")
        conflict = True

    # ── Rule 5: LLM decreases severity with high confidence ───────────
    elif llm_available and llm_adjustment <= -1 and llm_confidence > 0.8:
        static_int = SEVERITY_ORDER.get(static_sev, 2)
        reduced_int = max(0, static_int + llm_adjustment)
        final_sev = SEVERITY_FROM_INT[reduced_int]
        resolution_path.append(f"RULE_5_LLM_REDUCED_TO_{final_sev.upper()}")
        conflict = True

    # ── Default: Trust static scanner (conservative) ──────────────────
    else:
        resolution_path.append("RULE_DEFAULT_STATIC_TRUSTED")
        final_sev = static_sev
        conflict = llm_available and not severities_agree(static_sev, llm_sev)

    # ── RAG tie-breaker when conflict exists ──────────────────────────
    if conflict and rag_context:
        rag_result = _rag_tiebreaker(
            static_sev, llm_sev, rag_context, owasp_category
        )
        if rag_result:
            final_sev = rag_result
            resolution_path.append(f"RAG_TIEBREAKER_RESOLVED_TO_{final_sev.upper()}")

    return {
        "final_severity": final_sev,
        "static_severity": static_sev,
        "llm_severity": llm_sev if llm_available else "unavailable",
        "conflict_detected": conflict,
        "resolution_path": " → ".join(resolution_path),
        "llm_confidence": llm_confidence,
        "false_positive_likelihood": false_positive_likelihood,
        "rag_exploitability": rag_exploitability,
    }


def _rag_tiebreaker(
    static_sev: str,
    llm_sev: str,
    rag_context: List[Dict],
    owasp_category: str,
) -> Optional[str]:
    """
    Uses RAG context to break ties between static and LLM.
    Looks at similarity scores and source reliability.
    Returns resolved severity or None if inconclusive.
    """
    if not rag_context:
        return None

    # Compute weighted exploitability from RAG chunks
    high_relevance_chunks = [r for r in rag_context if r.get("similarity", 0) > 0.7]

    if not high_relevance_chunks:
        return None

    # Check if OWASP source confirms high severity
    owasp_chunks = [
        r for r in high_relevance_chunks
        if r.get("metadata", {}).get("source") == "OWASP"
        or r.get("source") == "OWASP"
    ]

    if owasp_chunks:
        # OWASP source is authoritative — trust static scanner
        return static_sev

    # If only CVE data and it's high severity, trust static
    cve_chunks = [
        r for r in high_relevance_chunks
        if r.get("metadata", {}).get("source") == "CVE"
        or r.get("source") == "CVE"
    ]

    if cve_chunks:
        avg_sim = sum(c.get("similarity", 0) for c in cve_chunks) / len(cve_chunks)
        if avg_sim > 0.8 and SEVERITY_ORDER.get(static_sev, 2) >= 2:
            return static_sev

    # Inconclusive — return None, caller keeps existing decision
    return None