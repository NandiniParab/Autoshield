# backend/api/fix_routes.py
#
# FastAPI router for the Safe Fix Generator pipeline.
#
# Endpoints:
#   POST /api/generate-fix        → validated patch (with retry logic)
#   POST /api/explain-vulnerability → human-readable "Learn About This Issue"
#
# Architecture:
#   code + vuln type
#     ↓  Self-RAG retrieves CWE/OWASP evidence
#     ↓  FixGenerator asks LLM, validates patch, retries on failure
#     ↓  Returns fixed_code + full validation report
#
# The VS Code extension shows "Preview Fix" / "Apply Fix" buttons —
# the fix is NEVER auto-applied without user confirmation.

from typing import List, Dict, Any, Optional
import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from rag.services.fix_generator import FixGenerator
from rag.services.self_rag import SelfRAG, GroqLLM
from rag.services.llm_service import _call_llm

router = APIRouter()

# ── LLM singleton (reuse project's Groq wrapper) ────────────────────────────
_llm = GroqLLM()


# ── Request / Response Models ────────────────────────────────────────────────

class FixRequest(BaseModel):
    language: str = Field(
        ...,
        description="Programming language: python | javascript | typescript | java | go | …",
    )
    vulnerability_type: str = Field(
        ...,
        description="Vulnerability name, e.g. 'SQL Injection', 'XSS', 'Hardcoded Secret'",
    )
    code: str = Field(..., description="The vulnerable code snippet")
    query: Optional[str] = Field(
        None,
        description="Optional search query for RAG retrieval. Defaults to vulnerability_type.",
    )
    evidence: Optional[List[Dict[str, Any]]] = Field(
        default=[],
        description="Pre-fetched RAG evidence docs. If empty, Self-RAG retrieves them.",
    )


class ExplainRequest(BaseModel):
    vulnerability_type: str = Field(
        ...,
        description="Vulnerability name, e.g. 'SQL Injection'",
    )
    code: Optional[str] = Field(
        None,
        description="Optional code snippet for context-aware explanation",
    )
    cwe_id: Optional[str] = Field(
        None,
        description="Optional CWE ID, e.g. 'CWE-89'",
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _retrieve_evidence(query: str) -> List[Dict[str, Any]]:
    """
    Runs Self-RAG to retrieve relevant CWE/OWASP evidence chunks.
    Returns the documents_used list from the RAG result.
    """
    try:
        rag = SelfRAG(llm=_llm)
        rag_result = rag.run(query)
        return rag_result.get("documents_used", [])
    except Exception as e:
        print(f"[FixRoutes] Self-RAG evidence fallback for {query}: {e}")
        return _fallback_evidence(query)


def _fallback_evidence(query: str) -> List[Dict[str, Any]]:
    q = query.lower()
    if "xss" in q or "cross-site scripting" in q or "cross site scripting" in q or "cwe-79" in q:
        return [
            {
                "text": "CWE-79 Cross-Site Scripting happens when untrusted data is inserted into a web page without output encoding or sanitization.",
                "source": "CWE",
                "similarity": 0.82,
            },
            {
                "text": "OWASP A03 Injection includes XSS. Prefer textContent for plain text, or sanitize HTML with a trusted sanitizer before insertion.",
                "source": "OWASP",
                "similarity": 0.8,
            },
        ]
    return []


def _deterministic_fix(language: str, vulnerability_type: str, code: str) -> Optional[Dict[str, Any]]:
    vuln = vulnerability_type.lower()
    if not ("xss" in vuln or "cross-site scripting" in vuln or "cross site scripting" in vuln):
        return None

    match = re.search(r"^(?P<lhs>.+?)\.innerHTML\s*=\s*(?P<rhs>.*?);?\s*$", code.strip())
    if not match:
        return None

    rhs = match.group("rhs").strip() or '""'
    fixed_code = f"{match.group('lhs')}.textContent = {rhs.rstrip(';')};"
    validation = FixGenerator().validator.validate_patch(
        language=language,
        vulnerability_type=vulnerability_type,
        original_code=code,
        fixed_code=fixed_code,
    )
    return {
        "success": validation.get("passed", False),
        "fixed_code": fixed_code,
        "validation": validation,
        "attempts": [{"attempt": 0, "validation": validation, "source": "deterministic"}],
        "explanation": "Replaced innerHTML with textContent so the value is rendered as text instead of executable HTML.",
    }


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post(
    "/generate-fix",
    summary="Safe Fix Generator — validated patch with retry",
    tags=["Fix Generator"],
)
def generate_fix(request: FixRequest):
    """
    Generates a validated, safe code patch for a detected vulnerability.

    Pipeline:
      1. If no evidence provided → run Self-RAG to retrieve CWE/OWASP docs.
      2. FixGenerator asks the LLM to produce a corrected version.
      3. PatchValidator checks syntax, dangerous patterns, and vuln removal.
      4. If validation fails → retry up to 3 times with error context.
      5. Return the patch + full validation report.

    The VS Code extension MUST show "Preview Fix" before allowing "Apply Fix".
    Never auto-apply this result without user confirmation.

    Returns:
        {
          "success": bool,
          "fixed_code": str,
          "validation": { "passed": bool, "syntax_check": {…}, … },
          "attempts": [...],        // per-attempt log
          "message": str            // only when success=False
        }
    """
    try:
        deterministic = _deterministic_fix(
            language=request.language,
            vulnerability_type=request.vulnerability_type,
            code=request.code,
        )
        if deterministic:
            return deterministic

        evidence = request.evidence or []
        if not evidence:
            query = request.query or request.vulnerability_type
            evidence = _retrieve_evidence(query)

        generator = FixGenerator(llm=_llm)
        result = generator.generate_fix(
            language=request.language,
            vulnerability_type=request.vulnerability_type,
            original_code=request.code,
            evidence=evidence,
        )

        # ── Explicit rejection gate ──────────────────────────────────
        # If validation did not pass, return a structured failure response.
        # The extension MUST check result["success"] before applying anything.
        # This prevents invalid AI output from ever reaching a file on disk.
        if not result.get("success"):
            return {
                "success": False,
                "message": result.get(
                    "message",
                    "Generated fix failed syntax/security validation. Patch not applied.",
                ),
                "validation": result.get("validation", {}),
                "attempts": result.get("attempts", []),
                # Return the rejected code only for display/debugging —
                # the extension must NOT apply it.
                "fixed_code": result.get("fixed_code", ""),
            }

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/explain-vulnerability",
    summary="Learn About This Issue — human-friendly vulnerability explainer",
    tags=["Fix Generator"],
)
def explain_vulnerability(request: ExplainRequest):
    """
    Returns a clear, structured explanation of a vulnerability for developers
    who want to understand *why* the issue is dangerous before applying a fix.

    Sections returned:
      • what_is_it      — plain-English description
      • how_it_works    — step-by-step attack scenario
      • real_world      — historical examples / CVEs
      • why_dangerous   — business / security impact
      • how_to_fix      — high-level remediation strategy
      • cwe_owasp       — CWE ID + OWASP mapping
      • further_reading — curated links

    This powers the "Learn About This Issue" button in the VS Code extension.
    """
    try:
        vuln_type = request.vulnerability_type
        cwe_id = request.cwe_id or "unknown"
        code_context = ""
        if request.code:
            code_context = f"\n\nVulnerable code snippet:\n```\n{request.code[:600]}\n```"

        prompt = f"""You are AutoShield's security educator. Explain this vulnerability clearly to a developer.

Vulnerability: {vuln_type}
CWE: {cwe_id}{code_context}

Return ONLY a JSON object with these exact keys (no markdown wrapper):
{{
  "what_is_it": "Plain English: what is {vuln_type}?",
  "how_it_works": "Step-by-step: how does an attacker exploit this?",
  "real_world": "Historical CVEs or famous incidents involving this vulnerability.",
  "why_dangerous": "What damage can it cause? (data theft, account takeover, RCE, etc.)",
  "how_to_fix": "High-level remediation strategy (not specific code).",
  "cwe_owasp": "CWE ID and OWASP Top 10 category this belongs to.",
  "further_reading": ["URL1", "URL2"]
}}

Use factual, authoritative information. Do NOT hallucinate CVEs or URLs.
"""

        import json, re

        raw = _call_llm(prompt)
        raw = re.sub(r"```json|```", "", raw).strip()

        try:
            data = json.loads(raw)
        except Exception:
            match = re.search(r"\{.*\}", raw, re.DOTALL)
            if match:
                data = json.loads(match.group())
            else:
                # Graceful fallback — return raw text in structured form
                data = {
                    "what_is_it": raw,
                    "how_it_works": "",
                    "real_world": "",
                    "why_dangerous": "",
                    "how_to_fix": "",
                    "cwe_owasp": cwe_id,
                    "further_reading": [],
                }

        data["vulnerability_type"] = vuln_type
        return data

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
