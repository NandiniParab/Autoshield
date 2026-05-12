# api/rag_routes.py
# FastAPI router for RAG endpoints.

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from rag.services.rag_service import analyze_vulnerability, analyze_batch
from rag.vector_store.chroma_client import get_collection_stats
from rag.services.self_rag import SelfRAG
from rag.services.llm_service import _call_llm

router = APIRouter(prefix="/rag", tags=["RAG"])


# ── Request Models ────────────────────────────────────────────────────────────

class VulnerabilityRequest(BaseModel):
    code_snippet: str = Field(..., description="The vulnerable code snippet")
    cwe_id: str = Field(..., description="CWE ID e.g. 'CWE-89'")
    severity: str = Field(..., description="low | medium | high | critical")
    vuln_type: Optional[str] = Field(None, description="Vulnerability type from static tool")
    # Extended fields used by Chrome extension
    file_path: Optional[str] = Field("unknown", description="File path or page URL")
    line: Optional[int] = Field(0, description="Line number (0 for browser extension)")
    tool: Optional[str] = Field("unknown", description="Scanner tool name")
    use_llm: Optional[bool] = Field(True, description="Whether to invoke LLM reasoning layer")


class BatchRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., description="List of static findings to analyze")
    use_llm: Optional[bool] = Field(False, description="LLM for batch (default off for speed)")


# ── NOTE: RAGResponse model removed ──────────────────────────────────────────
# Previously this route used response_model=RAGResponse which was a Pydantic
# model with only 5 fields (owasp_category, related_cves, exploitability,
# confidence, context_chunks). This caused FastAPI to STRIP the full verdict
# returned by build_final_verdict() — so risk_score, risk_category, reasoning,
# fix_code, key_risks, recommended_fix etc. never reached the Chrome extension.
#
# Fix: remove response_model so the full Dict is returned as-is.
# The Chrome extension sidepanel.js already knows how to render all these fields.
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/analyze")
async def analyze(request: VulnerabilityRequest):
    """
    Main RAG endpoint — Tri-Layer analysis (Static + RAG + LLM).

    Returns full verdict including:
      risk_score, risk_category, owasp_category, related_cves,
      key_risks, recommended_fix, fix_code, reasoning,
      conflict_resolution trace, score_components breakdown.

    Used by both the VS Code extension and Chrome extension sidepanel.
    """
    try:
        result = analyze_vulnerability(
            code_snippet=request.code_snippet,
            cwe_id=request.cwe_id,
            severity=request.severity,
            vuln_type=request.vuln_type or "",
            file_path=request.file_path or "unknown",
            line=request.line or 0,
            tool=request.tool or "unknown",
            use_llm=request.use_llm if request.use_llm is not None else True,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze-batch")
async def analyze_batch_endpoint(request: BatchRequest):
    """
    Batch analysis endpoint for multiple findings at once.
    Used by VS Code extension full-scan mode.
    LLM disabled by default for speed — enable with use_llm=true.
    """
    try:
        results = analyze_batch(
            findings=request.findings,
            use_llm=request.use_llm if request.use_llm is not None else False,
        )
        return {"results": results, "count": len(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health():
    """Check RAG system health and document count."""
    try:
        stats = get_collection_stats()
        return {
            "status": "ok",
            "collection": stats["name"],
            "documents_indexed": stats["count"],
        }
    except Exception as e:
        return {
            "status": "degraded",
            "error": str(e),
            "documents_indexed": 0,
        }


# ── Self-RAG ──────────────────────────────────────────────────────────────────

class SelfRAGRequest(BaseModel):
    query: str = Field(..., description="Natural-language security question or code issue")
    k: int = Field(default=5, description="Number of docs to retrieve", ge=1, le=20)
    static_findings: Optional[List[Dict[str, Any]]] = Field(
        default=[],
        description="Optional Semgrep/ESLint findings for the Evidence-Based Validator",
    )


@router.post(
    "/self-rag",
    summary="Self-RAG: smart retrieval with doc grading + query rewriting",
    tags=["RAG"],
)
def self_rag_query(request: SelfRAGRequest):
    """
    Self-Reflective RAG endpoint.

    Flow:
      1. Retrieve top-k chunks from ChromaDB.
      2. Grade: are the chunks actually relevant to the query?
      3. If weak → rewrite query using Groq/Llama → retrieve again.
      4. Generate a structured security answer from the (now good) docs.

    Returns:
      - original_query
      - query_used        (may differ if rewrite happened)
      - query_rewritten   (bool — whether step 3 fired)
      - documents_used    (list of retrieved chunks with similarity scores)
      - answer            (structured vulnerability analysis)
    """
    try:
        rag = SelfRAG()
        result = rag.run(
            query=request.query,
            k=request.k,
            static_findings=request.static_findings or [],
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Compliance Analysis ───────────────────────────────────────────────────────

class ComplianceRequest(BaseModel):
    page_url:    str = Field(...,  description="URL of the scanned page")
    security:    Dict[str, Any] = Field(default={}, description="Security data extracted by content.js")
    images:      List[Dict[str, Any]] = Field(default=[], description="Images extracted by content.js")
    videos:      List[Dict[str, Any]] = Field(default=[], description="Videos extracted by content.js")
    audios:      List[Dict[str, Any]] = Field(default=[], description="Audio elements")
    fonts:       List[Dict[str, Any]] = Field(default=[], description="Font sources")
    stylesheets: List[Dict[str, Any]] = Field(default=[], description="External stylesheets")
    text_blocks: List[Dict[str, Any]] = Field(default=[], description="Text blocks for plagiarism hints")
    iframe_embeds: List[Dict[str, Any]] = Field(default=[], description="Iframe embeds")
    license_indicators: Dict[str, Any] = Field(default={}, description="License indicators from page")


def _compliance_issue(category: str, title: str, severity: str, recommendation: str, evidence: str = "") -> Dict[str, Any]:
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "owasp": "A05: Security Misconfiguration",
        "recommendation": recommendation,
        "evidence": evidence,
    }


def _build_security_compliance_issues(request: ComplianceRequest) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    sec = request.security or {}
    meta = sec.get("metaTags", {}) or {}
    page_url = request.page_url or ""
    is_https = page_url.lower().startswith("https://")
    is_http = page_url.lower().startswith("http://")

    if is_http and "localhost" not in page_url and "127.0.0.1" not in page_url:
        issues.append(_compliance_issue("Transport Security", "HTTP instead of HTTPS", "HIGH", "Use HTTPS and redirect HTTP to HTTPS.", page_url))
    if not meta.get("csp"):
        issues.append(_compliance_issue("Security Headers", "Missing CSP", "HIGH", "Add a strict Content-Security-Policy header."))
    if is_https:
        issues.append(_compliance_issue("Security Headers", "Strict-Transport-Security must be verified server-side", "LOW", "Confirm the response includes Strict-Transport-Security. Browser content scripts cannot read this header."))
    if not meta.get("xFrameOptions"):
        issues.append(_compliance_issue("Security Headers", "Missing X-Frame-Options", "MEDIUM", "Add X-Frame-Options or CSP frame-ancestors."))
    if not meta.get("referrerPolicy"):
        issues.append(_compliance_issue("Security Headers", "Missing Referrer-Policy", "LOW", "Add Referrer-Policy: strict-origin-when-cross-origin."))

    mixed = sec.get("mixedContent", []) or []
    if mixed:
        issues.append(_compliance_issue("Mixed Content", "Mixed content HTTP resources", "HIGH", "Load all resources over HTTPS.", f"{len(mixed)} resource(s)"))

    inline_scripts = sec.get("inlineScripts", []) or []
    if inline_scripts:
        issues.append(_compliance_issue("Content Security Policy", "Inline scripts", "MEDIUM", "Move inline scripts to external files and enforce CSP without unsafe-inline.", f"{len(inline_scripts)} script(s)"))

    if any(s.get("hasEval") for s in inline_scripts) or any(p.get("pattern") == "eval()" for p in sec.get("dangerousPatterns", []) or []):
        issues.append(_compliance_issue("Code Execution", "eval usage", "HIGH", "Remove eval/new Function and replace it with safe parsing or dispatch.", "eval detected"))

    external_scripts = sec.get("externalScripts", []) or []
    no_sri = [s for s in external_scripts if s.get("isExternal") and not s.get("hasSRI")]
    if no_sri:
        issues.append(_compliance_issue("Supply Chain", "Third-party scripts without integrity", "MEDIUM", "Add integrity and crossorigin attributes to third-party scripts.", f"{len(no_sri)} script(s)"))

    storage = sec.get("storageUsage", {}) or {}
    exposed_storage = (storage.get("localStorage", []) or []) + (storage.get("sessionStorage", []) or [])
    if exposed_storage:
        issues.append(_compliance_issue("Secrets", "Exposed frontend secrets", "HIGH", "Do not store tokens, passwords, API keys, or secrets in browser storage.", ", ".join(x.get("key", "") for x in exposed_storage[:5])))

    for item in request.stylesheets:
        href = item.get("href", "")
        if is_https and href.startswith("http://"):
            issues.append(_compliance_issue("Mixed Content", "HTTP stylesheet on HTTPS page", "MEDIUM", "Load stylesheets over HTTPS.", href))

    return issues


def _score_compliance(issues: List[Dict[str, Any]]) -> int:
    weights = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 9, "LOW": 4, "REVIEW": 5}
    penalty = sum(weights.get(str(issue.get("severity", "LOW")).upper(), 4) for issue in issues)
    return max(0, min(100, 100 - penalty))


def _classify_assets_with_llm(page_url: str, assets_summary: str) -> Dict[str, Any]:
    """
    Ask the LLM to classify the asset domains dynamically.
    Returns a JSON-like dict with issues and clean lists.
    """
    prompt = f"""You are a web compliance analyst reviewing media assets found on a webpage.

Page URL: {page_url}

Assets found on this page:
{assets_summary}

For each asset, classify it as one of:
- FREE: Known free/open-source CDN, Google Fonts, Unsplash, Pixabay, Pexels, jsDelivr, cdnjs, unpkg, etc.
- LICENSED_EMBED: Official platform embeds (YouTube, Vimeo, Spotify, SoundCloud) — generally OK with their embed player.
- REVIEW_NEEDED: External asset from an unknown/uncommon domain — needs license verification.
- PAID_STOCK_WARNING: Domain is a paid stock site (Shutterstock, Getty Images, iStockPhoto, Adobe Stock, Alamy, Dreamstime, Depositphotos) — likely requires license.
- SELF_HOSTED: Relative URL or same-origin asset — no external compliance concern.

Return ONLY a JSON object in this exact format (no markdown):
{{
  "issues": [
    {{
      "type": "image|video|audio|font|stylesheet|text",
      "src": "...",
      "domain": "...",
      "severity": "HIGH|REVIEW",
      "issue": "short description",
      "recommendation": "what the developer should do"
    }}
  ],
  "clean": [
    {{
      "type": "image|video|audio|font|stylesheet|embed",
      "src": "...",
      "status": "free-source|ok|self-hosted",
      "note": "reason it is clean"
    }}
  ],
  "summary": {{
    "total_assets": 0,
    "issues_count": 0,
    "clean_count": 0,
    "paid_stock_warnings": 0,
    "free_assets": 0,
    "copyright_note": ""
  }}
}}
"""
    import json, re
    raw = _call_llm(prompt)
    raw = re.sub(r"```json|```", "", raw).strip()
    try:
        return json.loads(raw)
    except Exception:
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            return json.loads(match.group())
        return {"issues": [], "clean": [], "summary": {"total_assets": 0, "issues_count": 0, "clean_count": 0, "paid_stock_warnings": 0, "free_assets": 0, "copyright_note": ""}}


@router.post(
    "/compliance",
    summary="LLM-powered compliance analysis for page media assets",
    tags=["RAG"],
)
def analyze_compliance(request: ComplianceRequest):
    """
    Compliance endpoint — no hardcoded domain lists.

    Receives the page's assets (images, videos, audio, fonts, stylesheets,
    text blocks, embeds) extracted by the Chrome extension's content.js.

    Uses the Groq LLM to dynamically classify each asset as:
      - FREE (open CDN / free stock)
      - LICENSED_EMBED (YouTube/Vimeo/Spotify)
      - REVIEW_NEEDED (unknown external domain)
      - PAID_STOCK_WARNING (Shutterstock / Getty / Adobe Stock etc.)
      - SELF_HOSTED (same origin)

    Returns structured issues + clean list + summary — no hardcoded rules.
    """
    try:
        security_issues = _build_security_compliance_issues(request)

        # Build a concise text summary of all assets for the LLM
        lines = []

        for img in request.images[:30]:
            src = img.get("src", "")
            dom = img.get("domain", "")
            ext = img.get("isExternal", False)
            lines.append(f"IMAGE | domain={dom} | external={ext} | src={src[:120]}")

        for v in request.videos[:10]:
            src = v.get("src", "")
            dom = v.get("domain", "")
            lines.append(f"VIDEO | domain={dom} | src={src[:120]}")

        for a in request.audios[:10]:
            src = a.get("src", "")
            dom = a.get("domain", "")
            lines.append(f"AUDIO | domain={dom} | src={src[:120]}")

        for f in request.fonts[:15]:
            src = f.get("src", "")
            dom = f.get("domain", "")
            lines.append(f"FONT  | domain={dom} | src={src[:120]}")

        for s in request.stylesheets[:15]:
            href = s.get("href", "")
            dom = s.get("domain", "")
            ext = s.get("isExternal", False)
            sri = s.get("hasSRI", False)
            lines.append(f"CSS   | domain={dom} | external={ext} | sri={sri} | href={href[:120]}")

        for fr in request.iframe_embeds[:10]:
            src = fr.get("src", "")
            dom = fr.get("domain", "")
            is_yt = fr.get("isYouTube", False)
            is_vm = fr.get("isVimeo", False)
            lines.append(f"EMBED | domain={dom} | youtube={is_yt} | vimeo={is_vm} | src={src[:120]}")

        for tb in request.text_blocks[:5]:
            wc = tb.get("wordCount", 0)
            lines.append(f"TEXT  | words={wc} | preview={tb.get('text','')[:80]}")

        # Include license indicators as context
        li = request.license_indicators
        if li:
            lines.append(f"PAGE_META | copyright_text={li.get('copyrightText','')} | creative_commons={li.get('hasCreativeCommons',False)}")

        if not lines:
            return {
                "compliance_score": _score_compliance(security_issues),
                "issues": security_issues,
                "clean": [],
                "summary": {
                    "total_assets": 0,
                    "issues_count": len(security_issues),
                    "clean_count": 0,
                    "paid_stock_warnings": 0,
                    "free_assets": 0,
                    "copyright_note": li.get("copyrightText", "") if li else "",
                },
                "llm_used": False,
            }

        assets_summary = "\n".join(lines)
        result = _classify_assets_with_llm(request.page_url, assets_summary)
        result["issues"] = security_issues + result.get("issues", [])
        result["compliance_score"] = _score_compliance(result["issues"])
        result.setdefault("summary", {})
        result["summary"]["issues_count"] = len(result["issues"])
        result["summary"]["compliance_score"] = result["compliance_score"]
        result["llm_used"] = True
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

