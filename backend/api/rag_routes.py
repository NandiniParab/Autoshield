# api/rag_routes.py
# FastAPI router for RAG endpoints.

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from rag.services.rag_service import analyze_vulnerability
from rag.vector_store.chroma_client import get_collection_stats

router = APIRouter(prefix="/rag", tags=["RAG"])


class VulnerabilityRequest(BaseModel):
    code_snippet: str = Field(..., description="The vulnerable code snippet")
    cwe_id: str = Field(..., description="CWE ID e.g. 'CWE-89'")
    severity: str = Field(..., description="low | medium | high | critical")
    vuln_type: Optional[str] = Field(None, description="Vulnerability type from static tool")


class CVEReference(BaseModel):
    cve_id: str
    severity: str
    cvss_score: str
    summary: str
    similarity: float


class RAGResponse(BaseModel):
    owasp_category: str
    related_cves: List[Dict]
    exploitability: str
    confidence: float
    context_chunks: List[Dict]


@router.post("/analyze", response_model=RAGResponse)
async def analyze(request: VulnerabilityRequest):
    """
    Main RAG endpoint.
    Takes vulnerability context and returns security intelligence.
    """
    try:
        result = analyze_vulnerability(
            code_snippet=request.code_snippet,
            cwe_id=request.cwe_id,
            severity=request.severity,
            vuln_type=request.vuln_type or "",
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health():
    """Check RAG system health and document count."""
    stats = get_collection_stats()
    return {
        "status": "ok",
        "collection": stats["name"],
        "documents_indexed": stats["count"],
    }