# backend/main.py

import asyncio
import sys

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import List, Optional
import models
import database
import scanner
from crawler import scan_website_runtime

# RAG imports
from rag.retrieval.retriever import retrieve_context
from rag.services.rag_service import analyze_vulnerability, analyze_batch

app = FastAPI(title="AutoShield API", version="2.0.0")

# ──────────────────────────────────────────────────────────────────────
# CORS
# ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────────────────
# Request / Response Models
# ──────────────────────────────────────────────────────────────────────
class RAGRequest(BaseModel):
    code_snippet: str = Field(..., description="The vulnerable code or message")
    cwe_id: str = Field(default="CWE-Unknown", description="CWE ID e.g. CWE-89")
    severity: str = Field(default="medium", description="low | medium | high | critical")
    vuln_type: str = Field(default="", description="Vulnerability type label")
    file_path: str = Field(default="unknown")
    line: int = Field(default=0)
    tool: str = Field(default="unknown")
    use_llm: bool = Field(default=True, description="Set false to skip LLM for speed")


class FullScanRequest(BaseModel):
    """Request body for the full tri-layer scan of a project path."""
    path: str = Field(..., description="Absolute path to the project directory")
    use_llm: bool = Field(default=True, description="Enable LLM reasoning (slower, richer)")


# ──────────────────────────────────────────────────────────────────────
# Startup
# ──────────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup():
    models.Base.metadata.create_all(bind=database.engine)


# ──────────────────────────────────────────────────────────────────────
# Health Check
# ──────────────────────────────────────────────────────────────────────
@app.get("/")
def health_check():
    return {"status": "AutoShield Backend Online", "version": "2.0.0"}


# ──────────────────────────────────────────────────────────────────────
# Static Code Analysis (Path A only — fast)
# ──────────────────────────────────────────────────────────────────────
@app.post("/analyze-code")
def analyze_code(path: str, db: Session = Depends(database.get_db)):
    """
    Runs Semgrep + ESLint only. No RAG, no LLM.
    Use /analyze-full for the complete tri-layer analysis.
    """
    try:
        findings = scanner.run_scanners(path)
        for f in findings:
            db_vuln = models.Vulnerability(**f)
            db.add(db_vuln)
        db.commit()
        return {"count": len(findings), "results": findings}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────────────────────────────
# FULL TRI-LAYER ANALYSIS (Path A + B + C)  ← MAIN NEW ENDPOINT
# ──────────────────────────────────────────────────────────────────────
@app.post("/analyze-full")
def analyze_full(request: FullScanRequest, db: Session = Depends(database.get_db)):
    """
    Complete AutoShield analysis pipeline:
      Path A: Semgrep + ESLint (static)
      Path B: RAG retrieval (OWASP/CVE/CWE context)
      Path C: LLM reasoning (expert validation)
      → Conflict Resolution → Risk Scoring → Final Verdict

    Returns enriched findings with risk scores, OWASP categories,
    CVE references, conflict traces, and fix recommendations.
    """
    try:
        # ── Step 1: Run static scanners (Path A) ──────────────────────
        static_findings = scanner.run_scanners(request.path)

        if not static_findings:
            return {
                "status": "clean",
                "message": "No static findings detected.",
                "count": 0,
                "results": [],
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            }

        # Save raw findings to DB
        scan_record = models.Scan(scan_type="full", status="processing")
        db.add(scan_record)
        db.flush()

        for f in static_findings:
            db_vuln = models.Vulnerability(scan_id=scan_record.id, **f)
            db.add(db_vuln)

        # ── Step 2: Run RAG + LLM on each finding (Path B + C) ────────
        enriched = analyze_batch(static_findings, use_llm=request.use_llm)

        # ── Step 3: Build summary ──────────────────────────────────────
        summary = _build_summary(enriched)

        scan_record.status = "completed"
        db.commit()

        return {
            "status": "completed",
            "count": len(enriched),
            "results": enriched,
            "summary": summary,
            "llm_enabled": request.use_llm,
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────────────────────────────
# SINGLE VULNERABILITY RAG+LLM ANALYSIS
# ──────────────────────────────────────────────────────────────────────
@app.post("/rag/analyze")
def rag_analyze(payload: RAGRequest):
    """
    Analyzes a single vulnerability snippet through the full pipeline.
    Use this for on-demand analysis from the VS Code extension sidebar
    or when a user right-clicks a finding.
    """
    try:
        result = analyze_vulnerability(
            code_snippet=payload.code_snippet,
            cwe_id=payload.cwe_id,
            severity=payload.severity,
            vuln_type=payload.vuln_type,
            file_path=payload.file_path,
            line=payload.line,
            tool=payload.tool,
            use_llm=payload.use_llm,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────────────────────────────
# RAG HEALTH + STATS
# ──────────────────────────────────────────────────────────────────────
@app.get("/rag/health")
def rag_health():
    """Check RAG system status and document count."""
    try:
        from rag.vector_store.chroma_client import get_collection_stats
        stats = get_collection_stats()
        return {
            "status": "ok",
            "collection": stats["name"],
            "documents_indexed": stats["count"],
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ──────────────────────────────────────────────────────────────────────
# Runtime Analysis (Playwright)
# ──────────────────────────────────────────────────────────────────────
@app.post("/analyze-runtime")
async def analyze_runtime(url: str, db: Session = Depends(database.get_db)):
    new_scan = models.Scan(scan_type="runtime", status="processing")
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    try:
        findings = await scan_website_runtime(url)
        for f in findings:
            vuln = models.Vulnerability(scan_id=new_scan.id, **f)
            db.add(vuln)
        new_scan.status = "completed"
        db.commit()
        return {
            "status": "success",
            "scan_id": new_scan.id,
            "url": url,
            "issues": len(findings),
        }
    except Exception as e:
        db.rollback()
        new_scan.status = "failed"
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────────────────────────────
@app.get("/projects")
def get_projects(db: Session = Depends(database.get_db)):
    return db.query(models.Project).all()


@app.get("/dashboard-summary/{project_id}")
def get_project_summary(project_id: str, db: Session = Depends(database.get_db)):
    scans = db.query(models.Scan).filter(models.Scan.project_id == project_id).all()
    scan_ids = [s.id for s in scans]
    vulns = db.query(models.Vulnerability).filter(
        models.Vulnerability.scan_id.in_(scan_ids)
    ).all()

    high = len([v for v in vulns if v.severity.upper() == "HIGH"])
    medium = len([v for v in vulns if v.severity.upper() == "MEDIUM"])
    low = len([v for v in vulns if v.severity.upper() == "LOW"])

    trend = [
        {"month": "Jan", "count": 5},
        {"month": "Feb", "count": high + medium},
        {"month": "Mar", "count": high},
    ]
    score = min(100, (high * 15) + (medium * 8) + (low * 3))

    return {
        "risk_score": 100 - score,
        "stats": {"high": high, "medium": medium, "low": low},
        "trend": trend,
        "recent_vulns": vulns[:5],
    }


@app.get("/dashboard-summary")
def get_summary(db: Session = Depends(database.get_db)):
    high = db.query(models.Vulnerability).filter(
        models.Vulnerability.severity == "HIGH"
    ).count()
    medium = db.query(models.Vulnerability).filter(
        models.Vulnerability.severity == "MEDIUM"
    ).count()
    low = db.query(models.Vulnerability).filter(
        models.Vulnerability.severity == "LOW"
    ).count()
    score = min(100, (high * 15) + (medium * 8) + (low * 3))
    return {
        "risk_score": 100 - score,
        "stats": {"high": high, "medium": medium, "low": low},
        "total_scans": db.query(models.Scan).count(),
    }


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────
def _build_summary(results: List[dict]) -> dict:
    """Counts findings by final risk category."""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for r in results:
        cat = r.get("risk_category", "MEDIUM").upper()
        if cat == "CRITICAL":
            summary["critical"] += 1
        elif cat == "HIGH":
            summary["high"] += 1
        elif cat == "MEDIUM":
            summary["medium"] += 1
        elif cat == "LOW":
            summary["low"] += 1
        else:
            summary["informational"] += 1
    return summary