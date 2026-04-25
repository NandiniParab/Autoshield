# backend/main.py

import asyncio
import sys

# Fix Playwright event loop issue on Windows
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from rag.retrieval.retriever import retrieve_context
import models
import database
import scanner
from crawler import scan_website_runtime

# ✅ RAG imports (ADD THIS)
from rag.retrieval.retriever import retrieve_context
app = FastAPI(title="AutoShield API")

# -----------------------------
# CORS
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class RAGRequest(BaseModel):
    code_snippet: str
    cwe_id: str
    severity: str
    vuln_type: str = ""
# -----------------------------
# Startup DB init
# -----------------------------
@app.on_event("startup")
def startup():
    models.Base.metadata.create_all(bind=database.engine)


# -----------------------------
# Health Check
# -----------------------------
@app.get("/")
def health_check():
    return {"status": "AutoShield Backend Online"}


# -----------------------------
# Static Code Analysis
# -----------------------------
@app.post("/analyze-code")
def analyze_code(path: str, db: Session = Depends(database.get_db)):
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


# -----------------------------
# Runtime Analysis (Playwright)
# -----------------------------
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


# -----------------------------
# RAG ENDPOINT (FIX YOU WERE MISSING THIS)
# -----------------------------
@app.post("/rag/analyze")
@app.post("/rag/analyze")
def rag_analyze(payload: RAGRequest):
    try:
        results = retrieve_context(
            code_snippet=payload.code_snippet,
            cwe_id=payload.cwe_id,
            severity=payload.severity.lower(),
            vuln_type=payload.vuln_type,
            top_k=5
        )

        return {
            "input": payload.model_dump(),
            "context_chunks": results
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -----------------------------
# Dashboard Summary (Global)
# -----------------------------
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
        "total_scans": db.query(models.Scan).count()
    }


# -----------------------------
# Projects
# -----------------------------
@app.get("/projects")
def get_projects(db: Session = Depends(database.get_db)):
    return db.query(models.Project).all()


# -----------------------------
# Project Dashboard Summary
# -----------------------------
@app.get("/dashboard-summary/{project_id}")
def get_project_summary(project_id: str, db: Session = Depends(database.get_db)):

    scans = db.query(models.Scan).filter(
        models.Scan.project_id == project_id
    ).all()

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
        {"month": "Mar", "count": high}
    ]

    score = min(100, (high * 15) + (medium * 8) + (low * 3))

    return {
        "risk_score": 100 - score,
        "stats": {"high": high, "medium": medium, "low": low},
        "trend": trend,
        "recent_vulns": vulns[:5]
    }



