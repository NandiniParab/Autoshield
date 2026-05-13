from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from agents.security_graph import security_graph


router = APIRouter()


class AgentScanRequest(BaseModel):
    project_path: str


class FullAgentScanRequest(BaseModel):
    project_path: Optional[str] = ""
    runtime_url: Optional[str] = None
    runtime_page_data: Optional[Dict[str, Any]] = {}
    runtime_headers: Optional[Dict[str, Any]] = {}


@router.post("/scan")
def run_agent_scan(request: AgentScanRequest):
    result = security_graph.invoke(
        {
            "project_path": request.project_path,
            "errors": [],
        }
    )

    return result.get("report", result)


@router.post("/full-scan")
def run_full_agent_scan(request: FullAgentScanRequest):
    result = security_graph.invoke(
        {
            "project_path": request.project_path or "",
            "runtime_url": request.runtime_url,
            "runtime_page_data": request.runtime_page_data or {},
            "runtime_headers": request.runtime_headers or {},
            "errors": [],
        }
    )

    return result.get("report", result)
