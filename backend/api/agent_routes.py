from fastapi import APIRouter
from pydantic import BaseModel

from agents.security_graph import security_graph


router = APIRouter()


class AgentScanRequest(BaseModel):
    project_path: str


@router.post("/scan")
def run_agent_scan(request: AgentScanRequest):
    result = security_graph.invoke(
        {
            "project_path": request.project_path,
            "errors": [],
        }
    )

    return result.get("report", result)
