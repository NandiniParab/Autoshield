from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from runtime.runtime_analyzer import RuntimeAnalyzer


router = APIRouter()


class RuntimeAnalyzeRequest(BaseModel):
    url: str
    page_data: Dict[str, Any]
    headers: Optional[Dict[str, Any]] = None


@router.post("/analyze-page")
def analyze_runtime_page(request: RuntimeAnalyzeRequest):
    analyzer = RuntimeAnalyzer()
    return analyzer.analyze_page(
        url=request.url,
        page_data=request.page_data,
        headers=request.headers or {},
    )
