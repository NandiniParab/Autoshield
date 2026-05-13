from typing import Any, Dict, List, TypedDict


class SecurityGraphState(TypedDict, total=False):
    project_path: str
    runtime_url: str
    runtime_page_data: Dict[str, Any]
    runtime_headers: Dict[str, Any]

    raw_findings: List[Dict[str, Any]]
    runtime_findings: List[Dict[str, Any]]
    normalized_findings: List[Dict[str, Any]]

    current_finding_index: int
    current_finding: Dict[str, Any]
    cross_file_context: Dict[str, Any]
    data_flow: Dict[str, Any]

    rag_query: str
    rag_docs: List[Dict[str, Any]]
    rag_quality: Dict[str, Any]
    rag_attempts: int
    max_rag_attempts: int

    validation: Dict[str, Any]
    explanation: str

    enriched_findings: List[Dict[str, Any]]

    report: Dict[str, Any]
    errors: List[str]
    agent_trace: List[Dict[str, Any]]
