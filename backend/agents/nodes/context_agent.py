from typing import Any, Dict

from agents.context_builder import build_cross_file_context


def context_agent_node(state: Dict[str, Any]) -> Dict[str, Any]:
    project_path = state.get("project_path", "")
    finding = state.get("current_finding", {})

    if not project_path:
        context = {}
    else:
        context = build_cross_file_context(project_path, finding)

    return {
        "cross_file_context": context,
        "agent_trace": state.get("agent_trace", [])
        + [
            {
                "agent": "Context Agent",
                "status": "completed",
                "finding": finding.get("rule_id", ""),
                "related_files": len(context.get("related_files", [])),
            }
        ],
    }
