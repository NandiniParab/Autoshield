from typing import Any, Dict

from agents.data_flow_analyzer import analyze_data_flow


def data_flow_agent_node(state: Dict[str, Any]) -> Dict[str, Any]:
    project_path = state.get("project_path", "")
    finding = state.get("current_finding", {})

    if not project_path:
        flow = {}
    else:
        flow = analyze_data_flow(project_path, finding)

    return {
        "data_flow": flow,
        "agent_trace": state.get("agent_trace", [])
        + [
            {
                "agent": "Data Flow Agent",
                "status": "completed",
                "confirmed": flow.get("confirmed", False),
                "flows": len(flow.get("flows", [])),
            }
        ],
    }
