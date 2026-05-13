from pathlib import Path
from typing import Any, Dict, List
import re


SOURCE_REGEX = [
    r"const\s+(\w+)\s*=\s*req\.query\.(\w+)",
    r"const\s+(\w+)\s*=\s*req\.body\.(\w+)",
    r"const\s+(\w+)\s*=\s*req\.params\.(\w+)",
]

CALL_REGEX = r"(\w+)\(([^)]*)\)"

SINK_REGEX = [
    r"db\.query\(([^)]*)\)",
    r"db\.get\(([^)]*)\)",
    r"db\.run\(([^)]*)\)",
    r"exec\(([^)]*)\)",
    r"eval\(([^)]*)\)",
    r"\.innerHTML\s*=",
]


def analyze_data_flow(project_path: str, finding: Dict[str, Any]) -> Dict[str, Any]:
    root = Path(project_path)

    if not root.exists():
        return {"flows": [], "confirmed": False}

    files = list(root.rglob("*.js"))
    sources = []
    calls = []
    sinks = []

    for file in files:
        if "node_modules" in file.parts:
            continue

        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        rel = str(file.relative_to(root)).replace("\\", "/")

        for pattern in SOURCE_REGEX:
            for match in re.finditer(pattern, text):
                sources.append(
                    {
                        "file": rel,
                        "variable": match.group(1),
                        "source": match.group(0),
                    }
                )

        for match in re.finditer(CALL_REGEX, text):
            prefix = text[max(0, match.start() - 12):match.start()]
            if re.search(r"function\s+$", prefix):
                continue

            calls.append(
                {
                    "file": rel,
                    "function": match.group(1),
                    "args": match.group(2),
                }
            )

        for pattern in SINK_REGEX:
            for match in re.finditer(pattern, text):
                sinks.append(
                    {
                        "file": rel,
                        "sink": match.group(0),
                    }
                )

    flows = []

    for source in sources:
        var_name = source["variable"]

        for call in calls:
            if var_name not in call["args"]:
                continue

            for sink in sinks:
                flows.append(
                    {
                        "source_file": source["file"],
                        "source": source["source"],
                        "variable": var_name,
                        "call_file": call["file"],
                        "function_call": f'{call["function"]}({call["args"]})',
                        "sink_file": sink["file"],
                        "sink": sink["sink"],
                    }
                )

    return {
        "confirmed": len(flows) > 0,
        "flows": flows[:10],
        "sources_found": sources,
        "sinks_found": sinks,
    }
