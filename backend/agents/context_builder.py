from pathlib import Path
from typing import Any, Dict, List
import re


SOURCE_PATTERNS = [
    "req.query",
    "req.body",
    "req.params",
    "request.query",
    "request.body",
    "localStorage",
    "sessionStorage",
    "window.location",
    "document.cookie",
]

SINK_PATTERNS = [
    "db.query",
    "db.get",
    "db.run",
    "execute(",
    "exec(",
    "eval(",
    "innerHTML",
    "res.send",
    "document.write",
]


def build_cross_file_context(project_path: str, finding: Dict[str, Any]) -> Dict[str, Any]:
    root = Path(project_path)

    if not root.exists():
        return {
            "related_files": [],
            "sources": [],
            "sinks": [],
            "call_chain_hints": [],
        }

    target_file = _normalize_path(finding.get("file_path") or finding.get("file") or "")
    category = str(finding.get("category", "")).lower()
    snippet = finding.get("code_snippet", "")
    files = list_code_files(root)

    related_files = []
    sources = []
    sinks = []
    call_chain_hints = []
    function_names = extract_function_names(snippet)

    for file in files:
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        rel = _normalize_path(str(file.relative_to(root)))
        file_score = 0

        for source in SOURCE_PATTERNS:
            if source in text:
                sources.append({"file": rel, "pattern": source})
                file_score += 2

        for sink in SINK_PATTERNS:
            if sink in text:
                sinks.append({"file": rel, "pattern": sink})
                file_score += 2

        for function_name in function_names:
            if function_name and function_name in text:
                call_chain_hints.append({"file": rel, "function": function_name})
                file_score += 3

        if target_file and rel == target_file:
            file_score += 5

        if category_contains(category, text):
            file_score += 1

        if file_score > 0:
            related_files.append(
                {
                    "file": rel,
                    "score": file_score,
                    "preview": make_preview(text),
                }
            )

    related_files = sorted(related_files, key=lambda item: item["score"], reverse=True)[:5]

    return {
        "related_files": related_files,
        "sources": sources[:10],
        "sinks": sinks[:10],
        "call_chain_hints": call_chain_hints[:10],
    }


def list_code_files(root: Path) -> List[Path]:
    allowed = {".js", ".jsx", ".ts", ".tsx", ".py"}
    ignored_dirs = {"node_modules", ".git", "venv", ".venv", "dist", "build", "__pycache__"}
    files = []

    for path in root.rglob("*"):
        if any(part in ignored_dirs for part in path.parts):
            continue

        if path.is_file() and path.suffix.lower() in allowed:
            files.append(path)

    return files


def extract_function_names(snippet: str) -> List[str]:
    names = []
    patterns = [
        r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)",
        r"const\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=",
        r"let\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=",
        r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, snippet or ""):
            names.append(match.group(1))

    return list(set(names))


def category_contains(category: str, text: str) -> bool:
    lower = text.lower()

    if "sql injection" in category:
        return "select" in lower or "query" in lower

    if "command injection" in category:
        return "exec" in lower or "spawn" in lower

    if "cross-site scripting" in category or "xss" in category:
        return "innerhtml" in lower or "document.write" in lower

    if "hardcoded" in category:
        return "secret" in lower or "api_key" in lower or "token" in lower

    return False


def make_preview(text: str, max_chars: int = 500) -> str:
    compact = "\n".join(line for line in text.splitlines() if line.strip())
    return compact[:max_chars]


def _normalize_path(value: str) -> str:
    return str(value or "").replace("\\", "/").lstrip("/")
