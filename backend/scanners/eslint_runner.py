import json
import os
import subprocess
from typing import Any, Dict, List


def run_eslint(target_path: str) -> List[Dict[str, Any]]:
    result = subprocess.run(
        ["npx", "eslint", ".", "--format", "json"],
        cwd=target_path,
        capture_output=True,
        text=True,
        shell=True,
    )

    if not result.stdout.strip():
        if result.returncode not in (0, 1):
            raise RuntimeError(result.stderr.strip() or "ESLint failed")
        return []

    data = json.loads(result.stdout)
    findings: List[Dict[str, Any]] = []

    for file_entry in data:
        rel_path = os.path.relpath(file_entry.get("filePath", ""), target_path)
        for msg in file_entry.get("messages", []):
            findings.append(
                {
                    "tool": "eslint",
                    "rule_id": msg.get("ruleId") or "eslint",
                    "message": msg.get("message", "ESLint issue"),
                    "severity": "WARNING" if msg.get("severity") == 1 else "ERROR",
                    "file": rel_path,
                    "line": msg.get("line", 1),
                    "column": msg.get("column", 1),
                    "cwe": "CWE-Unknown",
                    "owasp": "Unknown",
                    "category": "Security Issue",
                    "metadata": {},
                    "raw": msg,
                }
            )

    return findings
