import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List


def run_dependency_scan(project_path: str) -> List[Dict[str, Any]]:
    root = Path(project_path)
    findings: List[Dict[str, Any]] = []

    if (root / "package.json").exists():
        findings.extend(run_npm_audit(root))

    if (root / "requirements.txt").exists():
        findings.extend(run_pip_audit(root))

    return findings


def run_npm_audit(root: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    try:
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm:
            raise FileNotFoundError("npm")

        result = subprocess.run(
            [npm, "audit", "--json"],
            cwd=str(root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            shell=False,
        )

        if not result.stdout.strip():
            return findings

        data = json.loads(result.stdout)
        vulnerabilities = data.get("vulnerabilities", {})
        if not vulnerabilities and data.get("error"):
            error = data.get("error", {})
            message = error.get("summary") or data.get("message") or "npm audit endpoint returned an error."
            findings.append(_dependency_scan_error("npm-audit-endpoint-error", message))
            return findings

        for package_name, vuln in vulnerabilities.items():
            severity = vuln.get("severity", "unknown")
            via = vuln.get("via", [])
            details = extract_npm_vuln_details(via)
            fixed_version = _format_fix_available(vuln.get("fixAvailable", ""))

            findings.append(
                {
                    "tool": "npm-audit",
                    "rule_id": f"npm-audit-{package_name}",
                    "message": details.get("title") or f"Vulnerable dependency: {package_name}",
                    "severity": str(severity).upper(),
                    "file": "package.json",
                    "file_path": "package.json",
                    "line": 1,
                    "column": 1,
                    "cwe": details.get("cwe", "CWE-1104"),
                    "cwe_id": details.get("cwe", "CWE-1104"),
                    "owasp": "A06: Vulnerable and Outdated Components",
                    "category": "Vulnerable Dependency",
                    "package": package_name,
                    "installed_version": vuln.get("range", ""),
                    "fixed_version": fixed_version,
                    "url": details.get("url", ""),
                    "code_snippet": f"{package_name}: {severity}",
                    "raw": vuln,
                }
            )

    except FileNotFoundError:
        findings.append(_dependency_scan_error("npm-not-found", "npm was not found on PATH. Dependency scan skipped."))
    except subprocess.TimeoutExpired:
        findings.append(_dependency_scan_error("npm-audit-timeout", "npm audit timed out after 60 seconds."))
    except json.JSONDecodeError as exc:
        findings.append(_dependency_scan_error("npm-audit-json-error", f"npm audit returned invalid JSON: {exc}"))
    except Exception as exc:
        findings.append(_dependency_scan_error("npm-audit-error", f"npm audit failed: {exc}"))

    return findings


def extract_npm_vuln_details(via: Any) -> Dict[str, Any]:
    if isinstance(via, list):
        for item in via:
            if isinstance(item, dict):
                cwes = item.get("cwe", [])
                cwe = cwes[0] if cwes else "CWE-1104"
                return {
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "cwe": cwe,
                }

    return {
        "title": "",
        "url": "",
        "cwe": "CWE-1104",
    }


def run_pip_audit(root: Path) -> List[Dict[str, Any]]:
    """
    Placeholder for Python dependency scanning.
    We will implement this later with pip-audit.
    """
    return []


def _dependency_scan_error(rule_id: str, message: str) -> Dict[str, Any]:
    return {
        "tool": "dependency-scanner",
        "rule_id": rule_id,
        "message": message,
        "severity": "INFO",
        "file": "package.json",
        "file_path": "package.json",
        "line": 1,
        "column": 1,
        "cwe": "CWE-Unknown",
        "cwe_id": "CWE-Unknown",
        "owasp": "A06: Vulnerable and Outdated Components",
        "category": "Dependency Scan Error",
        "code_snippet": "",
    }


def _format_fix_available(fix_available: Any) -> str:
    if isinstance(fix_available, dict):
        return str(fix_available.get("version", ""))
    if isinstance(fix_available, bool):
        return "available" if fix_available else ""
    return str(fix_available or "")
