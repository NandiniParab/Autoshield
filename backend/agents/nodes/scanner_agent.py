from typing import Any, Dict, List
import os


try:
    from scanners.semgrep_runner import run_semgrep
except Exception:
    run_semgrep = None

try:
    from scanners.eslint_runner import run_eslint
except Exception:
    run_eslint = None

try:
    from scanners.dependency_runner import run_dependency_scan
except Exception:
    run_dependency_scan = None


def scanner_agent_node(state: Dict[str, Any]) -> Dict[str, Any]:
    project_path = state.get("project_path")
    project_findings: List[Dict[str, Any]] = []
    errors = list(state.get("errors", []))
    runtime_findings = list(state.get("runtime_findings", []))

    if project_path:
        if run_semgrep:
            try:
                project_findings.extend(run_semgrep(project_path) or [])
            except Exception as exc:
                errors.append(f"Semgrep failed: {_short_error(exc)}")

        if os.getenv("AUTOSHIELD_ENABLE_ESLINT", "").lower() in ("1", "true", "yes") and run_eslint:
            try:
                project_findings.extend(run_eslint(project_path) or [])
            except Exception as exc:
                errors.append(f"ESLint failed: {_short_error(exc)}")

        if run_dependency_scan:
            try:
                project_findings.extend(run_dependency_scan(project_path) or [])
            except Exception as exc:
                errors.append(f"Dependency scan failed: {_short_error(exc)}")

        if not project_findings:
            try:
                import scanner

                project_findings.extend(scanner.run_scanners(project_path) or [])
            except Exception as exc:
                errors.append(f"Fallback scanner failed: {_short_error(exc)}")

    findings = runtime_findings + project_findings

    return {
        "raw_findings": findings,
        "errors": errors,
        "agent_trace": state.get("agent_trace", [])
        + [
            {
                "agent": "Scanner Agent",
                "status": "completed" if project_path else "skipped",
                "findings_added": len(project_findings),
                "total_raw_findings": len(findings),
            }
        ],
    }


def _short_error(exc: Exception) -> str:
    lines = [line.strip() for line in str(exc).splitlines() if line.strip()]
    return lines[-1] if lines else exc.__class__.__name__
