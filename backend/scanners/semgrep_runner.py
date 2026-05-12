import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


def resolve_semgrep_path() -> str | None:
    project_root = Path(__file__).resolve().parents[2]
    candidates = [
        project_root / ".venv" / "Scripts" / "semgrep.exe",
        project_root / ".venv" / "Scripts" / "semgrep",
        Path(sys.executable).parent / "semgrep.exe",
        Path(sys.executable).parent / "semgrep",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    path_semgrep = shutil.which("semgrep")
    if path_semgrep:
        return path_semgrep

    return None


def _semgrep_command_prefix() -> List[str]:
    semgrep_path = resolve_semgrep_path()
    print("Semgrep path:", semgrep_path)

    if semgrep_path is None:
        raise RuntimeError("Semgrep executable not found in the project venv, active Python Scripts folder, or PATH")

    if semgrep_path.lower().endswith(".exe"):
        return [semgrep_path]

    # The pip launcher in this project has no .exe suffix. PowerShell cannot
    # execute it directly on Windows, so run it with the active Python.
    return [sys.executable, semgrep_path]


def run_semgrep(target_path: str) -> List[Dict[str, Any]]:
    backend_dir = Path(__file__).resolve().parents[1]
    custom_rules = backend_dir / "semgrep_rules" / "autoshield-js.yml"
    target = Path(target_path).resolve()

    cmd = [
        *_semgrep_command_prefix(),
        "--config",
        "p/javascript",
        "--config",
        str(custom_rules),
        "--json",
        str(target),
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if _native_semgrep_unusable(result):
        docker_result = _run_semgrep_with_docker(target, custom_rules)
        if docker_result is not None:
            result = docker_result

    if result.returncode == 1 and not result.stdout.strip() and result.stderr.strip():
        detail = result.stderr.strip()
        if "exec_osemgrep" in detail or "FileNotFoundError" in detail:
            core_path = Path(__file__).resolve().parents[2] / ".venv" / "Lib" / "site-packages" / "semgrep" / "bin" / "semgrep-core.exe"
            extensionless_core = core_path.with_suffix("")
            raise RuntimeError(
                "Semgrep launcher was found but it could not start Semgrep core. "
                f"Checked Windows core path: {core_path} exists={core_path.exists()}. "
                f"Packaged extensionless core exists={extensionless_core.exists()}. "
                "Run `semgrep --version` from the same PowerShell and venv used by uvicorn."
            )
        raise RuntimeError(detail)

    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or "Semgrep failed")

    data = json.loads(result.stdout or "{}")
    findings: List[Dict[str, Any]] = []

    for item in data.get("results", []):
        extra = item.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        semgrep_file = item.get("path", "")
        line = item.get("start", {}).get("line")
        cwe = metadata.get("cwe", "CWE-Unknown")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else "CWE-Unknown"
        owasp = metadata.get("owasp", "Unknown")
        if isinstance(owasp, list):
            owasp = ", ".join(str(value) for value in owasp)

        findings.append(
            {
                "tool": "semgrep",
                "rule_id": item.get("check_id"),
                "message": extra.get("message"),
                "severity": extra.get("severity"),
                "file": _display_path(semgrep_file, target),
                "line": line,
                "column": item.get("start", {}).get("col"),
                "cwe": cwe,
                "owasp": owasp,
                "category": metadata.get("category", "Security Issue"),
                "metadata": metadata,
                "code_snippet": _read_source_line(semgrep_file, target, line) or extra.get("lines", ""),
                "raw": item,
            }
        )

    return findings


def _local_path_from_semgrep_path(semgrep_path: str, target: Path) -> Path:
    normalized = semgrep_path.replace("\\", "/")
    if normalized.startswith("/src/"):
        return target / normalized.removeprefix("/src/")

    path = Path(semgrep_path)
    if path.is_absolute():
        return path

    return target / path


def _read_source_line(semgrep_path: str, target: Path, line: int | None) -> str:
    if not line or line < 1:
        return ""

    local_path = _local_path_from_semgrep_path(semgrep_path, target)
    try:
        with local_path.open("r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except OSError:
        return ""

    if line > len(lines):
        return ""

    return lines[line - 1].strip()


def _display_path(semgrep_path: str, target: Path) -> str:
    local_path = _local_path_from_semgrep_path(semgrep_path, target)
    try:
        return str(local_path.relative_to(target))
    except ValueError:
        return semgrep_path


def _native_semgrep_unusable(result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode == 0 or result.stdout.strip():
        return False

    stderr = result.stderr or ""
    return (
        "exec_osemgrep" in stderr
        or "FileNotFoundError" in stderr
        or "No such file or directory" in stderr
        or "Access is denied" in stderr
        or "No module named 'resource'" in stderr
    )


def _run_semgrep_with_docker(
    target_path: Path,
    custom_rules: Path,
) -> subprocess.CompletedProcess[str] | None:
    docker = shutil.which("docker")
    if not docker:
        return None

    # Avoid hanging if Docker Desktop is not running.
    ping = subprocess.run(
        [docker, "info", "--format", "{{.ServerVersion}}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
    )
    if ping.returncode != 0:
        return None

    target_mount = f"{target_path}:/src:ro"
    rules_mount = f"{custom_rules}:/rules/autoshield-js.yml:ro"

    env = os.environ.copy()
    env.setdefault("SEMGREP_SEND_METRICS", "off")

    return subprocess.run(
        [
            docker,
            "run",
            "--rm",
            "-e",
            "SEMGREP_SEND_METRICS=off",
            "-v",
            target_mount,
            "-v",
            rules_mount,
            "semgrep/semgrep",
            "semgrep",
            "--config",
            "p/javascript",
            "--config",
            "/rules/autoshield-js.yml",
            "--json",
            "/src",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
    )
