# backend/scanner.py
import subprocess
import json
import os
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
RULES_PATH = BASE_DIR / "semgrep_rules" / "autoshield-js.yml"


def _finding_key(finding):
    return (
        finding.get("rule_id", ""),
        finding.get("file_path", ""),
        finding.get("line", 0),
        finding.get("code_snippet", ""),
    )


def _dedupe(findings):
    seen = set()
    unique = []
    for finding in findings:
        key = _finding_key(finding)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _normalize_semgrep_result(item, target_dir):
    extra = item.get("extra", {})
    meta = extra.get("metadata", {})
    start = item.get("start", {})
    end = item.get("end", {})
    path = item.get("path", "unknown")
    abs_path = path if os.path.isabs(path) else os.path.abspath(os.path.join(target_dir, path))
    rel_path = os.path.relpath(abs_path, target_dir) if os.path.isabs(abs_path) else path
    cwe = meta.get("cwe", "CWE-Unknown")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else "CWE-Unknown"
    owasp = meta.get("owasp", "Unknown")
    if isinstance(owasp, list):
        owasp = ", ".join(str(x) for x in owasp)
    code_snippet = extra.get("lines", "").strip()
    if (not code_snippet or code_snippet.endswith("=")) and abs_path:
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            line_no = int(start.get("line", 0))
            if line_no > 0 and line_no <= len(lines):
                code_snippet = lines[line_no - 1].strip()
        except Exception:
            pass

    return {
        "tool": "semgrep",
        "rule_id": item.get("check_id", "semgrep"),
        "file": rel_path,
        "file_path": rel_path,
        "line": start.get("line", 0),
        "column": start.get("col", 0),
        "end_line": end.get("line", start.get("line", 0)),
        "end_column": end.get("col", start.get("col", 0)),
        "message": extra.get("message", "Semgrep finding"),
        "code_snippet": code_snippet,
        "severity": extra.get("severity", "WARNING"),
        "cwe": cwe,
        "cwe_id": cwe,
        "owasp": owasp,
        "category": meta.get("category", extra.get("message", "Security Issue")),
    }


def _run_semgrep(target_dir: str):
    if not shutil.which("semgrep") or not RULES_PATH.exists():
        return []

    command = [
        "semgrep",
        "--config",
        "p/javascript",
        "--config",
        str(RULES_PATH),
        "--json",
        "--quiet",
        target_dir,
    ]
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    if not proc.stdout.strip():
        if proc.returncode not in (0, 1):
            print(f"Semgrep Error: {proc.stderr.strip()}")
        return []

    data = json.loads(proc.stdout)
    return [_normalize_semgrep_result(item, target_dir) for item in data.get("results", [])]

def run_scanners(target_dir: str):
    results = []
    
    if not os.path.exists(target_dir):
        print(f"Error: Target directory {target_dir} does not exist.")
        return results

    # 1. Run Semgrep with AutoShield custom rules when available.
    try:
        print("[INFO] Running Semgrep custom rules...")
        results.extend(_run_semgrep(target_dir))
    except Exception as e:
        print(f"Semgrep Error: {e}")

    # 2. Run Enhanced Fallback Scanner only when Semgrep is unavailable.
    # This mirrors the Semgrep rule metadata so scans still show the expected
    # issues on machines where the semgrep package is not installed yet.
    if not shutil.which("semgrep"):
      try:
        print("[INFO] Running enhanced fallback scanner...")
        import re
        
        # Patterns based on autoshield-js.yml
        rules = [
            {
                "id": "autoshield-js-sql-injection",
                "regex": r"(`[^`]*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^`]*\$\{[^`]*\}`)|((SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^;\n]*['\"][^;\n]*\+)",
                "message": "Possible SQL Injection using template literal.",
                "severity": "ERROR", "cwe": "CWE-89", "owasp": "A03: Injection", "category": "SQL Injection"
            },
            {
                "id": "autoshield-js-hardcoded-secret",
                "regex": r"(secret|api|key|token|password|jwt).*=.*['\"].{8,}['\"]",
                "message": "Hardcoded secret or API key detected.",
                "severity": "WARNING", "cwe": "CWE-798", "owasp": "A07: Identification and Authentication Failures", "category": "Hardcoded Secret"
            },
            {
                "id": "autoshield-js-weak-crypto",
                "regex": r"createHash\(['\"]?(md5|sha1)['\"]?\)",
                "message": "Weak hashing algorithm (MD5/SHA1) detected.",
                "severity": "WARNING", "cwe": "CWE-327", "owasp": "A02: Cryptographic Failures", "category": "Weak Cryptography"
            },
            {
                "id": "autoshield-js-dangerous-eval",
                "regex": r"\beval\(.*\)",
                "message": "Dangerous eval() usage detected.",
                "severity": "ERROR", "cwe": "CWE-95", "owasp": "A03: Injection", "category": "Code Injection"
            },
            {
                "id": "autoshield-js-command-injection",
                "regex": r"(exec|spawn)\(.*(\+|`.*\$\{)",
                "message": "Possible Command Injection detected.",
                "severity": "ERROR", "cwe": "CWE-78", "owasp": "A03: Injection", "category": "Command Injection"
            },
            {
                "id": "autoshield-js-dom-xss",
                "regex": r"\.(innerHTML|outerHTML)\s*=",
                "message": "Possible DOM XSS through innerHTML/outerHTML assignment.",
                "severity": "WARNING", "cwe": "CWE-79", "owasp": "A03: Injection", "category": "Cross-Site Scripting"
            },
            {
                "id": "autoshield-js-path-traversal",
                "regex": r"(sendFile|download)\(.*(\+|`.*\$\{)",
                "message": "Possible path traversal detected.",
                "severity": "ERROR", "cwe": "CWE-22", "owasp": "A01: Broken Access Control", "category": "Path Traversal"
            },
            {
                "id": "autoshield-js-wildcard-cors",
                "regex": r"cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]\*['\"]",
                "message": "Insecure wildcard CORS configuration.",
                "severity": "WARNING", "cwe": "CWE-942", "owasp": "A05: Security Misconfiguration", "category": "Insecure CORS"
            },
            {
                "id": "autoshield-js-insecure-jwt-secret",
                "regex": r"(jwt\.(sign|verify)\s*\([^,]+,\s*['\"][^'\"]{4,}['\"]|JWT_SECRET\s*=\s*['\"][^'\"]{4,}['\"])",
                "message": "Hardcoded JWT secret detected.",
                "severity": "ERROR", "cwe": "CWE-798", "owasp": "A07: Identification and Authentication Failures", "category": "Hardcoded JWT Secret"
            },
            {
                "id": "autoshield-js-no-rate-limit-login",
                "regex": r"app\.(post|put|patch)\s*\(\s*['\"]/login['\"]",
                "message": "Login route appears to have no rate limiting.",
                "severity": "WARNING", "cwe": "CWE-307", "owasp": "A07: Identification and Authentication Failures", "category": "Missing Rate Limiting"
            }
        ]

        for root, _, files in os.walk(target_dir):
            for file in files:
                if not file.endswith((".js", ".ts", ".jsx", ".tsx")): continue
                if "node_modules" in root: continue
                
                fpath = os.path.join(root, file)
                rel_path = os.path.relpath(fpath, target_dir)
                
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        for idx, line in enumerate(lines):
                            for rule in rules:
                                if re.search(rule["regex"], line, re.I):
                                    results.append({
                                        "tool": "autoshield-fallback",
                                        "rule_id": rule["id"],
                                        "file": rel_path,
                                        "file_path": rel_path,
                                        "line": idx + 1,
                                        "column": 1,
                                        "message": rule["message"],
                                        "code_snippet": line.strip(),
                                        "severity": rule["severity"],
                                        "cwe": rule["cwe"],
                                        "cwe_id": rule["cwe"],
                                        "owasp": rule["owasp"],
                                        "category": rule["category"]
                                    })
                except Exception as e:
                    print(f"[Fallback] Error reading {fpath}: {e}")

      except Exception as e:
        print(f"Fallback Scanner Error: {e}")

    # 3. Run ESLint (Optional but kept for depth)
    try:
        es_command = ["npx", "eslint", ".", "--format", "json"]
        es_proc = subprocess.run(
            es_command,
            cwd=target_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=True,
        )
        
        if es_proc.stdout.strip():
            es_data = json.loads(es_proc.stdout)
            for file_entry in es_data:
                for msg in file_entry.get("messages", []):
                    rel_path = os.path.relpath(file_entry['filePath'], target_dir)
                    results.append({
                        "tool": "eslint",
                        "file_path": rel_path,
                        "line": msg.get('line', 0),
                        "message": msg['message'],
                        "code_snippet": msg.get('source', '').strip(),
                        "severity": "WARNING" if msg['severity'] == 1 else "ERROR",
                        "cwe": "CWE-Unknown", # ESLint doesn't always provide CWE
                        "cwe_id": "CWE-Unknown",
                    })
    except Exception as e:
        print(f"ESLint Error: {e}")

    return _dedupe(results)
