# backend/rag/services/patch_validator.py
#
# PatchValidator — multi-stage patch safety gate.
#
# Stages:
#   1. Syntax check      — Python (ast), JS/TS (node --check)
#   2. Security check    — vuln-specific bad/good pattern comparison
#   3. Dangerous check   — eval, exec, shell=True, innerHTML, hardcoded secrets
#
# All stages must pass before a fix is returned to the caller.
# If ANY stage fails, the fix MUST NOT be applied to disk.

import ast
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any


class PatchValidator:
    """
    Validates an AI-generated code patch against three independent gates.

    Usage:
        validator = PatchValidator()
        result = validator.validate_patch(
            language="python",
            vulnerability_type="SQL Injection",
            original_code=original,
            fixed_code=fixed,
        )
        if result["passed"]:
            # safe to apply
    """

    def __init__(self):
        pass

    # ── Gate 1: Syntax ───────────────────────────────────────────────────────

    def check_python_syntax(self, code: str) -> Dict[str, Any]:
        """Uses the stdlib `ast` module — zero extra dependencies."""
        try:
            ast.parse(code)
            return {"passed": True, "error": None}
        except SyntaxError as e:
            return {
                "passed": False,
                "error": f"Python syntax error at line {e.lineno}: {e.msg}",
            }

    def check_javascript_syntax(self, code: str) -> Dict[str, Any]:
        """
        Uses `node --check`.
        Requires Node.js to be installed on the host.
        Falls back to passed=True (with a note) if Node is not found so the
        pipeline doesn't hard-fail on machines without Node.
        """
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".js", mode="w", delete=False, encoding="utf-8"
            ) as tmp:
                tmp.write(code)
                tmp_path = tmp.name

            result = subprocess.run(
                ["node", "--check", tmp_path],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                return {"passed": True, "error": None}
            return {
                "passed": False,
                "error": (result.stderr or result.stdout).strip(),
            }

        except FileNotFoundError:
            return {"passed": False, "error": "node not found; JS syntax check could not run"}
        except Exception as e:
            return {"passed": False, "error": str(e)}
        finally:
            if tmp_path:
                Path(tmp_path).unlink(missing_ok=True)

    def check_typescript_syntax(self, code: str) -> Dict[str, Any]:
        """
        Fallback TypeScript check via `npx tsc --noEmit`.
        Requires tsc / npx available on the host.
        """
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".ts", mode="w", delete=False, encoding="utf-8"
            ) as tmp:
                tmp.write(code)
                tmp_path = tmp.name

            result = subprocess.run(
                ["npx", "tsc", "--noEmit", "--allowJs", tmp_path],
                capture_output=True,
                text=True,
                timeout=15,
                shell=True,
            )

            if result.returncode == 0:
                return {"passed": True, "error": None}
            return {
                "passed": False,
                "error": (result.stderr or result.stdout).strip(),
            }

        except Exception as e:
            return {"passed": False, "error": str(e)}
        finally:
            if tmp_path:
                Path(tmp_path).unlink(missing_ok=True)

    def validate_syntax(self, language: str, code: str) -> Dict[str, Any]:
        """Dispatch to the correct language syntax checker."""
        lang = language.lower()
        if lang == "python":
            return self.check_python_syntax(code)
        if lang in ("javascript", "js"):
            return self.check_javascript_syntax(code)
        if lang in ("typescript", "ts"):
            return self.check_typescript_syntax(code)
        return {"passed": True, "error": None}

    # ── Gate 2: Security / vulnerability-removed check ───────────────────────

    def validate_security_fix(
        self,
        vulnerability_type: str,
        fixed_code: str,
    ) -> Dict[str, Any]:
        """
        Checks that:
          a) the risky pattern that caused the vulnerability is gone, AND
          b) a safe replacement pattern is present.

        Supports common AutoShield vulnerability categories.
        Unknown categories pass by default to avoid false positives.
        """
        vuln = vulnerability_type.lower()

        # ── SQL Injection ────────────────────────────────────────────────
        if "sql injection" in vuln or "sqli" in vuln:
            bad_patterns = [
                r"`.*\$\{.*\}.*`",                   # JS template literal in query
                r"\+\s*req\.",                         # +req. concatenation
                r"\+\s*request\.",                     # +request. concatenation
                r"\.format\s*\(",                      # .format() in query
                r"execute\s*\(\s*f['\"]",              # Python f-string in execute
                r"execute\s*\(\s*['\"].*\+",           # concatenation in execute
                r"query\s*\(\s*`.*\$\{.*\}.*`",       # JS db.query with template literal
                r"SELECT\s+.*\{.*\}",                  # f-string SELECT
                r"WHERE\s+.*\+.*",                     # concatenated WHERE clause
            ]
            good_patterns = [
                r"\?",                                 # sqlite3 / mysql2 style
                r"\$\d+",                              # pg style ($1, $2)
                r"%s",                                 # psycopg2 style
                r"execute\s*\([^,]+,\s*[\(\[]",        # execute(q, (params,)) or execute(q, [params])
                r"query\s*\([^,]+,\s*\[",              # db.query(q, [params])
            ]

            bad_found = any(
                re.search(p, fixed_code, re.IGNORECASE | re.DOTALL)
                for p in bad_patterns
            )
            good_found = any(
                re.search(p, fixed_code, re.IGNORECASE | re.DOTALL)
                for p in good_patterns
            )

            return {
                "passed": not bad_found and good_found,
                "bad_pattern_found": bad_found,
                "safe_pattern_found": good_found,
                # legacy aliases kept for backwards compat
                "risk_still_exists": bad_found,
            }

        # ── XSS / Cross-Site Scripting ───────────────────────────────────
        if "xss" in vuln or "cross-site scripting" in vuln or "cross site scripting" in vuln:
            bad_found = (
                ".innerHTML" in fixed_code
                or "dangerouslySetInnerHTML" in fixed_code
            )
            good_found = (
                ".textContent" in fixed_code
                or "DOMPurify" in fixed_code
                or "sanitize" in fixed_code
                or "encodeURIComponent" in fixed_code
                or "escape(" in fixed_code
            )

            return {
                "passed": not bad_found and good_found,
                "bad_pattern_found": bad_found,
                "safe_pattern_found": good_found,
                "risk_still_exists": bad_found,
            }

        if "command injection" in vuln:
            bad_found = bool(re.search(r"\b(exec|spawn|execSync|system|popen)\s*\(.*(\+|`.*\$\{)|shell\s*=\s*True", fixed_code, re.IGNORECASE | re.DOTALL))
            good_found = bool(re.search(r"\b(spawn|execFile|subprocess\.run)\s*\([^,\n]+,\s*\[|shell\s*=\s*False|allowlist|whitelist|validate", fixed_code, re.IGNORECASE))
            return {
                "passed": not bad_found and good_found,
                "bad_pattern_found": bad_found,
                "safe_pattern_found": good_found,
                "risk_still_exists": bad_found,
            }

        if "code injection" in vuln or "eval" in vuln:
            bad_found = bool(re.search(r"\b(eval|Function)\s*\(", fixed_code, re.IGNORECASE))
            good_found = not bad_found
            return {
                "passed": not bad_found and good_found,
                "bad_pattern_found": bad_found,
                "safe_pattern_found": good_found,
                "risk_still_exists": bad_found,
            }

        if "hardcoded" in vuln or "secret" in vuln or "jwt secret" in vuln:
            bad_found = bool(re.search(r"(api_key|secret|token|jwt_secret|password)\s*=\s*['\"][^'\"]{6,}['\"]|jwt\.(sign|verify)\s*\([^,]+,\s*['\"][^'\"]{6,}['\"]", fixed_code, re.IGNORECASE))
            good_found = bool(re.search(r"(os\.getenv|process\.env|getenv|secrets\.|config\.|settings\.)", fixed_code, re.IGNORECASE))
            return {
                "passed": not bad_found and good_found,
                "bad_pattern_found": bad_found,
                "safe_pattern_found": good_found,
                "risk_still_exists": bad_found,
            }

        if "weak cryptography" in vuln or "weak crypto" in vuln:
            bad_found = bool(re.search(r"(md5|sha1)", fixed_code, re.IGNORECASE))
            good_found = bool(re.search(r"(sha256|sha512|bcrypt|argon2|scrypt|pbkdf2)", fixed_code, re.IGNORECASE))
            return {
                "passed": not bad_found and good_found,
                "bad_pattern_found": bad_found,
                "safe_pattern_found": good_found,
                "risk_still_exists": bad_found,
            }

        if "cors" in vuln:
            bad_found = bool(re.search(r"origin\s*:\s*['\"]\*['\"]|access-control-allow-origin['\"]?\s*,\s*['\"]\*['\"]", fixed_code, re.IGNORECASE))
            good_found = bool(re.search(r"origin\s*:\s*(\[|function|\(|allowedOrigins)|allowlist|whitelist", fixed_code, re.IGNORECASE))
            return {
                "passed": not bad_found and good_found,
                "bad_pattern_found": bad_found,
                "safe_pattern_found": good_found,
                "risk_still_exists": bad_found,
            }

        if "path traversal" in vuln:
            bad_found = bool(re.search(r"(sendFile|download)\s*\([^)]*(req\.|params|query|\+|`.*\$\{)", fixed_code, re.IGNORECASE | re.DOTALL))
            good_found = bool(re.search(r"(path\.resolve|path\.normalize|realpath|basename|allowlist|safe_join|werkzeug\.utils\.secure_filename)", fixed_code, re.IGNORECASE))
            return {
                "passed": not bad_found and good_found,
                "bad_pattern_found": bad_found,
                "safe_pattern_found": good_found,
                "risk_still_exists": bad_found,
            }

        if "rate limit" in vuln:
            good_found = bool(re.search(r"(rateLimit|express-rate-limit|limiter|slowDown|throttle)", fixed_code, re.IGNORECASE))
            return {
                "passed": good_found,
                "bad_pattern_found": not good_found,
                "safe_pattern_found": good_found,
                "risk_still_exists": not good_found,
            }

        # ── Default: pass (avoids false positives for unknown vuln types) ─
        return {
            "passed": True,
            "bad_pattern_found": False,
            "safe_pattern_found": True,
            "risk_still_exists": False,
        }

    # ── Gate 3: Dangerous new patterns ──────────────────────────────────────

    def detect_dangerous_new_patterns(self, code: str) -> Dict[str, Any]:
        """
        Rejects patches that introduce well-known dangerous patterns.

        NOTE: 'password' is intentionally excluded from the hardcoded-secret
        pattern because login functions legitimately use password as a
        parameter — that does NOT mean a secret is hardcoded.
        """
        dangerous_patterns = {
            "eval_usage":                r"\beval\s*\(",
            "exec_usage":                r"\bexec\s*\(",
            "shell_true":                r"shell\s*=\s*True",
            "innerhtml_usage":           r"\.innerHTML\s*=",
            "dangerously_set_inner_html": r"dangerouslySetInnerHTML",
            "function_constructor":       r"\bnew\s+Function\s*\(",
            "hardcoded_secret":          r"(api_key|secret|token)\s*=\s*['\"][^'\"]{4,}['\"]",
        }

        found = [
            name
            for name, pattern in dangerous_patterns.items()
            if re.search(pattern, code, re.IGNORECASE)
        ]

        return {
            "passed": len(found) == 0,
            "dangerous_patterns": found,
        }

    # ── Main entry point ─────────────────────────────────────────────────────

    def validate_patch(
        self,
        language: str,
        vulnerability_type: str,
        original_code: str,
        fixed_code: str,
    ) -> Dict[str, Any]:
        """
        Run all three gates in order.

        Gate order:
          1. syntax_check          — is the code parseable?
          2. security_check        — did the vulnerability actually get fixed?
          3. dangerous_pattern_check — did we introduce new dangerous code?

        Returns a dict where `passed` is True only when ALL three pass.
        The VS Code extension checks `passed` before allowing Apply Fix.
        """
        # Gate 1
        syntax_result = self.validate_syntax(language, fixed_code)

        # Gate 2
        security_result = self.validate_security_fix(vulnerability_type, fixed_code)

        # Gate 3
        dangerous_result = self.detect_dangerous_new_patterns(fixed_code)

        overall_passed = (
            syntax_result["passed"]
            and security_result["passed"]
            and dangerous_result["passed"]
        )

        return {
            "passed": overall_passed,
            "syntax_check": syntax_result,
            "security_check": security_result,
            # keep legacy key so old code doesn't break
            "vulnerability_removed_check": security_result,
            "dangerous_pattern_check": dangerous_result,
        }
