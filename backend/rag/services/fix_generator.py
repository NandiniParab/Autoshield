# backend/rag/services/fix_generator.py
#
# FixGenerator — ask LLM for a fix, clean it, validate it, retry if it fails.
#
# Flow:
#   build_fix_prompt()
#     ↓  llm.invoke()
#     ↓  clean_llm_output()   ← strips markdown fences + prose
#     ↓  PatchValidator.validate_patch()
#     ↓  if failed → add error context, retry (up to max_attempts)
#     ↓  return validated result

import re
from typing import Dict, Any, List

from rag.services.patch_validator import PatchValidator


# ── LLM output cleaner ────────────────────────────────────────────────────────

def clean_llm_output(text: str) -> str:
    """
    Strips markdown fences, prose preambles, and AI explanation lines from
    an LLM response, leaving only the code.

    This is the first defence against invalid text being inserted into source
    files.  A second defence is the syntax gate in PatchValidator.
    """
    text = text.strip()

    # 1. Remove markdown code fences (with or without language tag)
    text = re.sub(
        r"```(?:javascript|js|typescript|ts|python|java|go|ruby|php|cpp|c)?\n?",
        "",
        text,
        flags=re.IGNORECASE,
    )
    text = text.replace("```", "")

    # 2. Drop lines that are clearly prose / AI preamble, not code
    skip_prefixes = (
        "here is",
        "here's",
        "sure",
        "the fixed code",
        "fixed code:",
        "explanation:",
        "explanation",
        "note:",
        "this fixes",
        "i have",
        "i've",
        "below is",
        "the following",
    )

    cleaned = []
    for line in text.splitlines():
        lower = line.strip().lower()
        if any(lower.startswith(p) for p in skip_prefixes):
            continue
        cleaned.append(line)

    return "\n".join(cleaned).strip()


# ── Prompt builder ────────────────────────────────────────────────────────────

def build_fix_prompt(
    language: str,
    vulnerability_type: str,
    original_code: str,
    evidence: List[Dict[str, Any]],
    previous_error: str = "",
) -> str:
    """
    Builds a strict code-only prompt.

    Key constraint: the model is explicitly told NOT to include markdown fences,
    explanations, or comments — only raw, runnable code.
    """
    evidence_text = "\n\n".join([doc.get("text", "") for doc in evidence])

    retry_block = ""
    if previous_error:
        retry_block = f"""
Previous generated patch FAILED validation.

Validation error:
{previous_error}

Generate a corrected version that fixes this specific issue.
"""

    return f"""You are AutoShield's secure code patch generator.

Fix ONLY the vulnerable code below.

Language: {language}
Vulnerability: {vulnerability_type}

Security evidence:
{evidence_text[:2000]}

Original vulnerable code:
```{language}
{original_code}
```

RULES — you MUST follow every rule:
1. Return ONLY valid {language} code. Nothing else.
2. Do NOT include markdown (no ``` fences).
3. Do NOT include any explanation, note, or comment about what you changed.
4. Do NOT include comments unless the original code already had them.
5. Do NOT remove unrelated logic.
6. Do NOT rename functions.
7. Do NOT invent new variables unless required for the fix.
8. Preserve function input/output behaviour exactly.
9. The output must be syntactically valid {language}.

Security rules:
- SQL Injection → use parameterized queries / prepared statements (? or %s placeholders, never string concatenation or f-strings in queries).
- XSS → do NOT use innerHTML or dangerouslySetInnerHTML; use textContent, DOMPurify.sanitize(), or encodeURIComponent().
- Command injection → do NOT use shell=True or string-concatenated shell commands.
- Hardcoded secrets → use environment variables (os.getenv / process.env).
{retry_block}
"""


# ── FixGenerator ──────────────────────────────────────────────────────────────

class FixGenerator:
    """
    Generates validated, safe code patches for detected vulnerabilities.

    Args:
        llm:          Any object with an `.invoke(prompt: str) -> str` method.
        max_attempts: Maximum retry count if validation fails (default 3).
    """

    def __init__(self, llm=None, max_attempts: int = 3):
        if llm is None:
            from rag.services.self_rag import GroqLLM
            llm = GroqLLM()
        self.llm = llm
        self.max_attempts = max_attempts
        self.validator = PatchValidator()

    def generate_fix(
        self,
        language: str,
        vulnerability_type: str,
        original_code: str,
        evidence: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Generates a validated patch with automatic retry on validation failure.

        Returns:
            {
                "success": bool,
                "fixed_code": str,
                "validation": { "passed": bool, "syntax_check": {…}, "security_check": {…} },
                "attempts": [...],
                "message": str   # only when success=False
            }

        IMPORTANT: callers must check `success == True` before applying the fix.
        If success is False, the fix MUST NOT be written to disk.
        """
        previous_error = ""
        attempts: List[Dict[str, Any]] = []
        fixed_code = original_code   # safe fallback — never return empty string
        validation: Dict[str, Any] = {}

        for attempt_num in range(1, self.max_attempts + 1):
            prompt = build_fix_prompt(
                language=language,
                vulnerability_type=vulnerability_type,
                original_code=original_code,
                evidence=evidence,
                previous_error=previous_error,
            )

            raw_response = self.llm.invoke(prompt)

            # ── Step 1: Clean ──────────────────────────────────────────
            # Strip markdown/prose BEFORE any validation so the syntax
            # checker never sees stray English text.
            fixed_code = clean_llm_output(raw_response)

            # ── Step 2: Validate ───────────────────────────────────────
            validation = self.validator.validate_patch(
                language=language,
                vulnerability_type=vulnerability_type,
                original_code=original_code,
                fixed_code=fixed_code,
            )

            attempts.append({"attempt": attempt_num, "validation": validation})

            if validation["passed"]:
                return {
                    "success": True,
                    "fixed_code": fixed_code,
                    "validation": validation,
                    "attempts": attempts,
                }

            # ── Step 3: Build error context for next retry ─────────────
            error_parts: List[str] = []

            syntax = validation.get("syntax_check", {})
            if not syntax.get("passed"):
                error_parts.append(f"Syntax error: {syntax.get('error', 'unknown')}")

            danger = validation.get("dangerous_pattern_check", {})
            if not danger.get("passed"):
                pats = danger.get("dangerous_patterns", [])
                error_parts.append(f"Dangerous patterns introduced: {', '.join(pats)}")

            # Support both key names: security_check (new) and
            # vulnerability_removed_check (legacy PatchValidator output)
            sec = validation.get("security_check") or validation.get("vulnerability_removed_check", {})
            if not sec.get("passed"):
                if sec.get("risk_still_exists") or sec.get("bad_pattern_found"):
                    error_parts.append("The original vulnerability pattern is still present.")
                if not sec.get("safe_pattern_found"):
                    error_parts.append("No safe replacement pattern was detected in the fix.")

            previous_error = "\n".join(error_parts) or "Validation failed — reason unknown."

        # All attempts exhausted — return best effort but flag as failed
        return {
            "success": False,
            "fixed_code": fixed_code,
            "validation": validation,
            "attempts": attempts,
            "message": (
                f"Could not generate a fully validated patch after "
                f"{self.max_attempts} attempt(s). "
                f"Last error: {previous_error}"
            ),
        }
