# rag/services/llm_service.py
# Path C: LLM Reasoning Layer
# Takes static findings + RAG context → produces expert validation
# LLM acts as an "expert witness", NOT the final judge.
# Final decision always goes through the deterministic risk engine.

import json
import os
from typing import Dict, List, Optional
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

_client: Optional[OpenAI] = None


def get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "OPENAI_API_KEY not set. Add it to your .env file."
            )
        _client = OpenAI(api_key=api_key)
    return _client


def build_reasoning_prompt(
    code_snippet: str,
    cwe_id: str,
    severity: str,
    vuln_type: str,
    rag_context: List[Dict],
    static_findings: Optional[List[Dict]] = None,
) -> str:
    """
    Constructs a structured prompt for LLM reasoning.
    Combines static analysis results with RAG knowledge.
    """
    # Format RAG context chunks
    context_text = ""
    for i, chunk in enumerate(rag_context[:3], 1):
        src = chunk.get("source", chunk.get("metadata", {}).get("source", "Unknown"))
        sim = chunk.get("similarity", 0)
        text = chunk.get("text", "")[:400]
        context_text += f"\n[Context {i} | Source: {src} | Relevance: {sim:.2f}]\n{text}\n"

    # Format static findings if provided
    static_text = ""
    if static_findings:
        for f in static_findings[:3]:
            static_text += (
                f"- Tool: {f.get('tool', 'unknown')} | "
                f"File: {f.get('file_path', 'N/A')} | "
                f"Line: {f.get('line', 0)} | "
                f"Message: {f.get('message', '')} | "
                f"Severity: {f.get('severity', 'unknown')}\n"
            )
    else:
        static_text = "No static findings provided."

    prompt = f"""You are a senior application security engineer performing expert vulnerability analysis.

## VULNERABILITY UNDER REVIEW
- **CWE ID**: {cwe_id}
- **Type**: {vuln_type or "Unknown"}
- **Reported Severity**: {severity.upper()}
- **Code Snippet**:
```
{code_snippet[:500]}
```

## STATIC ANALYSIS FINDINGS
{static_text}

## SECURITY KNOWLEDGE BASE CONTEXT
{context_text}

## YOUR TASK
Analyze this vulnerability carefully. Consider:
1. Is this a real, exploitable vulnerability or a false positive?
2. Is the reported severity accurate given the context?
3. What is your confidence in this assessment?

Return ONLY a valid JSON object with this exact structure (no markdown, no extra text):
{{
  "is_valid_vulnerability": true,
  "severity_assessment": "high",
  "severity_adjustment": 0,
  "confidence": 0.85,
  "exploitability": "high",
  "attack_vector": "network",
  "false_positive_likelihood": 0.1,
  "key_risks": ["Risk 1", "Risk 2"],
  "recommended_fix": "Brief fix recommendation",
  "reasoning": "One concise sentence explaining your verdict"
}}

Rules:
- "severity_assessment": one of "critical", "high", "medium", "low", "info"
- "severity_adjustment": integer from -2 (reduce severity) to +2 (increase severity)
- "confidence": float 0.0 to 1.0
- "false_positive_likelihood": float 0.0 to 1.0
- "exploitability": one of "high", "medium", "low"
- "attack_vector": one of "network", "local", "physical", "adjacent"
- "key_risks": list of 2-3 strings (empty list [] if not applicable)
"""
    return prompt


def analyze_with_llm(
    code_snippet: str,
    cwe_id: str,
    severity: str,
    vuln_type: str,
    rag_context: List[Dict],
    static_findings: Optional[List[Dict]] = None,
    model: str = "gpt-4o-mini",
) -> Dict:
    """
    Calls the LLM with structured vulnerability context.
    Returns a validated analysis dict.

    Falls back gracefully if OpenAI is unavailable or rate-limited.
    """
    try:
        client = get_client()
        prompt = build_reasoning_prompt(
            code_snippet, cwe_id, severity, vuln_type,
            rag_context, static_findings
        )

        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity expert. "
                        "You MUST respond with valid JSON only. "
                        "No markdown, no explanation outside the JSON."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0,          # Deterministic output
            max_tokens=600,
            response_format={"type": "json_object"},  # Force JSON mode
        )

        raw = response.choices[0].message.content.strip()
        result = json.loads(raw)
        result["llm_available"] = True
        return _validate_llm_output(result)

    except EnvironmentError as e:
        # No API key configured
        print(f"[LLM] Skipping — {e}")
        return _fallback_response(severity, reason="No API key configured")

    except Exception as e:
        error_str = str(e).lower()
        if "rate_limit" in error_str:
            print("[LLM] Rate limit hit — using fallback")
        elif "insufficient_quota" in error_str:
            print("[LLM] Quota exceeded — using fallback")
        else:
            print(f"[LLM] Error: {e}")
        return _fallback_response(severity, reason=str(e))


def _validate_llm_output(result: Dict) -> Dict:
    """Ensures LLM output has all required fields with valid types."""
    defaults = {
        "is_valid_vulnerability": True,
        "severity_assessment": "medium",
        "severity_adjustment": 0,
        "confidence": 0.5,
        "exploitability": "medium",
        "attack_vector": "network",
        "false_positive_likelihood": 0.2,
        "key_risks": [],
        "recommended_fix": "Review and remediate the identified vulnerability.",
        "reasoning": "Analysis based on provided context.",
        "llm_available": True,
    }

    for key, default in defaults.items():
        if key not in result:
            result[key] = default

    # Clamp numeric values
    result["confidence"] = max(0.0, min(1.0, float(result.get("confidence", 0.5))))
    result["false_positive_likelihood"] = max(
        0.0, min(1.0, float(result.get("false_positive_likelihood", 0.2)))
    )
    result["severity_adjustment"] = max(
        -2, min(2, int(result.get("severity_adjustment", 0)))
    )

    return result


def _fallback_response(severity: str, reason: str = "") -> Dict:
    """
    Returns a neutral analysis when LLM is unavailable.
    The risk engine will still work using static + RAG data alone.
    """
    return {
        "is_valid_vulnerability": True,
        "severity_assessment": severity.lower(),
        "severity_adjustment": 0,
        "confidence": 0.5,
        "exploitability": "medium",
        "attack_vector": "network",
        "false_positive_likelihood": 0.2,
        "key_risks": [],
        "recommended_fix": "Review the flagged code and apply security best practices.",
        "reasoning": f"LLM analysis unavailable ({reason}). Using static + RAG context only.",
        "llm_available": False,
    }