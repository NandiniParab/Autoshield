# scripts/test_llm.py
import sys
import os
from pprint import pprint

# Allow imports from project root
sys.path.insert(0, os.path.abspath("."))

from rag.services.rag_service import analyze_vulnerability

def test_llm_analysis():
    print("\nTesting AutoShield LLM Reasoning Layer...")
    print("="*50)

    # Sample: Classic SQL Injection
    sample_code = """
    @app.route("/user")
    def get_user():
        user_id = request.args.get("id")
        query = f"SELECT * FROM users WHERE id = '{user_id}'"
        return db.execute(query)
    """
    
    cwe_id = "CWE-89"
    vuln_type = "SQL Injection"
    severity = "high"

    print(f"Analyzing: {vuln_type} ({cwe_id})")
    print("-" * 30)

    try:
        result = analyze_vulnerability(
            code_snippet=sample_code,
            cwe_id=cwe_id,
            severity=severity,
            vuln_type=vuln_type,
            use_llm=True
        )

        print("\nLLM Response Received!")
        print("-" * 30)
        
        # The fields are at the top level of the result
        print(f"Is Valid: {result.get('is_valid_vulnerability')}")
        print(f"Confidence: {result.get('llm_confidence') or result.get('confidence')}")
        print(f"Severity Assessment: {result.get('severity_assessment')}")
        
        reasoning = result.get('reasoning', '')
        fix = result.get('recommended_fix', '')
        
        print(f"\nReasoning Snippet: {reasoning[:200]}...")
        print(f"\nRecommended Fix: {fix[:200]}...")
        
        if result.get("llm_available") and reasoning:
            print("\nLLM integration is WORKING perfectly.")
        else:
            print("\nLLM fallback was used. Check your GROQ_API_KEY.")

    except Exception as e:
        print(f"\nTest Failed: {e}")

def test_batch_analysis():
    print("\nTesting AutoShield Batch Analysis (Path A+B+C)...")
    print("="*50)

    from rag.services.rag_service import analyze_batch

    findings = [
        {
            "tool": "eslint",
            "file_path": "auth.js",
            "line": 9,
            "message": "Potential SQL injection in database query",
            "severity": "ERROR"
        },
        {
            "tool": "semgrep",
            "file_path": "server.js",
            "line": 2,
            "message": "Hardcoded secret detected",
            "severity": "HIGH",
            "cwe_id": "CWE-798"
        }
    ]

    try:
        results = analyze_batch(findings, use_llm=True)
        print(f"Batch Analysis Complete. Processed {len(results)} findings.")
        
        for i, res in enumerate(results):
            print(f"\nFinding {i+1}: {res.get('vuln_type') or res.get('cwe_id')}")
            print(f"  Severity: {res.get('final_severity')} (Score: {res.get('risk_score')})")
            print(f"  Reasoning: {res.get('reasoning', '')[:100]}...")
            if "error" in res:
                print(f"  ERROR: {res['error']}")

    except Exception as e:
        print(f"\nBatch Test Failed: {e}")

if __name__ == "__main__":
    test_llm_analysis()
    test_batch_analysis()
