import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BACKEND_DIR))

print("Backend path added:", BACKEND_DIR)

from rag.retrieval.retriever import retrieve_context

test_cases = [
    {
        "query": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "high"
    },
    {
        "query": "OWASP A03 Injection SQL Injection prepared statements",
        "cwe_id": "CWE-89",
        "severity": "high"
    },
    {
        "query": "Cross Site Scripting XSS",
        "cwe_id": "CWE-79",
        "severity": "high"
    },
    {
        "query": "Authentication failure login password session",
        "cwe_id": "CWE-287",
        "severity": "critical"
    }
]

for case in test_cases:
    print("\n======================")
    print("QUERY:", case["query"])
    print("CWE:", case["cwe_id"])
    print("SEVERITY:", case["severity"])
    print("======================")

    docs = retrieve_context(
        case["query"],
        case["cwe_id"],
        case["severity"]
    )

    print("TYPE:", type(docs))
    print("RESULT:", docs)