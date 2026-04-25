# rag/ingestion/load_cwe.py
# Loads CWE entries. We use a curated subset of the most
# security-relevant CWEs mapped to OWASP categories.

import json
from pathlib import Path
from typing import List, Dict


def get_default_cwes() -> List[Dict]:
    """
    Returns a curated list of high-impact CWEs.
    In production, replace with full MITRE CWE XML parse.
    """
    return [
        {"id": "CWE-89", "name": "SQL Injection", "owasp": "A03",
         "description": "The software constructs all or part of an SQL command using externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component."},
        {"id": "CWE-79", "name": "Cross-site Scripting (XSS)", "owasp": "A03",
         "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users."},
        {"id": "CWE-20", "name": "Improper Input Validation", "owasp": "A03",
         "description": "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly."},
        {"id": "CWE-287", "name": "Improper Authentication", "owasp": "A07",
         "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct. This could allow an attacker to access resources or perform actions without proper authorization."},
        {"id": "CWE-200", "name": "Exposure of Sensitive Information", "owasp": "A01",
         "description": "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information, such as stack traces, credentials, or personally identifiable information."},
        {"id": "CWE-22", "name": "Path Traversal", "owasp": "A01",
         "description": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname."},
        {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "owasp": "A01",
         "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request."},
        {"id": "CWE-327", "name": "Use of Broken Cryptographic Algorithm", "owasp": "A02",
         "description": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information. The use of a non-standard algorithm is dangerous because a determined attacker may be able to break the algorithm."},
        {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "owasp": "A10",
         "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination."},
        {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "owasp": "A08",
         "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid. This can allow an attacker to modify the serialized data to perform unexpected actions."},
    ]


def load_cwe(data_dir: str = "rag/data/cwe") -> List[Dict]:
    """
    Loads CWE data. First tries to load from JSON file,
    falls back to built-in curated list.
    """
    path = Path(data_dir) / "cwe_entries.json"

    if path.exists():
        with open(path) as f:
            raw = json.load(f)
    else:
        raw = get_default_cwes()

    records = []
    for item in raw:
        text = (
            f"CWE ID: {item['id']}. Name: {item['name']}. "
            f"Related OWASP: {item.get('owasp', 'N/A')}. "
            f"Description: {item['description']}"
        )
        records.append({
            "text": text,
            "metadata": {
                "source": "CWE",
                "cwe_id": item["id"],
                "category": item["name"],
                "owasp_id": item.get("owasp", ""),
                "severity": "medium",  # CWE doesn't have severity, default medium
            }
        })
    return records