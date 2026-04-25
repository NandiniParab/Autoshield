# rag/ingestion/load_owasp.py
# Loads the OWASP Top 10 JSON into a normalized list of records.
# Each record becomes one or more chunks later.

import json
from pathlib import Path
from typing import List, Dict

def load_owasp(data_dir: str = "rag/data/owasp") -> List[Dict]:
    """
    Load OWASP Top 10 data from JSON file.
    Returns a flat list of records with standardized fields.
    """
    path = Path(data_dir) / "owasp_top10.json"
    if not path.exists():
        raise FileNotFoundError(f"OWASP data not found at {path}")

    with open(path, "r") as f:
        raw = json.load(f)

    records = []
    for item in raw:
        # Build a rich text blob for this OWASP category
        text = (
            f"OWASP Category: {item['category']} ({item['id']}). "
            f"Severity: {item['severity']}. "
            f"Description: {item['description']} "
            f"Examples: {item['examples']} "
            f"Mitigations: {item['mitigations']}"
        )
        records.append({
            "text": text,
            "metadata": {
                "source": "OWASP",
                "owasp_id": item["id"],
                "category": item["category"],
                "cwe_ids": ",".join(item.get("cwe_ids", [])),
                "severity": item["severity"],
            }
        })
    return records