# rag/ingestion/load_cve.py

import json
import time
import requests
from pathlib import Path
from typing import List, Dict
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")


# -------------------------
# API CALL (SAFE VERSION)
# -------------------------
def fetch_nvd_page(start_index: int = 0, results_per_page: int = 100) -> Dict:

    end_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000")
    start_date = (datetime.now() - timedelta(days=730)).strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }

    headers = {
        "User-Agent": "AutoShield-RAG/1.0"
    }

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        resp = requests.get(
            NVD_API_BASE,
            params=params,
            headers=headers,
            timeout=30
        )

        # DO NOT crash pipeline
        if resp.status_code != 200:
            print(f"[CVE] API Error {resp.status_code}: {resp.text}")
            return {"vulnerabilities": []}

        return resp.json()

    except Exception as e:
        print(f"[CVE] Request failed: {e}")
        return {"vulnerabilities": []}


# -------------------------
# PARSE FUNCTION (UNCHANGED LOGIC)
# -------------------------
def parse_cve_item(item: Dict) -> Dict:

    cve = item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    metrics = cve.get("metrics", {})
    severity = "medium"
    cvss_score = 0.0

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            base = metrics[key][0].get("cvssData", {})
            cvss_score = base.get("baseScore", 0.0)
            severity = base.get("baseSeverity", "medium").lower()
            break

    weaknesses = cve.get("weaknesses", [])
    cwe_ids = []

    for w in weaknesses:
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    return {
        "id": cve_id,
        "description": desc,
        "cvss_score": cvss_score,
        "severity": severity,
        "cwe_ids": cwe_ids,
        "published": cve.get("published", ""),
    }


# -------------------------
# MAIN LOADER (FIXED CACHE LOGIC)
# -------------------------
def load_cve(
    data_dir: str = "rag/data/cve",
    max_records: int = 500,
    use_cache: bool = True
) -> List[Dict]:

    cache_path = Path(data_dir) / "cve_cache.json"

    # -------------------------
    # LOAD CACHE (ONLY IF VALID)
    # -------------------------
    if use_cache and cache_path.exists():
        try:
            print("[CVE] Loading from cache...")
            with open(cache_path, "r", encoding="utf-8") as f:
                parsed = json.load(f)

            # IMPORTANT: reject empty cache
            if not parsed:
                print("[CVE] Cache empty → refetching...")
                parsed = None

        except Exception:
            print("[CVE] Cache corrupted → refetching...")
            parsed = None
    else:
        parsed = None

    # -------------------------
    # FETCH FROM API
    # -------------------------
    if parsed is None:

        print(f"[CVE] Fetching {max_records} CVEs from NVD API...")

        parsed = []
        start_index = 0
        per_page = 100

        while len(parsed) < max_records:
            data = fetch_nvd_page(start_index, per_page)
            items = data.get("vulnerabilities", [])

            if not items:
                print("[CVE] No more data from API.")
                break

            for item in items:
                if len(parsed) >= max_records:
                    break
                parsed.append(parse_cve_item(item))

            start_index += per_page
            time.sleep(0.6)

            print(f"[CVE] Fetched {len(parsed)} records...")

        # -------------------------
        # SAVE CACHE ONLY IF VALID
        # -------------------------
        if parsed:
            Path(data_dir).mkdir(parents=True, exist_ok=True)

            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(parsed, f, indent=2)

            print(f"[CVE] Cached {len(parsed)} CVEs → {cache_path}")
        else:
            print("[CVE] WARNING: No data fetched → not caching")

    # -------------------------
    # FORMAT FOR RAG
    # -------------------------
    records = []

    for item in parsed:
        if not item["description"]:
            continue

        text = (
            f"CVE ID: {item['id']}. "
            f"Severity: {item['severity']}. "
            f"CVSS Score: {item['cvss_score']}. "
            f"CWE: {', '.join(item['cwe_ids']) if item['cwe_ids'] else 'N/A'}. "
            f"Description: {item['description']}"
        )

        records.append({
            "text": text,
            "metadata": {
                "source": "CVE",
                "cve_id": item["id"],
                "cwe_ids": ",".join(item["cwe_ids"]),
                "severity": item["severity"],
                "cvss_score": str(item["cvss_score"]),
                "category": "vulnerability",
            }
        })

    return records