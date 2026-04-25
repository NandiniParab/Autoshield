# rag/retrieval/retriever.py
# Core retrieval logic.
# Builds a semantic query from vulnerability context,
# retrieves top-k chunks, and returns structured results.

from typing import List, Dict, Optional
from rag.embeddings.embedder import embed_query
from rag.vector_store.chroma_client import query_collection
from rag.config import config


def build_query_text(
    code_snippet: str,
    cwe_id: str,
    severity: str,
    vuln_type: str = ""
) -> str:
    """
    Constructs a rich semantic query from vulnerability context.
    
    We do NOT embed raw code — instead we build a natural language
    description of the vulnerability. This matches better with our
    OWASP/CWE knowledge base which is also natural language.
    
    Example output:
    "SQL Injection vulnerability CWE-89 high severity. 
     Unsanitized user input passed to database query."
    """
    parts = []

    if vuln_type:
        parts.append(vuln_type)

    if cwe_id:
        parts.append(f"CWE ID: {cwe_id}")

    parts.append(f"severity: {severity}")

    # Extract a short context from code (first 200 chars)
    if code_snippet:
        code_context = code_snippet[:200].strip().replace("\n", " ")
        parts.append(f"code context: {code_context}")

    return ". ".join(parts)


def retrieve_context(
    code_snippet: str,
    cwe_id: str,
    severity: str,
    vuln_type: str = "",
    top_k: int = config.TOP_K_RESULTS
) -> List[Dict]:
    """
    Main retrieval function.
    
    Args:
        code_snippet: The vulnerable code
        cwe_id: e.g. "CWE-89"
        severity: "low", "medium", "high", "critical"
        vuln_type: e.g. "SQL Injection" (from static analysis tool)
        top_k: number of results to return
    
    Returns:
        List of retrieved chunks with metadata and similarity score
    """
    # Step 1: Build semantic query
    query_text = build_query_text(code_snippet, cwe_id, severity, vuln_type)
    print(f"[Retriever] Query: {query_text[:100]}...")

    # Step 2: Embed the query
    query_embedding = embed_query(query_text)

    # Step 3: Retrieve from ChromaDB
    raw_results = query_collection(
        embedding=query_embedding,
        n_results=top_k * 2,  # Fetch more, then re-rank
    )

    # Step 4: Parse results
    results = []
    docs = raw_results.get("documents", [[]])[0]
    metas = raw_results.get("metadatas", [[]])[0]
    distances = raw_results.get("distances", [[]])[0]

    for doc, meta, dist in zip(docs, metas, distances):
        # Cosine distance → similarity score (1 = identical)
        similarity = 1 - dist
        results.append({
            "text": doc,
            "metadata": meta,
            "similarity": round(similarity, 4),
        })

    # Step 5: Re-rank — boost exact CWE matches
    results = rerank_by_cwe(results, cwe_id)

    return results[:top_k]


def rerank_by_cwe(results: List[Dict], cwe_id: str) -> List[Dict]:
    """
    Re-rank results by boosting exact CWE ID matches.
    This is a simple but effective deterministic re-ranking.
    Adds 0.1 to similarity score for exact CWE match.
    """
    if not cwe_id:
        return results

    for r in results:
        meta_cwe = r["metadata"].get("cwe_ids", "")
        meta_cwe_single = r["metadata"].get("cwe_id", "")
        if cwe_id in meta_cwe or cwe_id == meta_cwe_single:
            r["similarity"] = min(1.0, r["similarity"] + 0.1)
            r["cwe_match"] = True

    return sorted(results, key=lambda x: x["similarity"], reverse=True)