# scripts/ingest_all.py
# Run this ONCE to ingest all security knowledge into ChromaDB.
# Run: python scripts/ingest_all.py
# Takes 2-5 minutes depending on CVE count.

import sys, os
sys.path.insert(0, os.path.abspath("."))  # Allow imports from project root

from rag.ingestion.load_owasp import load_owasp
from rag.ingestion.load_cwe import load_cwe
from rag.ingestion.load_cve import load_cve
from rag.embeddings.chunking import chunk_records
from rag.embeddings.embedder import embed_texts
from rag.vector_store.chroma_client import upsert_chunks, get_collection_stats


def ingest_source(name: str, records: list) -> int:
    """Generic ingestion pipeline for any data source."""
    print(f"\n{'='*50}")
    print(f"[{name}] Loaded {len(records)} records")

    # Chunk
    chunks = chunk_records(records)
    print(f"[{name}] Created {len(chunks)} chunks")

    # Embed all chunk texts
    texts = [c["text"] for c in chunks]
    embeddings = embed_texts(texts)

    # Attach embeddings to chunks
    for chunk, emb in zip(chunks, embeddings):
        chunk["embedding"] = emb

    # Store
    count = upsert_chunks(chunks)
    print(f"[{name}] Stored {count} chunks in ChromaDB")
    return count


def main():
    print("Starting AutoShield RAG Ingestion Pipeline")
    print("="*50)

    total = 0

    # 1. OWASP Top 10
    owasp_records = load_owasp()
    total += ingest_source("OWASP", owasp_records)

    # 2. CWE
    cwe_records = load_cwe()
    total += ingest_source("CWE", cwe_records)

    # 3. CVE (500 records to start — adjust max_records as needed)
    cve_records = load_cve(max_records=500)
    total += ingest_source("CVE", cve_records)

    # Summary
    stats = get_collection_stats()
    print(f"\n{'='*50}")
    print(f"✅ Ingestion complete!")
    print(f"   Total chunks stored: {stats['count']}")
    print(f"   Collection: {stats['name']}")


if __name__ == "__main__":
    main()