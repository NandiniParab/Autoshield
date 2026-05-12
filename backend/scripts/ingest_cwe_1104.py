import os
import sys

sys.path.insert(0, os.path.abspath("."))

from rag.embeddings.chunking import chunk_records
from rag.embeddings.embedder import embed_texts
from rag.ingestion.load_cwe import load_cwe
from rag.vector_store.chroma_client import get_collection, get_collection_stats, upsert_chunks


def main() -> None:
    records = [
        record
        for record in load_cwe()
        if record.get("metadata", {}).get("cwe_id") == "CWE-1104"
    ]
    if not records:
        raise RuntimeError("CWE-1104 record was not found in load_cwe().")

    collection = get_collection()
    try:
        collection.delete(where={"cwe_id": "CWE-1104"})
    except Exception as exc:
        print(f"[CWE-1104] Existing delete skipped: {exc}")

    chunks = chunk_records(records)
    for index, chunk in enumerate(chunks):
        chunk["id"] = f"cwe-CWE-1104-{index}"

    embeddings = embed_texts([chunk["text"] for chunk in chunks])
    for chunk, embedding in zip(chunks, embeddings):
        chunk["embedding"] = embedding

    count = upsert_chunks(chunks)
    stats = get_collection_stats()
    print(f"[CWE-1104] Stored {count} chunk(s). Collection count: {stats['count']}")


if __name__ == "__main__":
    main()
