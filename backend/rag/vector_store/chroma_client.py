# rag/vector_store/chroma_client.py
# ChromaDB singleton client with persistent storage.
# Data survives restarts — stored in ./chroma_db/ directory.

import chromadb
from chromadb.config import Settings
from rag.config import config
from typing import List
# Module-level singleton
_chroma_client = None
_collection = None


def get_chroma_client() -> chromadb.Client:
    """Returns singleton ChromaDB client with persistent storage."""
    global _chroma_client
    if _chroma_client is None:
        _chroma_client = chromadb.PersistentClient(
            path=config.CHROMA_DB_PATH
        )
    return _chroma_client


def get_collection() -> chromadb.Collection:
    """
    Returns the main security knowledge collection.
    Creates it if it doesn't exist.
    
    We use cosine similarity (best for text semantic search).
    """
    global _collection
    if _collection is None:
        client = get_chroma_client()
        _collection = client.get_or_create_collection(
            name=config.CHROMA_COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"}  # cosine distance for embeddings
        )
    return _collection


def upsert_chunks(chunks: list) -> int:
    """
    Insert or update chunks in ChromaDB.
    Each chunk must have: id, text, embedding, metadata.
    Returns count of upserted documents.
    """
    collection = get_collection()

    ids = [c["id"] for c in chunks]
    documents = [c["text"] for c in chunks]
    embeddings = [c["embedding"] for c in chunks]
    metadatas = [c["metadata"] for c in chunks]

    # Upsert in batches of 500 (ChromaDB recommended max)
    batch_size = 500
    for i in range(0, len(ids), batch_size):
        collection.upsert(
            ids=ids[i:i+batch_size],
            documents=documents[i:i+batch_size],
            embeddings=embeddings[i:i+batch_size],
            metadatas=metadatas[i:i+batch_size],
        )
        print(f"[ChromaDB] Upserted batch {i//batch_size + 1}")

    return len(ids)


def query_collection(
    embedding: List[float],
    n_results: int = 5,
    where_filter: dict = None
) -> dict:
    """
    Query ChromaDB for nearest neighbors.
    Optional where_filter for metadata filtering (e.g., source=OWASP).
    """
    collection = get_collection()
    kwargs = {
        "query_embeddings": [embedding],
        "n_results": n_results,
        "include": ["documents", "metadatas", "distances"],
    }
    if where_filter:
        kwargs["where"] = where_filter

    return collection.query(**kwargs)


def get_collection_stats() -> dict:
    """Returns basic stats about what's in the collection."""
    collection = get_collection()
    return {"count": collection.count(), "name": collection.name}