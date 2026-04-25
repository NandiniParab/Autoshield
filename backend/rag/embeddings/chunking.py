# rag/embeddings/chunking.py
# Word-based chunking with overlap.
# We use WORDS not tokens for simplicity; OpenAI's tokenizer
# is ~1.3 tokens per word so 200 words ≈ 260 tokens — well within limits.

import uuid
from typing import List, Dict
from rag.config import config


def chunk_text(
    text: str,
    chunk_size: int = config.CHUNK_SIZE_WORDS,
    overlap: int = config.CHUNK_OVERLAP_WORDS
) -> List[str]:
    """
    Split text into overlapping word-based chunks.
    Overlap ensures context isn't lost at chunk boundaries.
    """
    words = text.split()
    if not words:
        return []

    chunks = []
    start = 0

    while start < len(words):
        end = min(start + chunk_size, len(words))
        chunk = " ".join(words[start:end])
        chunks.append(chunk)
        if end == len(words):
            break
        start += chunk_size - overlap  # step forward with overlap

    return chunks


def chunk_records(records: List[Dict]) -> List[Dict]:
    """
    Takes raw records [{text, metadata}] and returns chunked records
    with unique IDs. Each chunk inherits the parent's metadata.
    
    Output format:
    {
        "id": "uuid4",
        "text": "chunk text...",
        "metadata": { source, cwe_id, severity, ... }
    }
    """
    chunked = []

    for record in records:
        text = record["text"]
        metadata = record["metadata"]
        chunks = chunk_text(text)

        for i, chunk in enumerate(chunks):
            chunk_meta = {
                **metadata,
                "chunk_index": str(i),
                "total_chunks": str(len(chunks)),
            }
            chunked.append({
                "id": str(uuid.uuid4()),
                "text": chunk,
                "metadata": chunk_meta,
            })

    return chunked