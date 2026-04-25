# rag/embeddings/embedder.py
# Supports BOTH OpenAI embeddings and local SentenceTransformer embeddings
# Toggle via config.USE_LOCAL_EMBEDDINGS

import time
from typing import List

from rag.config import config

# -----------------------------
# LOCAL EMBEDDINGS (FREE)
# -----------------------------
_local_model = None

def get_local_model():
    global _local_model
    if _local_model is None:
        from sentence_transformers import SentenceTransformer
        _local_model = SentenceTransformer("all-MiniLM-L6-v2")
    return _local_model


def embed_texts_local(texts: List[str]) -> List[List[float]]:
    model = get_local_model()
    return model.encode(texts).tolist()


def embed_query_local(query: str) -> List[float]:
    model = get_local_model()
    return model.encode([query])[0].tolist()


# -----------------------------
# OPENAI EMBEDDINGS (PAID)
# -----------------------------
_client = None

def get_client():
    from openai import OpenAI
    global _client
    if _client is None:
        _client = OpenAI(api_key=config.OPENAI_API_KEY)
    return _client


def embed_texts_openai(texts: List[str], batch_size: int = 100) -> List[List[float]]:
    client = get_client()
    all_embeddings = []

    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]

        try:
            response = client.embeddings.create(
                model=config.EMBEDDING_MODEL,
                input=batch
            )

            all_embeddings.extend([e.embedding for e in response.data])
            print(f"[Embedder] OpenAI batch {i//batch_size + 1}: {len(batch)} texts")

        except Exception as e:
            if "rate_limit" in str(e).lower():
                print("[Embedder] Rate limit hit, sleeping 60s...")
                time.sleep(60)

                response = client.embeddings.create(
                    model=config.EMBEDDING_MODEL,
                    input=batch
                )
                all_embeddings.extend([e.embedding for e in response.data])
            else:
                raise

    return all_embeddings


def embed_query_openai(query: str) -> List[float]:
    client = get_client()
    response = client.embeddings.create(
        model=config.EMBEDDING_MODEL,
        input=[query]
    )
    return response.data[0].embedding


# -----------------------------
# UNIFIED API (USED BY YOUR PIPELINE)
# -----------------------------
def embed_texts(texts: List[str]) -> List[List[float]]:
    if getattr(config, "USE_LOCAL_EMBEDDINGS", True):
        return embed_texts_local(texts)
    return embed_texts_openai(texts)


def embed_query(query: str) -> List[float]:
    if getattr(config, "USE_LOCAL_EMBEDDINGS", True):
        return embed_query_local(query)
    return embed_query_openai(query)