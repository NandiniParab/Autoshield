# rag/config.py
# Central configuration — all env vars loaded once here.
# Import this module anywhere you need settings.

import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # OpenAI
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")

    # ChromaDB
    CHROMA_DB_PATH: str = os.getenv("CHROMA_DB_PATH", "./chroma_db")
    CHROMA_COLLECTION_NAME: str = os.getenv("CHROMA_COLLECTION_NAME", "autoshield_security")

    # Retrieval
    TOP_K_RESULTS: int = int(os.getenv("TOP_K_RESULTS", "5"))

    # Chunking
    CHUNK_SIZE_WORDS: int = 200   # target words per chunk
    CHUNK_OVERLAP_WORDS: int = 30  # overlap between chunks

    # Data paths
    DATA_DIR: str = "rag/data"
    OWASP_DIR: str = "rag/data/owasp"
    CVE_DIR: str = "rag/data/cve"
    CWE_DIR: str = "rag/data/cwe"

config = Config()
USE_LOCAL_EMBEDDINGS = True