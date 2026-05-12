# rag/services/self_rag.py
#
# Self-RAG — smarter retrieval with document grading + query rewriting.
#
# Flow:
#   user query
#     ↓  retrieve docs from ChromaDB
#     ↓  deduplicate
#     ↓  grade: keyword check + similarity threshold
#     ↓  if WEAK  → deterministic / LLM query rewrite → retrieve again → deduplicate
#     ↓  generate final answer with honest confidence instructions
#
# Plugs into the existing retriever (rag/retrieval/retriever.py)
# and the existing Groq LLM wrapper (rag/services/llm_service.py).

import re
from typing import List, Dict, Any, Optional

from rag.services.vulnerability_validator import VulnerabilityValidator
from rag.retrieval.retriever import retrieve_context
from rag.services.llm_service import _call_llm


# SimpleRetriever removed. Now using core retrieve_context directly.


# ─────────────────────────────────────────────────────────────────────────────
# Thin LLM wrapper
# ─────────────────────────────────────────────────────────────────────────────

class GroqLLM:
    """
    Thin wrapper around the existing _call_llm helper so Self-RAG can
    call llm.invoke(prompt) — a simple, consistent interface.
    """

    def invoke(self, prompt: str) -> str:
        return _call_llm(prompt)


# ─────────────────────────────────────────────────────────────────────────────
# Self-RAG core
# ─────────────────────────────────────────────────────────────────────────────

class SelfRAG:
    """
    Self-Reflective RAG pipeline.

    Usage:
        rag = SelfRAG()
        result = rag.run("How to fix SQL injection in login API?")
        print(result["answer"])
    """

    def __init__(self, llm=None):
        self.llm       = llm       or GroqLLM()
        self.validator = VulnerabilityValidator()

    # ── Step 0: metadata detection ────────────────────────────────────

    def detect_security_metadata(self, query: str):
        """
        Extracts CWE ID and severity from the query to help the retriever.
        """
        q = query.lower()
        if "vulnerable dependency" in q or "outdated component" in q or "a06" in q or "npm-audit" in q:
            return "CWE-1104", "high"
        if "sql injection" in q or "cwe-89" in q:
            return "CWE-89", "high"
        if "hardcoded" in q or "secret" in q or "api key" in q or "cwe-798" in q:
            return "CWE-798", "high"
        if "xss" in q or "cross site scripting" in q or "cross-site scripting" in q or "cwe-79" in q:
            return "CWE-79", "high"
        if "csrf" in q or "cwe-352" in q:
            return "CWE-352", "high"
        if "command injection" in q or "cwe-78" in q:
            return "CWE-78", "critical"
        if "code injection" in q or re.search(r"\beval\b", q) or "cwe-95" in q:
            return "CWE-95", "critical"
        if "md5" in q or "sha1" in q or "weak cryptography" in q or "cwe-327" in q:
            return "CWE-327", "medium"
        if "cors" in q or "cwe-942" in q:
            return "CWE-942", "medium"
        if "path traversal" in q or "cwe-22" in q:
            return "CWE-22", "high"
        if "rate limit" in q or "cwe-307" in q:
            return "CWE-307", "medium"
        if "auth" in q or "login" in q or "password" in q or "cwe-287" in q:
            return "CWE-287", "critical"
        return "N/A", "medium"

    # ── Step 1: retrieve ──────────────────────────────────────────────

    def retrieve_docs(self, query: str, k: int = 5) -> List[Dict[str, Any]]:
        """Calls the core retrieve_context with CWE + severity metadata."""
        cwe_id, severity = self.detect_security_metadata(query)
        docs = retrieve_context(query, cwe_id, severity, top_k=k)
        print(f"[SelfRAG] Retrieved {len(docs)} docs for query: {query[:80]}...")
        return docs

    # ── Step 2: deduplicate ───────────────────────────────────────────

    def deduplicate_docs(self, docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Removes duplicate chunks (same text returned multiple times by ChromaDB).
        Preserves original order; keeps the first occurrence of each unique text.
        """
        seen: set = set()
        unique: List[Dict[str, Any]] = []
        for doc in docs:
            text = doc.get("text", "")
            if text not in seen:
                unique.append(doc)
                seen.add(text)
        removed = len(docs) - len(unique)
        if removed:
            print(f"[SelfRAG] Deduplicated: removed {removed} duplicate doc(s).")
        return unique

    # ── Step 3: grade ─────────────────────────────────────────────────

    def grade_documents(self, query: str, docs: List[Dict[str, Any]]) -> bool:
        """
        Strict relevance check — two-stage:

        Stage A — keyword matching:
          For known vulnerability keywords in the query, at least one
          domain-specific term must appear in the combined retrieved text.
          If nothing matches, immediately reject (no need to call LLM).

        Stage B — similarity threshold:
          Best cosine similarity must be >= 0.45.
          Scores below that indicate the retriever is effectively guessing.

        Returns True if docs pass both stages, False otherwise.
        """
        if not docs:
            return False

        query_lower   = query.lower()
        combined_text = " ".join([doc.get("text", "").lower() for doc in docs])
        hardcoded_query = any(term in query_lower for term in ("hardcoded", "secret", "api key", "cwe-798"))
        dependency_query = any(
            term in query_lower
            for term in ("vulnerable dependency", "outdated component", "npm audit", "npm-audit", "owasp a06", "a06", "cwe-1104")
        )

        # --- Stage A: domain keyword gating ---------------------------------
        keyword_rules = {
            "sql injection": [
                "sql injection", "injection", "cwe-89",
                "prepared statement", "parameterized query", "owasp a03",
            ],
            "xss": [
                "cross-site scripting", "xss", "cwe-79",
                "output encoding", "content security policy", "owasp a03",
            ],
            "cross site scripting": [
                "cross-site scripting", "xss", "cwe-79",
                "output encoding", "content security policy", "owasp a03",
            ],
            "csrf": [
                "csrf", "cross-site request forgery", "cwe-352",
                "anti-csrf token", "same-site cookie", "owasp a01",
            ],
            "command injection": [
                "command injection", "os command", "cwe-78",
                "shell injection", "owasp a03",
            ],
            "code injection": [
                "code injection", "eval", "function constructor", "cwe-95",
                "owasp a03",
            ],
            "eval": [
                "code injection", "eval", "function constructor", "cwe-95",
                "owasp a03",
            ],
            "hardcoded": [
                "hardcoded", "credential", "secret", "api key", "token",
                "cwe-798", "owasp a07",
            ],
            "secret": [
                "hardcoded", "credential", "secret", "api key", "token",
                "cwe-798", "owasp a07",
            ],
            "weak cryptography": [
                "weak cryptography", "weak hashing", "md5", "sha1",
                "cwe-327", "owasp a02",
            ],
            "md5": [
                "weak cryptography", "weak hashing", "md5", "sha1",
                "cwe-327", "owasp a02",
            ],
            "sha1": [
                "weak cryptography", "weak hashing", "md5", "sha1",
                "cwe-327", "owasp a02",
            ],
            "cors": [
                "cors", "cross-origin resource sharing", "wildcard origin",
                "cwe-942", "owasp a05",
            ],
            "path traversal": [
                "path traversal", "directory traversal", "cwe-22",
                "owasp a01",
            ],
            "rate limit": [
                "rate limit", "rate limiting", "brute force", "cwe-307",
                "owasp a07",
            ],
            "vulnerable dependency": [
                "vulnerable dependency", "outdated component",
                "third party component", "third-party component",
                "package", "cwe-1104", "owasp a06",
            ],
            "outdated component": [
                "vulnerable dependency", "outdated component",
                "third party component", "third-party component",
                "package", "cwe-1104", "owasp a06",
            ],
            "npm audit": [
                "vulnerable dependency", "outdated component",
                "third party component", "package", "cwe-1104", "owasp a06",
            ],
            "authentication": [
                "authentication", "session management", "mfa",
                "password hash", "owasp a07", "cwe-287",
            ],
            "password": [
                "password", "bcrypt", "argon2", "pbkdf2",
                "owasp a07", "cwe-259", "cwe-521",
            ],
            "broken access": [
                "access control", "authorization", "privilege",
                "owasp a01", "cwe-284",
            ],
            "ssrf": [
                "ssrf", "server-side request forgery", "cwe-918", "owasp a10",
            ],
            "xxe": [
                "xxe", "xml external entity", "cwe-611", "owasp a05",
            ],
        }

        for trigger, required_terms in keyword_rules.items():
            if hardcoded_query and trigger in ("authentication", "password"):
                continue
            if dependency_query and trigger not in ("vulnerable dependency", "outdated component", "npm audit"):
                continue
            if trigger == "eval":
                trigger_present = re.search(r"\beval\b", query_lower) is not None
            else:
                trigger_present = trigger in query_lower

            if trigger_present:
                match_found = any(term in combined_text for term in required_terms)
                if not match_found:
                    print(
                        f"[SelfRAG] Grade FAIL — query mentions '{trigger}' "
                        f"but no matching terms found in docs."
                    )
                    return False

        # --- Stage B: similarity threshold ----------------------------------
        best_similarity = max(doc.get("similarity", 0) for doc in docs)
        if best_similarity < 0.45:
            print(
                f"[SelfRAG] Grade FAIL — best similarity {best_similarity:.4f} "
                f"is below threshold 0.45."
            )
            return False

        print(f"[SelfRAG] Grade PASS — best similarity {best_similarity:.4f}.")
        return True

    # ── Step 4: rewrite query ─────────────────────────────────────────

    def rewrite_query(self, query: str) -> str:
        """
        Rewrites a weak query into a better security-focused query.

        For common vulnerability types, returns a deterministic,
        OWASP/CWE-enriched query string directly (no LLM call needed,
        avoids hallucination and latency).

        Falls back to the LLM only for less-common / composite queries.
        """
        query_lower = query.lower()

        # Deterministic rules — ordered by specificity
        if "sql injection" in query_lower:
            rewritten = (
                "OWASP A03 Injection SQL Injection CWE-89 "
                "prepared statements parameterized queries login API secure coding"
            )
        elif "xss" in query_lower or "cross site scripting" in query_lower:
            rewritten = (
                "OWASP A03 Injection Cross Site Scripting CWE-79 "
                "output encoding input sanitization content security policy"
            )
        elif "csrf" in query_lower or "cross site request forgery" in query_lower:
            rewritten = (
                "OWASP A01 Broken Access Control CSRF CWE-352 "
                "anti-csrf token same-site cookie"
            )
        elif "vulnerable dependency" in query_lower or "outdated component" in query_lower or "npm audit" in query_lower or "npm-audit" in query_lower or "a06" in query_lower:
            rewritten = (
                "OWASP A06 Vulnerable and Outdated Components CWE-1104 "
                "vulnerable dependency outdated third party component package advisory CVE npm audit"
            )
        elif "command injection" in query_lower:
            rewritten = (
                "OWASP A03 Injection OS Command Injection CWE-78 "
                "shell escape subprocess secure coding"
            )
        elif "path traversal" in query_lower or "directory traversal" in query_lower:
            rewritten = (
                "OWASP A01 Broken Access Control Path Traversal CWE-22 "
                "file path validation canonicalization"
            )
        elif "ssrf" in query_lower or "server side request forgery" in query_lower:
            rewritten = (
                "OWASP A10 Server Side Request Forgery SSRF CWE-918 "
                "allowlist URL validation internal network"
            )
        elif "xxe" in query_lower or "xml external entity" in query_lower:
            rewritten = (
                "OWASP A05 Security Misconfiguration XXE CWE-611 "
                "disable external entity processing XML parser"
            )
        elif "broken access" in query_lower or "authorization" in query_lower:
            rewritten = (
                "OWASP A01 Broken Access Control CWE-284 "
                "role based access control privilege escalation authorization"
            )
        elif "hardcoded" in query_lower or "secret" in query_lower or "api key" in query_lower:
            rewritten = (
                "OWASP A07 Identification and Authentication Failures CWE-798 "
                "CWE-798 Hardcoded Secret hardcoded API key credential exposure "
                "hardcoded credentials secret token secure storage environment variables"
            )
        elif "authentication" in query_lower or "login" in query_lower or "password" in query_lower:
             rewritten = (
                "OWASP A07 Identification and Authentication Failures CWE-287 "
                "password hashing bcrypt Argon2 session management MFA secure login"
            )
        elif "code injection" in query_lower or re.search(r"\beval\b", query_lower):
            rewritten = (
                "OWASP A03 Injection Code Injection CWE-95 "
                "eval Function constructor secure coding"
            )
        elif "md5" in query_lower or "sha1" in query_lower or "weak cryptography" in query_lower:
            rewritten = (
                "OWASP A02 Cryptographic Failures CWE-327 "
                "weak hashing MD5 SHA1 secure cryptography bcrypt Argon2"
            )
        elif "cors" in query_lower:
            rewritten = (
                "OWASP A05 Security Misconfiguration Insecure CORS CWE-942 "
                "wildcard origin cross-origin resource sharing secure configuration"
            )
        elif "rate limit" in query_lower:
            rewritten = (
                "OWASP A07 Identification and Authentication Failures Missing Rate Limiting CWE-307 "
                "brute force rate limit express-rate-limit secure login"
            )
        else:
            # Generic LLM fallback for less-common queries
            prompt = (
                f"Rewrite this query for cybersecurity RAG retrieval.\n"
                f"Add OWASP category, CWE ID, vulnerability name, "
                f"exploitability, and secure coding terms.\n\n"
                f"Original query:\n{query}\n\n"
                f"Return only the rewritten query."
            )
            rewritten = self.llm.invoke(prompt).strip()

        print(f"[SelfRAG] Rewritten query: {rewritten[:120]}")
        return rewritten

    # ── Step 5: generate answer ───────────────────────────────────────

    def generate_answer(self, query: str, docs: List[Dict[str, Any]]) -> str:
        """
        Generates a structured security answer using only the retrieved docs.
        Instructs the LLM to set confidence LOW when context does not match query.
        """
        context = "\n\n".join(
            [str(d.get("text", d)) for d in docs]
        )

        prompt = f"""You are AutoShield, an AI security analysis assistant.

Use only the context below.
Do not invent OWASP, CWE, or CVE values.
If the context does not support the query, say confidence is LOW.

Context:
{context[:3000]}

User query:
{query}

Answer in this format:

1. Vulnerability Summary
Explain the issue in simple language.

2. Evidence Used
Mention only evidence from the provided context.

3. Security Mapping
Mention OWASP/CWE/CVE only if present in the context.

4. Exploit Scenario
Explain how an attacker could exploit this.

5. Recommended Fix
Give secure coding fix.

6. Confidence Level
HIGH only if context directly supports the vulnerability.
MEDIUM if partially supported.
LOW if unsupported.
"""

        return self.llm.invoke(prompt)

    # ── Main loop ─────────────────────────────────────────────────────

    def run(
        self,
        query: str,
        k: int = 5,
        static_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Full Self-RAG loop:
          retrieve → deduplicate → grade
          → if WEAK: rewrite → retrieve again → deduplicate
          → generate answer
          → validate across static scan + RAG + LLM evidence layers

        Args:
            query:           Natural-language security question.
            k:               Number of docs to retrieve.
            static_findings: Optional Semgrep / ESLint findings for
                             the Evidence-Based Validator.
        """
        static_findings = static_findings or []

        # Attempt 1
        docs = self.retrieve_docs(query, k=k)
        docs = self.deduplicate_docs(docs)

        is_relevant     = self.grade_documents(query, docs)
        query_used      = query
        query_rewritten = False

        if not is_relevant:
            # Attempt 2 with improved query
            improved_query  = self.rewrite_query(query)
            docs            = self.retrieve_docs(improved_query, k=k)
            docs            = self.deduplicate_docs(docs)
            query_used      = improved_query
            query_rewritten = True

        # Always generate answer using the original (human-readable) query
        final_answer = self.generate_answer(query, docs)

        # Evidence-Based Validation — cross-check all three layers
        validation = self.validator.validate(
            query=query,
            docs=docs,
            static_findings=static_findings,
            llm_answer=final_answer,
        )

        return {
            "original_query":  query,
            "query_used":      query_used,
            "query_rewritten": query_rewritten,
            "documents_used":  docs,
            "validation":      validation,
            "answer":          final_answer,
        }
