# AutoShield: AI-Powered Security Intelligence

## Project Overview
AutoShield is a next-generation vulnerability management platform that moves beyond simple static analysis. It employs a **Tri-Layer Analysis Engine** to provide high-confidence security insights and automated remediation.

## Current Architecture
The project is currently structured into three main components:

### 1. The Tri-Layer Analysis Engine (Backend)
- **Path A (Static)**: Deterministic scanning using **Semgrep** and **ESLint**.
- **Path B (RAG)**: A Retrieval-Augmented Generation layer that queries a local **ChromaDB** vector store containing:
  - OWASP Top 10 Documentation
  - CWE (Common Weakness Enumeration) entries
  - CVE (Common Vulnerabilities and Exposures) records
- **Path C (LLM)**: A probabilistic reasoning layer powered by **Groq (Llama 3.1)** that analyzes findings in context.

### 2. VS Code Extension (Frontend-Dev)
- Provides a "Security Dashboard" sidebar in the IDE.
- Highlights vulnerabilities with inline squiggles.
- Enables **one-click "Get Fix"** functionality using AI-generated patches.
- Supports **Analyze Selection** for real-time code review.

### 3. Runtime Crawler
- A **Playwright-powered** scanner that analyzes live URLs for:
  - Missing security headers (CSP, HSTS, etc.)
  - Insecure Mixed Content (HTTP scripts on HTTPS sites)
  - Asset compliance.

## Key Innovations
- **Conflict Resolution**: A deterministic engine that resolves disagreements between static tools and LLMs (e.g., suppressing false positives while elevating high-exploitability risks).
- **Local Embeddings**: Uses `sentence-transformers` locally to ensure security data stays private and reduces API costs.
- **Actionable Remediation**: Instead of just flagging issues, AutoShield generates and applies code-level fixes directly to the source.
