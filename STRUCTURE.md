# AutoShield Project Structure (Exhaustive)

This document provides a complete map of the AutoShield codebase.

## 🌳 Full File Structure Tree

```text
autoshield/
├── CONTEXT.md                 # Architecture overview
├── SETUP.md                   # Installation guide
├── RUN.md                     # Usage commands
├── STRUCTURE.md               # (This file) Complete map
├── README.md                  # Quick start
├── backend/                   # AI Security Engine (FastAPI)
│   ├── main.py                # App entry point & main endpoints
│   ├── scanner.py             # Static tool orchestrator (Semgrep/ESLint)
│   ├── crawler.py             # Playwright runtime scanner
│   ├── database.py            # SQLAlchemy configuration
│   ├── models.py              # DB Models (User, Scan, Vuln)
│   ├── schemas.py             # Pydantic validation models
│   ├── init_db.py             # Database initializer
│   ├── seed_db.py             # Sample data generator
│   ├── requirements.txt       # Python dependencies
│   ├── api/                   # Modular route groups
│   │   └── rag_routes.py      # Specific RAG endpoints
│   ├── routers/               # Logic-based controllers
│   │   ├── auth.py            # User authentication
│   │   ├── dashboard.py       # Stats & summary logic
│   │   └── scan.py            # Scan management
│   ├── scanners/              # Scanner runner wrappers
│   │   ├── eslint_runner.py
│   │   └── semgrep_runner.py
│   ├── scripts/               # Maintenance utilities
│   │   ├── ingest_all.py      # Initialize RAG vector store
│   │   └── test_llm.py        # Groq reasoning diagnostic
│   ├── chroma_db/             # Persistent Vector Database (Binary)
│   └── rag/                   # RAG Pipeline System
│       ├── config.py          # Central RAG/LLM settings
│       ├── requirements.txt   # Sub-module dependencies
│       ├── data/              # Security Knowledge JSONs (OWASP, CVE)
│       ├── embeddings/        # Chunking & Embedding logic
│       ├── ingestion/         # Source-specific data loaders
│       ├── retrieval/         # Semantic search & ranking
│       ├── services/          # Reasoning, Conflict Resolution, Risk Engine
│       └── vector_store/      # ChromaDB client & schema
├── autoshield-dev/            # VS Code Extension (TypeScript)
│   ├── package.json           # Manifest & configuration
│   ├── tsconfig.json          # TS compiler settings
│   ├── out/                   # Compiled JS output
│   └── src/                   # Source code
│       ├── extension.ts       # Main activation & commands
│       └── sidebar.ts         # Webview dashboard logic
├── dashboard-web/             # Admin Web Interface (React/Vite)
│   ├── index.html             # Entry page
│   ├── package.json           # JS dependencies
│   └── src/                   
│       ├── App.jsx            # Main app shell
│       ├── main.jsx           # React mounting
│       └── components/        # UI Widgets (Charts, Cards)
├── extension-chrome/          # Browser Extension version
│   ├── manifest.json          # Chrome extension manifest
│   ├── background.js          # Service worker
│   ├── content.js             # Page interaction script
│   ├── popup.html/js          # Extension popup UI
│   ├── sidepanel.html/js      # Chrome side-panel UI
│   └── icons/                 # Visual assets
└── extension-vscode/          # Alternate/Legacy VS Code config
```

---

## 📁 Key Components Breakdown

### 1. The Backend Core (`backend/`)
- **`api/` & `routers/`**: Decouples API logic into manageable modules. `auth.py` handles user sessions, while `scan.py` manages long-running analysis tasks.
- **`scanners/`**: Wraps external tools like Semgrep to provide a clean JSON interface to the rest of the app.

### 2. The RAG Pipeline (`backend/rag/`)
- **`embeddings/embedder.py`**: Handles the critical task of converting text into vectors using either local `sentence-transformers` or OpenAI.
- **`services/conflict_resolver.py`**: The "brain" that compares Static vs RAG vs LLM data to determine the final truth about a vulnerability.

### 3. VS Code Extension (`autoshield-dev/`)
- **`src/sidebar.ts`**: A complex Webview-based UI that renders findings in a custom "dark-amber" theme matching the AutoShield brand.

### 4. Web Dashboard (`dashboard-web/`)
- Uses **React** and **Vite** for a fast, responsive interface.
- Includes `VulnerabilityChart.jsx` for visual risk trends.

### 5. Chrome Extension (`extension-chrome/`)
- Implements the same security intelligence for browser-based auditing.
- Uses `manifest.json` v3.
