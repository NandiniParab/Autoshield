# AutoShield Setup Guide

Follow these steps to set up the AutoShield development environment.

## 1. Prerequisites
- **Python 3.9+**
- **Node.js 18+**
- **Git**
- **Groq API Key** (Get one at [console.groq.com](https://console.groq.com))

## 2. Backend Setup
1. **Create Virtual Environment**:
   ```powershell
   cd backend
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
2. **Install Dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```
3. **Initialize Playwright**:
   ```powershell
   playwright install chromium
   ```
4. **Environment Variables**:
   Create `backend/.env` and add:
   ```env
   DATABASE_URL=your_postgres_url
   GROQ_API_KEY=your_groq_key
   GROQ_MODEL=llama-3.1-8b-instant
   CHROMA_DB_PATH=./chroma_db
   CHROMA_COLLECTION_NAME=autoshield_security
   ```

## 3. RAG Knowledge Base Initialization
You must populate the vector store once before using the RAG features:
```powershell
python scripts/ingest_all.py
```

## 4. VS Code Extension Setup
1. Navigate to the extension folder:
   ```powershell
   cd autoshield-dev
   ```
2. Install dependencies:
   ```powershell
   npm install
   ```
3. Compile the extension:
   ```powershell
   npm run compile
   ```

## 5. Web Dashboard Setup (Optional)
If you are using the web dashboard:
```powershell
cd dashboard-web
npm install
```
