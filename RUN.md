# AutoShield Execution Guide

How to run the different components of the AutoShield platform.

## 1. Start the Backend Server
Always start the backend first, as both the extension and dashboard depend on it.
```powershell
cd backend
.\venv\Scripts\Activate.ps1
uvicorn main:app --reload
```
- API will be available at: `http://127.0.0.1:8000`
- API Docs: `http://127.0.0.1:8000/docs`

## 2. Launch the VS Code Extension
1. Open the `autoshield-dev` folder in VS Code.
2. Press **F5** to open a new "Extension Development Host" window.
3. In the new window, open the project you want to scan.
4. Click the **AutoShield** icon in the activity bar (left sidebar).
5. Click **[S] Scan** to start a project-wide analysis.

## 3. Run Analysis Tools
### Full Project Scan
- Use the **[S] Scan** button in the VS Code sidebar.
- Choose "Full Analysis" for LLM-enriched results.

### Single Snippet Analysis
- Highlight code in the editor.
- **Right-click** -> **AutoShield: Analyze Selection**.

### Apply Fixes
- Expand a vulnerability card in the sidebar.
- Click **Get Fix**.
- Review the AI-generated code and click **Apply**.

## 4. Run Maintenance Scripts
- **Test LLM**: `python scripts/test_llm.py` (Verify Groq connection)
- **Re-ingest Knowledge**: `python scripts/ingest_all.py` (Update RAG data)
- **Seed DB**: `python seed_db.py` (Add demo data to relational DB)
