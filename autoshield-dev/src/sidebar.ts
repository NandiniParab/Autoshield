import * as vscode from 'vscode';

export class AutoShieldSidebarProvider implements vscode.WebviewViewProvider {
    private _view?: vscode.WebviewView;

    constructor(private readonly _extensionUri: vscode.Uri) {}

    resolveWebviewView(webviewView: vscode.WebviewView) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri],
        };

        webviewView.webview.html = this._getHtml();

        // Handle messages FROM the webview
        webviewView.webview.onDidReceiveMessage(async (msg) => {
            switch (msg.type) {
                case 'jumpToFile': {
                    if (!msg.filePath || msg.filePath === 'unknown') { return; }
                    try {
                        const uri = vscode.Uri.file(msg.filePath);
                        const doc = await vscode.workspace.openTextDocument(uri);
                        const editor = await vscode.window.showTextDocument(doc);
                        const line = Math.max(0, (msg.line || 1) - 1);
                        const pos = new vscode.Position(line, 0);
                        editor.selection = new vscode.Selection(pos, pos);
                        editor.revealRange(
                            new vscode.Range(pos, pos),
                            vscode.TextEditorRevealType.InCenter
                        );
                    } catch {
                        vscode.window.showWarningMessage(`Cannot open: ${msg.filePath}`);
                    }
                    break;
                }
                case 'runScan': {
                    vscode.commands.executeCommand('autoshield.scan');
                    break;
                }
                case 'clearResults': {
                    vscode.commands.executeCommand('autoshield.clear');
                    break;
                }
            }
        });
    }

    /** Push data from extension → webview */
    postMessage(msg: object) {
        this._view?.webview.postMessage(msg);
    }

    private _getHtml(): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>AutoShield</title>
<style>
  /* ── Reset & base ─────────────────────────────────────────── */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --surface2: #21262d;
    --border: #30363d;
    --accent: #58a6ff;
    --accent2: #3fb950;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --critical: #ff7b72;
    --high: #ffa657;
    --medium: #e3b341;
    --low: #3fb950;
    --info: #58a6ff;
    --radius: 8px;
    font-size: 13px;
  }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    line-height: 1.5;
    padding: 0;
    overflow-x: hidden;
  }

  /* ── Header ───────────────────────────────────────────────── */
  .header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 12px 14px;
    display: flex;
    align-items: center;
    gap: 10px;
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .logo-mark {
    width: 28px; height: 28px;
    background: linear-gradient(135deg, var(--accent), #a371f7);
    border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    font-size: 14px; flex-shrink: 0;
  }
  .header-title { font-weight: 700; font-size: 14px; flex: 1; }
  .header-subtitle { font-size: 11px; color: var(--text-muted); }

  /* ── Buttons ──────────────────────────────────────────────── */
  .btn-row { display: flex; gap: 8px; padding: 10px 14px; }
  .btn {
    flex: 1;
    padding: 7px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface2);
    color: var(--text);
    cursor: pointer;
    font-size: 12px;
    font-weight: 500;
    transition: background 0.15s, border-color 0.15s;
    text-align: center;
  }
  .btn:hover { background: var(--border); border-color: var(--accent); }
  .btn-primary {
    background: var(--accent);
    color: #000;
    border-color: var(--accent);
    font-weight: 600;
  }
  .btn-primary:hover { background: #79bfff; }

  /* ── Summary bar ─────────────────────────────────────────── */
  #summary-bar {
    display: none;
    padding: 10px 14px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 6px;
  }
  .sum-chip {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 8px;
    text-align: center;
  }
  .sum-chip .num { font-size: 18px; font-weight: 700; }
  .sum-chip .lbl { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .sum-chip.critical .num { color: var(--critical); }
  .sum-chip.high .num { color: var(--high); }
  .sum-chip.medium .num { color: var(--medium); }
  .sum-chip.low .num { color: var(--low); }

  /* ── State panels ────────────────────────────────────────── */
  #empty-state {
    padding: 40px 20px;
    text-align: center;
    color: var(--text-muted);
  }
  #empty-state .big-icon { font-size: 40px; margin-bottom: 12px; }
  #empty-state h3 { font-size: 15px; color: var(--text); margin-bottom: 6px; }
  #loading-state {
    display: none;
    padding: 40px 20px;
    text-align: center;
    color: var(--text-muted);
  }
  .spinner {
    width: 32px; height: 32px;
    border: 3px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    margin: 0 auto 16px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Results list ────────────────────────────────────────── */
  #results-container { display: none; padding: 0 14px 14px; }
  #results-list { display: flex; flex-direction: column; gap: 8px; margin-top: 10px; }

  /* ── Finding card ────────────────────────────────────────── */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    transition: border-color 0.15s;
  }
  .card:hover { border-color: var(--accent); }
  .card-header {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 12px;
    cursor: pointer;
    user-select: none;
  }
  .sev-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    margin-top: 5px;
    flex-shrink: 0;
  }
  .sev-dot.CRITICAL { background: var(--critical); }
  .sev-dot.HIGH { background: var(--high); }
  .sev-dot.MEDIUM { background: var(--medium); }
  .sev-dot.LOW { background: var(--low); }
  .sev-dot.INFORMATIONAL { background: var(--info); }

  .card-main { flex: 1; min-width: 0; }
  .card-title {
    font-weight: 600;
    font-size: 12.5px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .card-sub {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 2px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .card-score {
    font-size: 18px;
    font-weight: 700;
    flex-shrink: 0;
    line-height: 1;
  }
  .card-score.CRITICAL { color: var(--critical); }
  .card-score.HIGH { color: var(--high); }
  .card-score.MEDIUM { color: var(--medium); }
  .card-score.LOW { color: var(--low); }
  .card-score.INFORMATIONAL { color: var(--info); }

  /* ── Card expanded body ─────────────────────────────────── */
  .card-body {
    display: none;
    padding: 0 12px 12px;
    border-top: 1px solid var(--border);
    font-size: 12px;
  }
  .card-body.open { display: block; }

  .tag-row { display: flex; flex-wrap: wrap; gap: 5px; margin: 8px 0; }
  .tag {
    padding: 2px 8px;
    border-radius: 20px;
    font-size: 10px;
    font-weight: 600;
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--text-muted);
  }
  .tag.cwe { border-color: #58a6ff44; color: var(--accent); }
  .tag.owasp { border-color: #3fb95044; color: var(--accent2); }
  .tag.fp { border-color: #e3b34144; color: var(--medium); }
  .tag.conflict { border-color: #ff7b7244; color: var(--critical); }

  .section-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin: 10px 0 4px;
    font-weight: 600;
  }
  .reasoning-box {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
    font-size: 11.5px;
    color: var(--text);
    line-height: 1.5;
    font-style: italic;
  }
  .fix-box {
    background: #3fb95015;
    border: 1px solid #3fb95030;
    border-radius: 6px;
    padding: 8px 10px;
    font-size: 11.5px;
    line-height: 1.5;
  }
  .risks-list {
    list-style: none;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .risks-list li::before { content: '→ '; color: var(--text-muted); }
  .risks-list li { font-size: 11.5px; }

  .score-bar-row { display: flex; flex-direction: column; gap: 4px; margin-top: 6px; }
  .score-bar-item { display: flex; align-items: center; gap: 8px; }
  .score-bar-label { width: 90px; font-size: 10px; color: var(--text-muted); flex-shrink: 0; }
  .score-bar-track {
    flex: 1; height: 4px;
    background: var(--surface2);
    border-radius: 2px;
    overflow: hidden;
  }
  .score-bar-fill { height: 100%; border-radius: 2px; background: var(--accent); }
  .score-bar-val { width: 28px; text-align: right; font-size: 10px; color: var(--text-muted); }

  .jump-btn {
    display: inline-block;
    margin-top: 10px;
    padding: 5px 12px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 5px;
    font-size: 11px;
    color: var(--accent);
    cursor: pointer;
    transition: background 0.15s;
    font-weight: 500;
  }
  .jump-btn:hover { background: var(--border); }

  .path-trace {
    font-size: 10px;
    color: var(--text-muted);
    margin-top: 8px;
    font-family: monospace;
    word-break: break-all;
    background: var(--surface2);
    border-radius: 4px;
    padding: 4px 6px;
  }

  /* ── Single analysis view ────────────────────────────────── */
  #single-view { display: none; padding: 14px; }
  .back-btn {
    font-size: 12px;
    color: var(--accent);
    cursor: pointer;
    margin-bottom: 12px;
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .back-btn:hover { text-decoration: underline; }
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="logo-mark">🛡</div>
  <div>
    <div class="header-title">AutoShield</div>
    <div class="header-subtitle">Tri-Layer Security Analysis</div>
  </div>
</div>

<!-- Action buttons -->
<div class="btn-row">
  <button class="btn btn-primary" onclick="vscode.postMessage({type:'runScan'})">⚡ Scan Project</button>
  <button class="btn" onclick="vscode.postMessage({type:'clearResults'})">✕ Clear</button>
</div>

<!-- Summary bar -->
<div id="summary-bar">
  <div class="summary-grid">
    <div class="sum-chip critical"><div class="num" id="sum-critical">0</div><div class="lbl">Critical</div></div>
    <div class="sum-chip high"><div class="num" id="sum-high">0</div><div class="lbl">High</div></div>
    <div class="sum-chip medium"><div class="num" id="sum-medium">0</div><div class="lbl">Medium</div></div>
    <div class="sum-chip low"><div class="num" id="sum-low">0</div><div class="lbl">Low</div></div>
  </div>
</div>

<!-- Empty state -->
<div id="empty-state">
  <div class="big-icon">🔒</div>
  <h3>No scan results yet</h3>
  <p>Click <strong>Scan Project</strong> to run a full<br/>tri-layer security analysis.</p>
</div>

<!-- Loading state -->
<div id="loading-state">
  <div class="spinner"></div>
  <p>Running analysis…</p>
</div>

<!-- Results -->
<div id="results-container">
  <div id="results-list"></div>
</div>

<!-- Single analysis view -->
<div id="single-view">
  <div class="back-btn" onclick="showResultsList()">← Back to results</div>
  <div id="single-content"></div>
</div>

<script>
  const vscode = acquireVsCodeApi();
  let _allResults = [];

  // ── Message handler ──────────────────────────────────────────
  window.addEventListener('message', (event) => {
    const msg = event.data;
    switch (msg.type) {
      case 'scanResults':
        _allResults = msg.results || [];
        renderResults(_allResults, msg.summary, msg.count, msg.llmEnabled);
        break;
      case 'singleAnalysis':
        renderSingleResult(msg.result);
        break;
      case 'clear':
        clearAll();
        break;
    }
  });

  // ── Render full scan results ─────────────────────────────────
  function renderResults(results, summary, count, llmEnabled) {
    hide('empty-state');
    hide('loading-state');
    hide('single-view');
    show('summary-bar');
    show('results-container');

    // Update summary chips
    document.getElementById('sum-critical').textContent = summary?.critical ?? 0;
    document.getElementById('sum-high').textContent = summary?.high ?? 0;
    document.getElementById('sum-medium').textContent = summary?.medium ?? 0;
    document.getElementById('sum-low').textContent = summary?.low ?? 0;

    const list = document.getElementById('results-list');
    list.innerHTML = '';

    if (!results.length) {
      list.innerHTML = '<p style="color:var(--accent2);padding:16px 0;">✅ No vulnerabilities detected!</p>';
      return;
    }

    // Sort by risk score descending
    const sorted = [...results].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));

    sorted.forEach((r, idx) => {
      list.appendChild(buildCard(r, idx));
    });
  }

  // ── Build a finding card ─────────────────────────────────────
  function buildCard(r, idx) {
    const cat = (r.risk_category || 'MEDIUM').toUpperCase();
    const score = (r.risk_score || 0).toFixed(1);
    const fileParts = (r.file_path || 'unknown').split(/[/\\]/);
    const fileName = fileParts[fileParts.length - 1] || 'unknown';
    const cweName = r.vuln_type || r.cwe_id || 'Unknown';
    const hasFP = (r.false_positive_likelihood || 0) > 0.5;
    const hasConflict = r.conflict_detected;

    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = \`
      <div class="card-header" onclick="toggleCard(\${idx})">
        <div class="sev-dot \${cat}"></div>
        <div class="card-main">
          <div class="card-title" title="\${r.file_path}">\${cweName}</div>
          <div class="card-sub">\${fileName}:\${r.line || 0} · \${r.tool || 'unknown'} · \${r.priority || cat}</div>
        </div>
        <div class="card-score \${cat}">\${score}</div>
      </div>
      <div class="card-body" id="card-body-\${idx}">
        <div class="tag-row">
          \${r.cwe_id ? '<span class="tag cwe">' + r.cwe_id + '</span>' : ''}
          \${r.owasp_category && r.owasp_category !== 'Unknown' ? '<span class="tag owasp">' + r.owasp_category + '</span>' : ''}
          \${hasFP ? '<span class="tag fp">⚠ Possible False Positive</span>' : ''}
          \${hasConflict ? '<span class="tag conflict">⚡ Conflict Resolved</span>' : ''}
          \${r.llm_available ? '<span class="tag">🧠 LLM Verified</span>' : '<span class="tag">📊 RAG Only</span>'}
        </div>

        \${r.reasoning ? \`
          <div class="section-label">LLM Reasoning</div>
          <div class="reasoning-box">\${escHtml(r.reasoning)}</div>
        \` : ''}

        \${r.recommended_fix ? \`
          <div class="section-label">Recommended Fix</div>
          <div class="fix-box">\${escHtml(r.recommended_fix)}</div>
        \` : ''}

        \${r.key_risks && r.key_risks.length ? \`
          <div class="section-label">Key Risks</div>
          <ul class="risks-list">
            \${r.key_risks.map(k => '<li>' + escHtml(k) + '</li>').join('')}
          </ul>
        \` : ''}

        <div class="section-label">Score Breakdown</div>
        \${buildScoreBar(r)}

        \${hasConflict ? \`
          <div class="path-trace">Resolution: \${escHtml(r.resolution_path || '')}</div>
        \` : ''}

        \${r.file_path && r.file_path !== 'unknown' ? \`
          <div class="jump-btn" onclick="jumpTo('\${escHtml(r.file_path)}', \${r.line || 0})">
            → Open in Editor (line \${r.line || 0})
          </div>
        \` : ''}
      </div>
    \`;
    return card;
  }

  function buildScoreBar(r) {
    const comp = r.score_components || {};
    const bars = [
      ['Static (50%)', comp.static_contribution, 50],
      ['LLM (20%)', comp.llm_contribution, 20],
      ['RAG (20%)', comp.rag_contribution, 20],
      ['Exploitability (10%)', comp.exploitability_contribution, 10],
    ];
    return '<div class="score-bar-row">' + bars.map(([lbl, val, max]) => {
      const pct = max > 0 ? Math.min(100, ((val || 0) / max) * 100) : 0;
      return \`<div class="score-bar-item">
        <div class="score-bar-label">\${lbl}</div>
        <div class="score-bar-track"><div class="score-bar-fill" style="width:\${pct}%"></div></div>
        <div class="score-bar-val">\${(val || 0).toFixed(1)}</div>
      </div>\`;
    }).join('') + '</div>';
  }

  // ── Render single analysis ───────────────────────────────────
  function renderSingleResult(r) {
    hide('empty-state');
    hide('results-container');
    hide('loading-state');
    hide('summary-bar');
    show('single-view');

    const singleContent = document.getElementById('single-content');
    const tempCard = buildCard(r, 9999);
    // Auto-expand
    const body = tempCard.querySelector('.card-body');
    if (body) { body.classList.add('open'); }
    singleContent.innerHTML = '';
    singleContent.appendChild(tempCard);
  }

  // ── Helpers ──────────────────────────────────────────────────
  function toggleCard(idx) {
    const body = document.getElementById('card-body-' + idx);
    if (body) { body.classList.toggle('open'); }
  }

  function jumpTo(filePath, line) {
    vscode.postMessage({ type: 'jumpToFile', filePath, line });
  }

  function showResultsList() {
    hide('single-view');
    if (_allResults.length) { show('results-container'); show('summary-bar'); }
    else { show('empty-state'); }
  }

  function clearAll() {
    _allResults = [];
    hide('summary-bar');
    hide('results-container');
    hide('single-view');
    show('empty-state');
  }

  function show(id) { document.getElementById(id).style.display = ''; }
  function hide(id) { document.getElementById(id).style.display = 'none'; }

  function escHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
</script>
</body>
</html>`;
    }
}