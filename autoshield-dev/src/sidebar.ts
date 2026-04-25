import * as vscode from 'vscode';

export class AutoShieldSidebarProvider implements vscode.WebviewViewProvider {
  private _view?: vscode.WebviewView;

  constructor(private readonly _extensionUri: vscode.Uri) {}

  resolveWebviewView(webviewView: vscode.WebviewView) {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
    };

    webviewView.webview.html = this._getHtml();

    webviewView.webview.onDidReceiveMessage(async (msg) => {
      console.log("Extension received:", msg);

      switch (msg.type) {
        case 'runScan':
          vscode.commands.executeCommand('autoshield.scan');
          break;
        case 'clearResults':
          vscode.commands.executeCommand('autoshield.clear');
          break;
        case 'jumpToLine':
          vscode.commands.executeCommand('autoshield.jumpToLine', {
            filePath: msg.filePath,
            line: msg.line,
          });
          break;
        case 'generateFix':
          vscode.commands.executeCommand('autoshield.generateFix', {
            codeSnippet: msg.codeSnippet,
            vulnType: msg.vulnType,
            cweId: msg.cweId,
            findingIndex: msg.findingIndex,
          });
          break;
        case 'applyFix':
          vscode.commands.executeCommand('autoshield.applyFix', {
            filePath: msg.filePath,
            line: msg.line,
            originalCode: msg.originalCode,
            fixCode: msg.fixCode,
          });
          break;
      }
    });
  }

  postMessage(msg: any) {
    this._view?.webview.postMessage(msg);
  }

  private _getHtml(): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="UTF-8">
    <style>
      @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans:wght@300;400;500&display=swap');

      :root {
        --bg:         #1a1200;
        --bg2:        #211700;
        --bg3:        #2a1f00;
        --border:     #3a2b00;
        --border2:    #5a4300;
        --amber:      #e8a000;
        --amber-dim:  #9a6a00;
        --amber-lo:   #4a3200;
        --text:       #cc9000;
        --text-dim:   #886000;
        --text-lo:    #4a3500;
        --red:        #cc3333;
        --red-bg:     #280808;
        --orange:     #cc7700;
        --orange-bg:  #221200;
        --yellow:     #b88800;
        --yellow-bg:  #1e1600;
        --green:      #4a8a3a;
        --green-bg:   #0a1608;
        --green-dim:  #203a18;
        --blue:       #3a6a9a;
        --font-mono:  'IBM Plex Mono', 'Cascadia Code', 'Courier New', monospace;
        --font-sans:  'IBM Plex Sans', sans-serif;
      }

      * { box-sizing: border-box; margin: 0; padding: 0; }

      body {
        background: var(--bg);
        color: var(--text);
        font-family: var(--font-mono);
        font-size: 11px;
        line-height: 1.5;
      }

      /* ── Header ─────────────────────────────── */
      .header {
        padding: 9px 12px 7px;
        border-bottom: 1px solid var(--border);
        display: flex;
        align-items: baseline;
        justify-content: space-between;
      }

      .logo {
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.18em;
        color: var(--amber);
        text-transform: uppercase;
      }

      .logo-dim { color: var(--amber-dim); font-weight: 300; }

      .version {
        font-size: 9px;
        color: var(--text-lo);
        letter-spacing: 0.05em;
      }

      /* ── Toolbar ─────────────────────────────── */
      .toolbar {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 1px;
        background: var(--border);
        border-bottom: 1px solid var(--border);
      }

      .tbtn {
        background: var(--bg2);
        color: var(--text-dim);
        border: none;
        padding: 6px 0;
        cursor: pointer;
        font-family: var(--font-mono);
        font-size: 9px;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        font-weight: 500;
        transition: background 0.1s, color 0.1s;
      }

      .tbtn:hover          { background: var(--bg3); color: var(--amber); }
      .tbtn.primary        { color: var(--amber); }
      .tbtn.primary:hover  { background: var(--amber-lo); }

      /* ── Status ──────────────────────────────── */
      .statusbar {
        padding: 4px 12px;
        font-size: 9px;
        color: var(--text-lo);
        letter-spacing: 0.06em;
        border-bottom: 1px solid var(--border);
        min-height: 21px;
        display: flex;
        align-items: center;
        gap: 7px;
      }

      .statusbar.scanning { color: var(--amber-dim); }
      .statusbar.done     { color: var(--text-dim); }
      .statusbar.error    { color: var(--red); }

      .dot {
        width: 5px; height: 5px;
        border-radius: 50%;
        background: var(--amber);
        flex-shrink: 0;
        animation: blink 1s ease-in-out infinite;
      }

      @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.15} }

      /* ── Summary ─────────────────────────────── */
      .summary {
        display: none;
        gap: 1px;
        background: var(--border);
        border-bottom: 1px solid var(--border);
      }

      .summary.visible { display: flex; }

      .sum-cell {
        flex: 1;
        background: var(--bg2);
        padding: 5px 3px;
        text-align: center;
      }

      .sum-n    { font-size: 13px; font-weight: 600; display: block; line-height: 1; }
      .sum-l    { font-size: 8px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-lo); margin-top: 2px; display: block; }

      .n-crit   { color: #cc3333; }
      .n-high   { color: #cc7700; }
      .n-med    { color: var(--yellow); }
      .n-low    { color: var(--green); }

      /* ── Empty state ─────────────────────────── */
      .empty {
        padding: 32px 12px;
        text-align: center;
        color: var(--text-lo);
        font-size: 9px;
        letter-spacing: 0.08em;
        line-height: 2;
      }

      /* ── Card ────────────────────────────────── */
      .card { border-bottom: 1px solid var(--border); }

      .card-head {
        padding: 7px 10px 7px 12px;
        display: grid;
        grid-template-columns: auto 1fr auto;
        gap: 8px;
        align-items: start;
        cursor: pointer;
        user-select: none;
        transition: background 0.08s;
      }

      .card-head:hover { background: var(--bg2); }

      .sev-tag {
        font-size: 7px;
        font-weight: 600;
        letter-spacing: 0.1em;
        padding: 2px 4px;
        border: 1px solid;
        text-transform: uppercase;
        margin-top: 1px;
        flex-shrink: 0;
      }

      .sev-CRITICAL { color:#cc3333; border-color:#cc3333; background:#280808; }
      .sev-HIGH     { color:#cc7700; border-color:#cc7700; background:#221200; }
      .sev-MEDIUM   { color:#b88800; border-color:#b88800; background:#1e1600; }
      .sev-LOW      { color:#4a8a3a; border-color:#4a8a3a; background:#0a1608; }
      .sev-INFO     { color:#3a6a9a; border-color:#3a6a9a; background:#080e18; }

      .card-title {
        font-size: 10px;
        font-weight: 500;
        color: var(--text);
        line-height: 1.4;
      }

      .card-meta {
        font-size: 9px;
        color: var(--text-lo);
        margin-top: 2px;
      }

      .file-link {
        color: var(--amber-dim);
        cursor: pointer;
        text-decoration: none;
      }

      .file-link:hover { color: var(--amber); text-decoration: underline; }

      .score-row {
        display: flex;
        align-items: center;
        gap: 5px;
        margin-top: 4px;
      }

      .score-track {
        flex: 1;
        height: 2px;
        background: var(--border);
      }

      .score-fill { height: 100%; }

      .score-num {
        font-size: 8px;
        color: var(--text-lo);
        flex-shrink: 0;
        width: 30px;
        text-align: right;
      }

      .chevron {
        font-size: 8px;
        color: var(--text-lo);
        transition: transform 0.15s;
        padding-top: 2px;
        font-family: var(--font-mono);
      }

      .chevron.open { transform: rotate(90deg); }

      /* ── Card body ───────────────────────────── */
      .card-body {
        display: none;
        background: var(--bg2);
        border-top: 1px solid var(--border);
      }

      .card-body.open { display: block; }

      .body-sec {
        padding: 7px 12px;
        border-bottom: 1px solid var(--border);
      }

      .body-sec:last-child { border-bottom: none; }

      .sec-label {
        font-size: 8px;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: var(--amber-dim);
        font-weight: 600;
        margin-bottom: 4px;
      }

      .body-text {
        font-size: 10px;
        color: var(--text-dim);
        line-height: 1.55;
        font-family: var(--font-sans);
      }

      .risks { list-style: none; }

      .risks li {
        font-size: 10px;
        color: var(--text-dim);
        padding: 1px 0 1px 12px;
        position: relative;
        font-family: var(--font-sans);
      }

      .risks li::before {
        content: '>';
        position: absolute;
        left: 0;
        color: var(--amber-dim);
        font-family: var(--font-mono);
      }

      /* ── Action row ──────────────────────────── */
      .act-row {
        display: flex;
        gap: 1px;
        background: var(--border);
      }

      .abtn {
        flex: 1;
        background: var(--bg2);
        color: var(--text-dim);
        border: none;
        padding: 6px 2px;
        cursor: pointer;
        font-family: var(--font-mono);
        font-size: 8px;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        font-weight: 500;
        transition: background 0.08s, color 0.08s;
      }

      .abtn:disabled          { opacity: 0.3; cursor: not-allowed; }
      .abtn:hover             { background: var(--bg3); color: var(--amber); }
      .abtn.goto              { color: var(--amber-dim); }
      .abtn.goto:hover        { background: var(--amber-lo); color: var(--amber); }
      .abtn.fix               { color: var(--green); }
      .abtn.fix:hover         { background: var(--green-dim); color: #7acc6a; }
      .abtn.apply             { color: var(--yellow); }
      .abtn.apply:hover       { background: var(--yellow-bg); color: var(--amber); }

      /* ── Fix block ───────────────────────────── */
      .fix-wrap { border-top: 1px solid var(--green-dim); }

      .fix-head {
        padding: 4px 12px;
        font-size: 8px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: #5aaa4a;
        background: var(--green-dim);
        display: flex;
        justify-content: space-between;
        align-items: center;
      }

      .fix-code {
        padding: 8px 12px;
        font-family: var(--font-mono);
        font-size: 9.5px;
        color: #a8cc98;
        white-space: pre-wrap;
        word-break: break-all;
        max-height: 150px;
        overflow-y: auto;
        background: #080e06;
        line-height: 1.5;
      }

      .fix-desc {
        padding: 5px 12px;
        font-size: 10px;
        color: var(--text-lo);
        font-family: var(--font-sans);
        border-top: 1px solid var(--border);
        line-height: 1.5;
      }

      /* ── Spinner ─────────────────────────────── */
      .spin {
        display: inline-block;
        width: 7px; height: 7px;
        border: 1px solid var(--border2);
        border-top-color: var(--amber);
        border-radius: 50%;
        animation: rot 0.6s linear infinite;
        vertical-align: middle;
        margin-right: 3px;
      }

      @keyframes rot { to { transform: rotate(360deg); } }

      ::-webkit-scrollbar       { width: 3px; }
      ::-webkit-scrollbar-track { background: var(--bg); }
      ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }
    </style>
    </head>
    <body>

      <div class="header">
        <div class="logo">Auto<span class="logo-dim">Shield</span></div>
        <div class="version">v1.0.0</div>
      </div>

      <div class="toolbar">
        <button class="tbtn primary" onclick="runScan()">[S]  Scan</button>
        <button class="tbtn" onclick="clearUI()">[C]  Clear</button>
      </div>

      <div id="sb" class="statusbar">Ready</div>

      <div id="summary" class="summary">
        <div class="sum-cell"><span class="sum-n n-crit" id="s-crit">0</span><span class="sum-l">Crit</span></div>
        <div class="sum-cell"><span class="sum-n n-high" id="s-high">0</span><span class="sum-l">High</span></div>
        <div class="sum-cell"><span class="sum-n n-med"  id="s-med">0</span><span class="sum-l">Med</span></div>
        <div class="sum-cell"><span class="sum-n n-low"  id="s-low">0</span><span class="sum-l">Low</span></div>
      </div>

      <div id="out"></div>

      <script>
        const vscode = acquireVsCodeApi();
        let currentResults = [];

        function runScan() {
          setStatus('Scanning workspace...', 'scanning', true);
          vscode.postMessage({ type: 'runScan' });
        }

        function clearUI() {
          document.getElementById('out').innerHTML = '';
          document.getElementById('summary').classList.remove('visible');
          setStatus('Ready', '');
          currentResults = [];
        }

        function setStatus(text, cls, pulse) {
          const el = document.getElementById('sb');
          el.className = 'statusbar' + (cls ? ' ' + cls : '');
          el.innerHTML = (pulse ? '<span class="dot"></span>' : '') + text;
        }

        function jumpToLine(fp, line) {
          vscode.postMessage({ type: 'jumpToLine', filePath: fp, line });
        }

        function generateFix(i) {
          const r = currentResults[i];
          if (!r) return;
          vscode.postMessage({
            type: 'generateFix',
            findingIndex: i,
            codeSnippet: r.code_snippet || r.message || '',
            vulnType: r.vuln_type || '',
            cweId: r.cwe_id || 'CWE-Unknown',
          });
        }

        function applyFix(i) {
          const r = currentResults[i];
          if (!r || !r._fixCode) return;
          vscode.postMessage({
            type: 'applyFix',
            filePath: r.file_path,
            line: r.line,
            originalCode: r.code_snippet || '',
            fixCode: r._fixCode,
          });
        }

        function toggle(i) {
          const body = document.getElementById('b-' + i);
          const chev = document.getElementById('c-' + i);
          if (!body) return;
          const open = body.classList.toggle('open');
          chev.classList.toggle('open', open);
        }

        function scoreColor(s) {
          if (s >= 85) return '#cc3333';
          if (s >= 65) return '#cc7700';
          if (s >= 40) return '#b88800';
          return '#4a8a3a';
        }

        function esc(s) {
          return String(s)
            .replace(/&/g,'&amp;')
            .replace(/</g,'&lt;')
            .replace(/>/g,'&gt;');
        }

        function fixBlock(i, code, desc) {
          if (!code && !desc) return '';
          return \`<div class="fix-wrap" id="fix-wrap-\${i}">
            <div class="fix-head">
              Fix ready
              \${code ? \`<button class="abtn apply" style="flex:none;padding:2px 8px" onclick="applyFix(\${i})">Apply</button>\` : ''}
            </div>
            \${code ? \`<div class="fix-code">\${esc(code)}</div>\` : ''}
            \${desc  ? \`<div class="fix-desc">\${esc(desc)}</div>\` : ''}
          </div>\`;
        }

        function updateSummary(results) {
          const c = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
          results.forEach(r => {
            const k = (r.risk_category||'MEDIUM').toUpperCase();
            if (c[k] !== undefined) c[k]++;
          });
          document.getElementById('s-crit').innerText = c.CRITICAL;
          document.getElementById('s-high').innerText = c.HIGH;
          document.getElementById('s-med').innerText  = c.MEDIUM;
          document.getElementById('s-low').innerText  = c.LOW;
          document.getElementById('summary').classList.add('visible');
        }

        function render(results) {
          const out = document.getElementById('out');
          out.innerHTML = '';

          if (!results || results.length === 0) {
            out.innerHTML = '<div class="empty">// No issues detected</div>';
            return;
          }

          updateSummary(results);

          results.forEach((r, i) => {
            const cat   = (r.risk_category || 'MEDIUM').toUpperCase();
            const score = r.risk_score || 0;
            const fp    = r.file_path || 'unknown';
            const fn    = fp.split(/[\\/]/).pop();
            const cwe   = r.cwe_id ? ' [' + r.cwe_id + ']' : '';
            const hasF  = !!(r.fix_code || r.recommended_fix);
            const risks = r.key_risks || [];
            const rsn   = r.reasoning || '';

            const card = document.createElement('div');
            card.className = 'card';
            card.innerHTML = \`
              <div class="card-head" onclick="toggle(\${i})">
                <span class="sev-tag sev-\${cat}">\${cat}</span>
                <div>
                  <div class="card-title">\${esc(r.vuln_type || r.cwe_id || 'Unknown Issue')}\${cwe}</div>
                  <div class="card-meta">
                    <span class="file-link" onclick="event.stopPropagation();jumpToLine('\${fp}',\${r.line||1})">\${fn}</span>
                    &nbsp;:&nbsp;\${r.line||0}&nbsp;&nbsp;\${r.tool ? '[ '+r.tool+' ]' : ''}
                  </div>
                  <div class="score-row">
                    <div class="score-track">
                      <div class="score-fill" style="width:\${score}%;background:\${scoreColor(score)}"></div>
                    </div>
                    <span class="score-num">\${score}/100</span>
                  </div>
                </div>
                <span class="chevron" id="c-\${i}">&gt;</span>
              </div>

              <div class="card-body" id="b-\${i}">
                \${rsn ? \`<div class="body-sec"><div class="sec-label">LLM Reasoning</div><div class="body-text">\${esc(rsn)}</div></div>\` : ''}
                \${risks.length ? \`<div class="body-sec"><div class="sec-label">Key Risks</div><ul class="risks">\${risks.map(k=>\`<li>\${esc(k)}</li>\`).join('')}</ul></div>\` : ''}
                <div class="act-row">
                  <button class="abtn goto" onclick="jumpToLine('\${fp}',\${r.line||1})">Go to line \${r.line||1}</button>
                  <button class="abtn fix" id="fb-\${i}" onclick="generateFix(\${i})">Get Fix</button>
                </div>
                \${hasF ? fixBlock(i, r.fix_code||'', r.recommended_fix||'') : ''}
                <div id="fa-\${i}"></div>
              </div>
            \`;
            out.appendChild(card);
          });
        }

        window.addEventListener('message', ev => {
          const msg = ev.data;

          if (msg.type === 'scanStarted') {
            setStatus('Scanning workspace...', 'scanning', true);
            document.getElementById('out').innerHTML = '';
            document.getElementById('summary').classList.remove('visible');
            currentResults = [];
          }

          if (msg.type === 'scanResults') {
            currentResults = msg.results || [];
            const n = msg.count || 0;
            setStatus('Scan complete  —  ' + n + ' finding' + (n!==1?'s':''), 'done');
            render(currentResults);
          }

          if (msg.type === 'clear') { clearUI(); }

          if (msg.type === 'scanError') {
            setStatus('Error: ' + msg.error, 'error');
          }

          if (msg.type === 'fixGenerating') {
            const btn = document.getElementById('fb-' + msg.findingIndex);
            if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spin"></span>Generating'; }
          }

          if (msg.type === 'fixGenerated') {
            const i = msg.findingIndex;
            const d = msg.fixData || {};
            const btn = document.getElementById('fb-' + i);
            if (btn) { btn.disabled = false; btn.innerText = 'Regenerate'; }
            if (currentResults[i]) currentResults[i]._fixCode = d.fix_code || '';
            const area = document.getElementById('fa-' + i);
            if (area) area.innerHTML = fixBlock(i, d.fix_code||'', d.explanation||'');
            const body = document.getElementById('b-' + i);
            const chev = document.getElementById('c-' + i);
            if (body && !body.classList.contains('open')) {
              body.classList.add('open');
              if (chev) chev.classList.add('open');
            }
          }

          if (msg.type === 'fixError') {
            const i = msg.findingIndex;
            const btn = document.getElementById('fb-' + i);
            if (btn) { btn.disabled = false; btn.innerText = 'Retry'; }
            const area = document.getElementById('fa-' + i);
            if (area) area.innerHTML = '<div style="padding:5px 12px;font-size:9px;color:#cc3333;letter-spacing:0.04em">Error: ' + esc(msg.error) + '</div>';
          }
        });
      </script>
    </body>
    </html>
    `;
  }
}