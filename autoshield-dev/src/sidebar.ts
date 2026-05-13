import * as vscode from 'vscode';

export class AutoShieldSidebarProvider implements vscode.WebviewViewProvider {
  private _view?: vscode.WebviewView;
  private lastReport: any = null;

  constructor(private readonly _extensionUri: vscode.Uri) {}

  resolveWebviewView(webviewView: vscode.WebviewView) {
    this._view = webviewView;
    webviewView.webview.options = { enableScripts: true };
    webviewView.webview.html = this.getHtml();

    webviewView.webview.onDidReceiveMessage(async (msg) => {
      if (msg.command === 'exportReport' || msg.type === 'exportReport') {
        await this.exportReport(msg.format === 'html' ? 'html' : 'json');
        return;
      }

      switch (msg.type) {
        case 'runScan':
          vscode.commands.executeCommand('autoshield.scan');
          break;
        case 'runMediaCompliance':
          vscode.commands.executeCommand('autoshield.mediaComplianceScan');
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
      }
    });
  }

  postMessage(msg: any) {
    if (msg?.type === 'scanResults' && msg.report) {
      this.lastReport = msg.report;
    }
    this._view?.webview.postMessage(msg);
  }

  private async exportReport(format: 'json' | 'html') {
    if (!this.lastReport) {
      vscode.window.showErrorMessage('No AutoShield report available to export.');
      return;
    }

    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    const defaultUri = workspaceFolder
      ? vscode.Uri.joinPath(workspaceFolder.uri, `autoshield-report.${format}`)
      : vscode.Uri.file(`C:\\tmp\\autoshield-report.${format}`);

    const uri = await vscode.window.showSaveDialog({
      defaultUri,
      filters: format === 'json'
        ? { JSON: ['json'] }
        : { HTML: ['html'] },
    });

    if (!uri) {
      return;
    }

    let content = '';

    if (format === 'json') {
      content = JSON.stringify(this.lastReport, null, 2);
    } else {
      const response = await fetch('http://127.0.0.1:8000/api/report/export', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          format: 'html',
          report: this.lastReport,
        }),
      });

      if (!response.ok) {
        vscode.window.showErrorMessage('Failed to export HTML report.');
        return;
      }

      content = await response.text();
    }

    await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
    vscode.window.showInformationMessage(`AutoShield ${format.toUpperCase()} report exported.`);
  }

  private getHtml(): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        :root {
          --bg: #17130a;
          --panel: #211b0f;
          --panel2: #2b2313;
          --border: #43351b;
          --text: #f0c36a;
          --muted: #a88646;
          --low: #65a765;
          --medium: #d6a83d;
          --high: #e06f38;
          --critical: #e05353;
          --info: #6ea6d7;
        }

        * { box-sizing: border-box; }
        body {
          margin: 0;
          background: var(--bg);
          color: var(--text);
          font-family: Consolas, "Courier New", monospace;
          font-size: 12px;
        }

        .header {
          display: flex;
          justify-content: space-between;
          align-items: baseline;
          padding: 10px 12px;
          border-bottom: 1px solid var(--border);
        }

        .brand { font-size: 12px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; }
        .version { color: var(--muted); font-size: 10px; }

        .tabs {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 1px;
          background: var(--border);
          border-bottom: 1px solid var(--border);
        }

        .tab-btn {
          border-bottom: 2px solid transparent;
          text-transform: uppercase;
          letter-spacing: 0.08em;
          font-size: 10px;
        }

        .tab-btn.active {
          background: var(--panel2);
          border-bottom-color: var(--text);
        }

        .toolbar {
          display: none;
          grid-template-columns: 1fr;
          gap: 1px;
          background: var(--border);
          border-bottom: 1px solid var(--border);
        }

        .toolbar.active {
          display: grid;
        }

        .utility-toolbar {
          display: grid;
          grid-template-columns: 1fr;
          gap: 1px;
          background: var(--border);
          border-bottom: 1px solid var(--border);
        }

        button {
          border: 0;
          background: var(--panel);
          color: var(--text);
          padding: 8px;
          cursor: pointer;
          font: inherit;
        }

        button:hover { background: var(--panel2); }
        button:disabled { opacity: 0.45; cursor: not-allowed; }

        .status {
          min-height: 28px;
          padding: 7px 12px;
          color: var(--muted);
          border-bottom: 1px solid var(--border);
        }

        .summary {
          display: none;
          grid-template-columns: repeat(3, 1fr);
          gap: 1px;
          background: var(--border);
          border-bottom: 1px solid var(--border);
        }

        .summary.visible { display: grid; }
        .sum { background: var(--panel); padding: 8px 4px; text-align: center; }
        .sum strong { display: block; font-size: 16px; }
        .sum span { color: var(--muted); font-size: 9px; text-transform: uppercase; }
        .high { color: var(--high); }
        .medium { color: var(--medium); }
        .low { color: var(--low); }

        .empty { padding: 32px 12px; color: var(--muted); text-align: center; }
        .card { border-bottom: 1px solid var(--border); background: var(--panel); }
        .head {
          display: grid;
          grid-template-columns: auto 1fr auto;
          gap: 8px;
          padding: 10px 12px;
          cursor: pointer;
        }

        .sev {
          border: 1px solid currentColor;
          padding: 2px 5px;
          font-size: 9px;
          height: fit-content;
        }

        .sev-CRITICAL, .sev-ERROR { color: var(--critical); }
        .sev-HIGH { color: var(--high); }
        .sev-WARNING, .sev-MEDIUM { color: var(--medium); }
        .sev-LOW { color: var(--low); }
        .sev-INFO { color: var(--info); }

        .title { font-weight: 700; line-height: 1.35; }
        .meta { color: var(--muted); font-size: 10px; margin-top: 3px; }
        .file { color: var(--text); text-decoration: underline; cursor: pointer; }
        .chev { color: var(--muted); }
        .body { display: none; background: var(--panel2); border-top: 1px solid var(--border); }
        .body.open { display: block; }
        .section { padding: 8px 12px; border-bottom: 1px solid var(--border); }
        .label { color: var(--muted); font-size: 9px; text-transform: uppercase; margin-bottom: 4px; }
        .text { color: #d6b979; white-space: pre-wrap; line-height: 1.5; }
        .kv { display: grid; grid-template-columns: 72px 1fr; gap: 4px 8px; color: #d6b979; }
        .kv span:nth-child(odd) { color: var(--muted); }
        .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 1px; background: var(--border); }
        .export-actions {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 1px;
          background: var(--border);
          border-bottom: 1px solid var(--border);
        }
        .export-actions button {
          background: var(--panel);
          color: var(--text);
          border: 0;
          padding: 8px;
          cursor: pointer;
          font: inherit;
        }
        .export-actions button:hover { background: var(--panel2); }
        .summary-card {
          background: var(--panel);
          border-bottom: 1px solid var(--border);
          padding: 12px;
        }
        .summary-title {
          color: var(--text);
          font-weight: 700;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          margin-bottom: 10px;
        }
        .risk-score {
          display: grid;
          grid-template-columns: 1fr auto;
          align-items: center;
          gap: 10px;
          margin-bottom: 10px;
        }
        .score {
          font-size: 24px;
          font-weight: 700;
          color: var(--text);
        }
        .level {
          border: 1px solid currentColor;
          padding: 4px 7px;
          font-size: 9px;
          font-weight: 700;
        }
        .level.low { color: var(--low); }
        .level.medium { color: var(--medium); }
        .level.high { color: var(--high); }
        .level.critical { color: var(--critical); }
        .summary-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 1px;
          background: var(--border);
          margin: 10px 0;
        }
        .summary-grid div {
          background: var(--panel2);
          padding: 8px 4px;
          text-align: center;
        }
        .summary-grid strong {
          display: block;
          color: var(--muted);
          font-size: 9px;
          text-transform: uppercase;
          margin-bottom: 4px;
        }
        .summary-section { margin-top: 10px; }
        .summary-section h3 {
          color: var(--muted);
          font-size: 9px;
          text-transform: uppercase;
          letter-spacing: 0.08em;
          margin: 0 0 5px;
        }
        .summary-list {
          list-style: none;
          margin: 0;
          padding: 0;
          color: #d6b979;
        }
        .summary-list li {
          border-top: 1px solid var(--border);
          padding: 5px 0;
          line-height: 1.45;
        }
        .summary-muted { color: var(--muted); }
      </style>
    </head>
    <body>
      <div class="header">
        <div class="brand">AutoShield</div>
        <div class="version">LangGraph</div>
      </div>
      <div class="tabs">
        <button id="securityTab" class="tab-btn active" onclick="switchTab('security')">Security</button>
        <button id="complianceTab" class="tab-btn" onclick="switchTab('compliance')">Compliance</button>
      </div>
      <div id="securityToolbar" class="toolbar active">
        <button onclick="runScan()">Scan Project</button>
      </div>
      <div id="complianceToolbar" class="toolbar">
        <button onclick="runMediaCompliance()">Media Compliance</button>
      </div>
      <div class="utility-toolbar">
        <button onclick="clearUI()">Clear</button>
      </div>
      <div id="status" class="status">Ready</div>
      <div id="summary" class="summary">
        <div class="sum"><strong id="s-high" class="high">0</strong><span>High</span></div>
        <div class="sum"><strong id="s-medium" class="medium">0</strong><span>Medium</span></div>
        <div class="sum"><strong id="s-low" class="low">0</strong><span>Low</span></div>
      </div>
      <div class="export-actions">
        <button id="exportJson">Export JSON</button>
        <button id="exportHtml">Export HTML</button>
      </div>
      <div id="out" class="empty">Open a folder and run Scan Project.</div>

      <script>
        const vscode = acquireVsCodeApi();
        let currentResults = [];
        let activeTab = 'security';
        const tabReports = {
          security: null,
          compliance: null,
        };

        function switchTab(tab) {
          activeTab = tab;
          document.getElementById('securityTab')?.classList.toggle('active', tab === 'security');
          document.getElementById('complianceTab')?.classList.toggle('active', tab === 'compliance');
          document.getElementById('securityToolbar')?.classList.toggle('active', tab === 'security');
          document.getElementById('complianceToolbar')?.classList.toggle('active', tab === 'compliance');

          const stored = tabReports[tab];
          if (stored) {
            currentResults = stored.results || [];
            render(currentResults, stored.summary || {}, stored.report || {});
            return;
          }

          currentResults = [];
          document.getElementById('summary').classList.remove('visible');
          const text = tab === 'security'
            ? 'Open a folder and run Scan Project.'
            : 'Open a folder and run Media Compliance.';
          const out = document.getElementById('out');
          out.className = 'empty';
          out.innerHTML = text;
        }

        function runScan() {
          switchTab('security');
          setStatus('Scanning workspace...');
          vscode.postMessage({ type: 'runScan' });
        }

        function runMediaCompliance() {
          switchTab('compliance');
          setStatus('Scanning media compliance...');
          vscode.postMessage({ type: 'runMediaCompliance' });
        }

        function clearUI() {
          currentResults = [];
          tabReports.security = null;
          tabReports.compliance = null;
          document.getElementById('out').className = 'empty';
          document.getElementById('out').innerHTML = activeTab === 'security'
            ? 'Open a folder and run Scan Project.'
            : 'Open a folder and run Media Compliance.';
          document.getElementById('summary').classList.remove('visible');
          setStatus('Ready');
          vscode.postMessage({ type: 'clearResults' });
        }

        function exportReport(format) {
          vscode.postMessage({
            command: 'exportReport',
            format,
          });
        }

        function setStatus(text) {
          document.getElementById('status').textContent = text;
        }

        function esc(value) {
          return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
        }

        function severityClass(value) {
          return String(value || 'INFO').toUpperCase().replace(/[^A-Z]/g, '');
        }

        function confidence(result) {
          return result.validation && result.validation.confidence
            ? result.validation.confidence
            : 'UNKNOWN';
        }

        function updateSummary(results, summary) {
          const counts = {
            high: summary?.high ?? 0,
            medium: summary?.medium ?? 0,
            low: summary?.low ?? 0,
          };

          if (!summary || Object.keys(summary).length === 0) {
            results.forEach((result) => {
              const c = String(confidence(result)).toLowerCase();
              if (counts[c] !== undefined) counts[c]++;
            });
          }

          document.getElementById('s-high').textContent = counts.high;
          document.getElementById('s-medium').textContent = counts.medium;
          document.getElementById('s-low').textContent = counts.low;
          document.getElementById('summary').classList.add('visible');
        }

        function riskLevelClass(level) {
          return String(level || 'unknown').toLowerCase().replace(/[^a-z]/g, '');
        }

        function renderObjectList(values, emptyText) {
          const entries = Object.entries(values || {});
          if (!entries.length) return '<li class="summary-muted">' + esc(emptyText || 'No data') + '</li>';
          return entries.map(([name, count]) => '<li>' + esc(name) + ': ' + esc(count) + '</li>').join('');
        }

        function renderTopIssues(issues) {
          if (!issues || issues.length === 0) return '<li class="summary-muted">No top issues reported</li>';
          return issues.map((issue, index) => {
            const location = issue.file ? ' - ' + esc(issue.file) + ':' + esc(issue.line || 1) : '';
            return '<li>' + esc(index + 1) + '. <strong>' + esc(issue.category || 'Security Issue') + '</strong> - ' +
              esc(issue.severity || '') + location + '</li>';
          }).join('');
        }

        function renderRemediationPlan(plan) {
          if (!plan || plan.length === 0) return '<li class="summary-muted">No remediation plan available</li>';
          return plan.map((item) => '<li><strong>' + esc(item.priority || '') + '</strong> - ' +
            esc(item.category || 'Security Issue') + '<br><span class="summary-muted">' +
            esc(item.action || '') + '</span></li>').join('');
        }

        function renderExecutiveSummary(report, results, summary) {
          const confidence = report?.confidence_summary || summary || {};
          const grouped = report?.grouped_summary || {};
          const bySource = grouped.by_source || {};
          const byCategory = grouped.by_category || {};
          const score = report?.overall_risk_score ?? 'N/A';
          const level = report?.overall_risk_level || 'UNKNOWN';
          const total = report?.total_findings ?? (results ? results.length : 0);

          return '<section class="summary-card">' +
            '<div class="summary-title">AutoShield Risk Summary</div>' +
            '<div class="risk-score"><div class="score">' + esc(score) + '/100</div>' +
            '<div class="level ' + esc(riskLevelClass(level)) + '">' + esc(level) + '</div></div>' +
            '<div class="summary-grid">' +
              '<div><strong>Total</strong>' + esc(total) + '</div>' +
              '<div><strong>High</strong>' + esc(confidence.high || 0) + '</div>' +
              '<div><strong>Medium</strong>' + esc(confidence.medium || 0) + '</div>' +
              '<div><strong>Low</strong>' + esc(confidence.low || 0) + '</div>' +
            '</div>' +
            '<div class="summary-section"><h3>Findings by Source</h3><ul class="summary-list">' +
              renderObjectList(bySource, 'No source grouping') + '</ul></div>' +
            '<div class="summary-section"><h3>Findings by Category</h3><ul class="summary-list">' +
              renderObjectList(byCategory, 'No category grouping') + '</ul></div>' +
            '<div class="summary-section"><h3>Top Issues</h3><ul class="summary-list">' +
              renderTopIssues(report?.top_issues || []) + '</ul></div>' +
            '<div class="summary-section"><h3>Remediation Plan</h3><ul class="summary-list">' +
              renderRemediationPlan(report?.remediation_plan || []) + '</ul></div>' +
          '</section>';
        }

        function toggle(index) {
          const body = document.getElementById('body-' + index);
          if (body) body.classList.toggle('open');
        }

        function jumpToLine(filePath, line) {
          vscode.postMessage({ type: 'jumpToLine', filePath, line });
        }

        function render(results, summary, report) {
          const out = document.getElementById('out');
          out.className = '';
          out.innerHTML = '';

          if (!results || results.length === 0) {
            out.className = 'empty';
            out.innerHTML = 'No issues detected.';
            document.getElementById('summary').classList.remove('visible');
            return;
          }

          updateSummary(results, summary);
          out.innerHTML = renderExecutiveSummary(report || {}, results, summary || {});

          results.forEach((result, index) => {
            const filePath = result.file_path || result.file || 'unknown';
            const fileName = filePath.split(/[\\\\/]/).pop();
            const line = result.line || 1;
            const severity = String(result.severity || 'INFO').toUpperCase();
            const category = result.category || 'Security Issue';
            const cwe = result.cwe || result.cwe_id || 'CWE-Unknown';
            const owasp = result.owasp || 'OWASP-Unknown';
            const explanation = result.explanation || result.message || '';
            const code = result.code_snippet || '';

            const card = document.createElement('div');
            card.className = 'card';
            card.innerHTML = \`
              <div class="head" onclick="toggle(\${index})">
                <div class="sev sev-\${severityClass(severity)}">\${esc(severity)}</div>
                <div>
                  <div class="title">\${esc(category)}</div>
                  <div class="meta">
                    <span class="file" onclick="event.stopPropagation(); jumpToLine('\${esc(filePath)}', \${line})">\${esc(fileName)}</span>:\${line}
                    &nbsp; \${esc(cwe)}
                    &nbsp; \${esc(confidence(result))}
                  </div>
                </div>
                <div class="chev">&gt;</div>
              </div>
              <div class="body" id="body-\${index}">
                <div class="section">
                  <div class="label">Details</div>
                  <div class="kv">
                    <span>Severity</span><span>\${esc(severity)}</span>
                    <span>Confidence</span><span>\${esc(confidence(result))}</span>
                    <span>CWE</span><span>\${esc(cwe)}</span>
                    <span>OWASP</span><span>\${esc(owasp)}</span>
                    <span>Tool</span><span>\${esc(result.tool || 'unknown')}</span>
                    <span>Location</span><span>\${esc(filePath)}:\${line}</span>
                  </div>
                </div>
                \${code ? \`<div class="section"><div class="label">Evidence</div><div class="text">\${esc(code)}</div></div>\` : ''}
                \${explanation ? \`<div class="section"><div class="label">Explanation</div><div class="text">\${esc(explanation)}</div></div>\` : ''}
                <div class="actions">
                  <button onclick="jumpToLine('\${esc(filePath)}', \${line})">Go to Line</button>
                  <button disabled>Get Fix / Apply Fix coming soon</button>
                </div>
              </div>
            \`;

            out.appendChild(card);
          });
        }

        window.addEventListener('message', (event) => {
          const msg = event.data;

          if (msg.type === 'scanStarted') {
            switchTab('security');
            currentResults = [];
            tabReports.security = null;
            document.getElementById('out').className = 'empty';
            document.getElementById('out').innerHTML = 'Scanning...';
            document.getElementById('summary').classList.remove('visible');
            setStatus('Scanning workspace...');
          }

          if (msg.type === 'mediaComplianceStarted') {
            switchTab('compliance');
            currentResults = [];
            tabReports.compliance = null;
            document.getElementById('out').className = 'empty';
            document.getElementById('out').innerHTML = 'Scanning media compliance...';
            document.getElementById('summary').classList.remove('visible');
            setStatus('Scanning media compliance...');
          }

          if (msg.type === 'scanResults') {
            currentResults = msg.results || [];
            tabReports[activeTab] = {
              results: currentResults,
              summary: msg.summary || {},
              report: msg.report || {},
            };
            setStatus('Scan complete - ' + currentResults.length + ' finding' + (currentResults.length === 1 ? '' : 's'));
            render(currentResults, msg.summary || {}, msg.report || {});
          }

          if (msg.type === 'scanError') {
            setStatus('Error: ' + msg.error);
          }

          if (msg.type === 'clear') {
            currentResults = [];
            tabReports.security = null;
            tabReports.compliance = null;
            document.getElementById('out').className = 'empty';
            document.getElementById('out').innerHTML = activeTab === 'security'
              ? 'Open a folder and run Scan Project.'
              : 'Open a folder and run Media Compliance.';
            document.getElementById('summary').classList.remove('visible');
            setStatus('Ready');
          }
        });

        document.getElementById('exportJson')?.addEventListener('click', () => exportReport('json'));
        document.getElementById('exportHtml')?.addEventListener('click', () => exportReport('html'));
      </script>
    </body>
    </html>
    `;
  }
}
