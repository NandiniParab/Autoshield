import * as vscode from 'vscode';
import axios from 'axios';
import { AutoShieldSidebarProvider } from './sidebar.js';

const BACKEND = 'http://127.0.0.1:8000';

export function activate(context: vscode.ExtensionContext) {
    // ── Diagnostic collection for inline squiggles ─────────────────
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('autoshield');

    // ── Register sidebar webview ───────────────────────────────────
    const sidebarProvider = new AutoShieldSidebarProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('autoshield.view', sidebarProvider)
    );

    // ── Command: Full Tri-Layer Scan ───────────────────────────────
    const scanCommand = vscode.commands.registerCommand('autoshield.scan', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showErrorMessage('AutoShield: Open a project folder first.');
            return;
        }

        const projectPath = workspaceFolders[0].uri.fsPath;

        // Ask user whether to use LLM
        const useLLM = await vscode.window.showQuickPick(
            [
                { label: '🧠 Full Analysis (Static + RAG + LLM)', value: true },
                { label: '⚡ Fast Scan (Static + RAG only)', value: false },
            ],
            { placeHolder: 'Choose analysis depth' }
        );

        if (!useLLM) { return; }

        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: 'AutoShield',
                cancellable: false,
            },
            async (progress) => {
                progress.report({ message: '🔍 Running static analysis…' });

                try {
                    const response = await axios.post(`${BACKEND}/analyze-full`, {
                        path: projectPath,
                        use_llm: useLLM.value,
                    });

                    const { results, summary, count } = response.data;

                    progress.report({ message: '🧠 Processing findings…' });

                    // ── Apply inline squiggles ─────────────────────
                    diagnosticCollection.clear();
                    const diagnosticMap = new Map<string, vscode.Diagnostic[]>();

                    for (const finding of results) {
                        if (!finding.file_path || finding.file_path === 'unknown') {
                            continue;
                        }
                        const uri = vscode.Uri.file(finding.file_path);
                        const line = Math.max(0, (finding.line || 1) - 1);
                        const range = new vscode.Range(line, 0, line, 200);

                        const severity = _toDiagnosticSeverity(finding.risk_category);
                        const message = _formatDiagnosticMessage(finding);

                        const diagnostic = new vscode.Diagnostic(range, message, severity);
                        diagnostic.source = `AutoShield [${finding.tool}]`;
                        diagnostic.code = finding.cwe_id;

                        const existing = diagnosticMap.get(uri.toString()) ?? [];
                        existing.push(diagnostic);
                        diagnosticMap.set(uri.toString(), existing);
                    }

                    diagnosticMap.forEach((diags, uriStr) => {
                        diagnosticCollection.set(vscode.Uri.parse(uriStr), diags);
                    });

                    // ── Send results to sidebar ────────────────────
                    sidebarProvider.postMessage({
                        type: 'scanResults',
                        results,
                        summary,
                        count,
                        projectPath,
                        llmEnabled: useLLM.value,
                    });

                    // ── Status bar summary ─────────────────────────
                    const critHigh = (summary.critical ?? 0) + (summary.high ?? 0);
                    const msg = critHigh > 0
                        ? `⚠️ AutoShield: ${critHigh} critical/high issues in ${count} findings`
                        : `✅ AutoShield: ${count} findings, no critical issues`;

                    vscode.window.showInformationMessage(msg, 'View in Sidebar').then(sel => {
                        if (sel) {
                            vscode.commands.executeCommand('autoshield.view.focus');
                        }
                    });

                } catch (error: any) {
                    const detail = error?.response?.data?.detail ?? error.message;
                    vscode.window.showErrorMessage(
                        `AutoShield scan failed: ${detail}. Is the backend running?`
                    );
                }
            }
        );
    });

    // ── Command: Analyze selection / single finding ────────────────
    const analyzeSelectionCommand = vscode.commands.registerCommand(
        'autoshield.analyzeSelection',
        async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) { return; }

            const selection = editor.selection;
            const code = editor.document.getText(selection);

            if (!code.trim()) {
                vscode.window.showWarningMessage('AutoShield: Select some code first.');
                return;
            }

            await vscode.window.withProgress(
                { location: vscode.ProgressLocation.Notification, title: 'AutoShield: Analyzing…' },
                async () => {
                    try {
                        const response = await axios.post(`${BACKEND}/rag/analyze`, {
                            code_snippet: code,
                            cwe_id: 'CWE-Unknown',
                            severity: 'medium',
                            vuln_type: '',
                            file_path: editor.document.fileName,
                            line: selection.start.line + 1,
                            tool: 'manual-review',
                            use_llm: true,
                        });

                        sidebarProvider.postMessage({
                            type: 'singleAnalysis',
                            result: response.data,
                        });

                        vscode.commands.executeCommand('autoshield.view.focus');
                    } catch (error: any) {
                        vscode.window.showErrorMessage(
                            `Analysis failed: ${error?.response?.data?.detail ?? error.message}`
                        );
                    }
                }
            );
        }
    );

    // ── Command: Clear diagnostics ─────────────────────────────────
    const clearCommand = vscode.commands.registerCommand('autoshield.clear', () => {
        diagnosticCollection.clear();
        sidebarProvider.postMessage({ type: 'clear' });
        vscode.window.showInformationMessage('AutoShield: Diagnostics cleared.');
    });

    context.subscriptions.push(
        scanCommand,
        analyzeSelectionCommand,
        clearCommand,
        diagnosticCollection,
    );
}

export function deactivate() {}

// ── Helpers ────────────────────────────────────────────────────────
function _toDiagnosticSeverity(riskCategory: string): vscode.DiagnosticSeverity {
    switch ((riskCategory ?? '').toUpperCase()) {
        case 'CRITICAL':
        case 'HIGH':
            return vscode.DiagnosticSeverity.Error;
        case 'MEDIUM':
            return vscode.DiagnosticSeverity.Warning;
        default:
            return vscode.DiagnosticSeverity.Information;
    }
}

function _formatDiagnosticMessage(finding: any): string {
    const score = finding.risk_score?.toFixed(1) ?? '?';
    const cat = finding.risk_category ?? finding.final_severity ?? 'UNKNOWN';
    const owasp = finding.owasp_category ? ` | OWASP: ${finding.owasp_category}` : '';
    const fp = finding.false_positive_likelihood > 0.5 ? ' ⚠ Possible FP' : '';
    return `[${cat} | Score: ${score}/100${owasp}] ${finding.vuln_type || finding.cwe_id}${fp}`;
}