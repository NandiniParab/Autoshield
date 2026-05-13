import * as vscode from 'vscode';
import axios from 'axios';
import * as fs from 'fs';
import * as path from 'path';
import { AutoShieldSidebarProvider } from './sidebar.js';

const BACKEND = 'http://127.0.0.1:8000';

export function activate(context: vscode.ExtensionContext) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('autoshield');
    const sidebarProvider = new AutoShieldSidebarProvider(context.extensionUri);

    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('autoshield.view', sidebarProvider)
    );

    const scanCommand = vscode.commands.registerCommand('autoshield.scan', async () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];

        if (!workspaceFolder) {
            vscode.window.showErrorMessage('Open a project folder before running AutoShield scan.');
            return;
        }

        const projectPath = workspaceFolder.uri.fsPath;
        sidebarProvider.postMessage({ type: 'scanStarted' });

        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: 'AutoShield',
                cancellable: false,
            },
            async (progress) => {
                progress.report({ message: 'Running LangGraph scan...' });

                try {
                    const response = await axios.post(`${BACKEND}/api/agent/scan`, {
                        project_path: projectPath,
                    });

                    const report = response.data ?? {};
                    const findings = Array.isArray(report.findings) ? report.findings : [];
                    const summary = report.confidence_summary ?? {};
                    const count = report.total_findings ?? findings.length;

                    progress.report({ message: 'Rendering findings...' });
                    diagnosticCollection.clear();
                    applyDiagnostics(findings, projectPath, diagnosticCollection);

                    sidebarProvider.postMessage({
                        type: 'scanResults',
                        results: findings,
                        summary,
                        count,
                        projectPath,
                        report,
                        langGraph: true,
                    });

                    const high = summary.high ?? 0;
                    const medium = summary.medium ?? 0;
                    const low = summary.low ?? 0;
                    const msg = high > 0
                        ? `AutoShield: ${high} high-confidence issues in ${count} findings`
                        : `AutoShield: ${count} findings (${medium} medium, ${low} low confidence)`;

                    vscode.window.showInformationMessage(msg, 'View in Sidebar').then((selection) => {
                        if (selection) {
                            vscode.commands.executeCommand('autoshield.view.focus');
                        }
                    });
                } catch (error: any) {
                    const detail = error?.response?.data?.detail ?? error.message;
                    sidebarProvider.postMessage({ type: 'scanError', error: detail });
                    vscode.window.showErrorMessage(
                        `AutoShield scan failed: ${detail}. Is the backend running?`
                    );
                }
            }
        );
    });

    const mediaComplianceCommand = vscode.commands.registerCommand('autoshield.mediaComplianceScan', async () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];

        if (!workspaceFolder) {
            vscode.window.showErrorMessage('Open a project folder before running AutoShield media compliance scan.');
            return;
        }

        const projectPath = workspaceFolder.uri.fsPath;
        const scanMode = await vscode.window.showQuickPick(
            [
                {
                    label: 'Local checks only',
                    description: 'Fast scan. Checks image filenames and local metadata signals.',
                    enableReverseSearch: false,
                },
                {
                    label: 'Reverse image search',
                    description: 'Uses SerpAPI Google Lens. Requires public_base_url/ngrok.',
                    enableReverseSearch: true,
                },
            ],
            {
                placeHolder: 'Choose media compliance scan mode',
                ignoreFocusOut: true,
            }
        );

        if (!scanMode) {
            return;
        }

        let publicBaseUrl: string | undefined;

        if (scanMode.enableReverseSearch) {
            publicBaseUrl = await vscode.window.showInputBox({
                title: 'Public image base URL',
                prompt: 'Enter the public URL serving this workspace, for example https://abc123.ngrok-free.app',
                placeHolder: 'https://abc123.ngrok-free.app',
                ignoreFocusOut: true,
                validateInput: (value) => {
                    const trimmed = value.trim();
                    if (!trimmed) {
                        return 'public_base_url is required for reverse image search.';
                    }
                    if (!/^https?:\/\//i.test(trimmed)) {
                        return 'Use a URL beginning with http:// or https://';
                    }
                    return null;
                },
            });

            if (!publicBaseUrl) {
                return;
            }
        }

        sidebarProvider.postMessage({ type: 'mediaComplianceStarted' });

        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: 'AutoShield Media Compliance',
                cancellable: false,
            },
            async (progress) => {
                progress.report({ message: 'Scanning local media files...' });

                try {
                    const response = await axios.post(`${BACKEND}/api/compliance/media-license/scan`, {
                        project_path: projectPath,
                        public_base_url: publicBaseUrl,
                        enable_reverse_search: scanMode.enableReverseSearch,
                        max_images: 10,
                    });

                    const mediaResult = response.data ?? {};
                    const report = buildMediaComplianceReport(mediaResult);
                    const findings = Array.isArray(report.findings) ? report.findings : [];
                    const summary = report.confidence_summary ?? {};
                    const count = report.total_findings ?? findings.length;

                    sidebarProvider.postMessage({
                        type: 'scanResults',
                        results: findings,
                        summary,
                        count,
                        projectPath,
                        report,
                        mediaCompliance: true,
                    });

                    vscode.window.showInformationMessage(
                        `AutoShield media compliance: ${mediaResult.images_scanned ?? 0} image(s), ${count} issue(s)`
                    );
                } catch (error: any) {
                    const detail = error?.response?.data?.detail ?? error.message;
                    sidebarProvider.postMessage({ type: 'scanError', error: detail });
                    vscode.window.showErrorMessage(
                        `AutoShield media compliance scan failed: ${detail}. Is the backend running?`
                    );
                }
            }
        );
    });

    const analyzeSelectionCommand = vscode.commands.registerCommand(
        'autoshield.analyzeSelection',
        async () => {
            vscode.window.showInformationMessage(
                'AutoShield: selected-code analysis is paused. Use AutoShield: Scan Project for LangGraph results.'
            );
        }
    );

    const applyFixCommand = vscode.commands.registerCommand('autoshield.applyFix', async () => {
        vscode.window.showInformationMessage('AutoShield: Apply Fix is coming soon.');
    });

    const generateFixCommand = vscode.commands.registerCommand('autoshield.generateFix', async () => {
        vscode.window.showInformationMessage('AutoShield: Get Fix is coming soon.');
    });

    const jumpToCommand = vscode.commands.registerCommand(
        'autoshield.jumpToLine',
        async (args: { filePath: string; line: number }) => {
            if (!args?.filePath || args.filePath === 'unknown') {
                return;
            }

            const projectPath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '';
            const resolvedPath = resolveFilePath(args.filePath, projectPath);

            if (!resolvedPath) {
                vscode.window.showWarningMessage(`AutoShield: Cannot find file: ${args.filePath}`);
                return;
            }

            try {
                const uri = vscode.Uri.file(resolvedPath);
                const doc = await vscode.workspace.openTextDocument(uri);
                const editor = await vscode.window.showTextDocument(doc);
                const line = Math.max(0, (args.line || 1) - 1);
                const pos = new vscode.Position(line, 0);
                editor.selection = new vscode.Selection(pos, pos);
                editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
            } catch (error: any) {
                vscode.window.showWarningMessage(`AutoShield: Cannot open ${args.filePath}: ${error.message}`);
            }
        }
    );

    const clearCommand = vscode.commands.registerCommand('autoshield.clear', () => {
        diagnosticCollection.clear();
        sidebarProvider.postMessage({ type: 'clear' });
        vscode.window.showInformationMessage('AutoShield: Diagnostics cleared.');
    });

    context.subscriptions.push(
        scanCommand,
        mediaComplianceCommand,
        analyzeSelectionCommand,
        applyFixCommand,
        generateFixCommand,
        jumpToCommand,
        clearCommand,
        diagnosticCollection
    );
}

function buildMediaComplianceReport(mediaResult: any): any {
    const issues = Array.isArray(mediaResult.issues) ? mediaResult.issues : [];
    const findings = issues.map((issue: any, index: number) => ({
        tool: 'media-compliance',
        rule_id: `media-compliance-${index + 1}`,
        message: issue.title || 'Media compliance issue',
        severity: issue.severity || 'LOW',
        file: issue.file || mediaResult.project_path || 'media',
        file_path: issue.file || mediaResult.project_path || 'media',
        line: 1,
        column: 1,
        cwe: 'CWE-Unknown',
        cwe_id: 'CWE-Unknown',
        owasp: 'Compliance',
        category: issue.category || mediaResult.category || 'Media Compliance',
        code_snippet: issue.evidence || '',
        recommendation: issue.recommendation || '',
        validation: {
            confidence: issue.severity === 'HIGH' ? 'HIGH' : issue.severity === 'MEDIUM' ? 'MEDIUM' : 'LOW',
        },
        explanation: [
            issue.evidence ? `Evidence: ${issue.evidence}` : '',
            issue.recommendation ? `Recommendation: ${issue.recommendation}` : '',
            issue.matches ? `Matches: ${issue.matches.slice(0, 5).join(', ')}` : '',
        ].filter(Boolean).join('\n\n'),
        raw: issue,
    }));

    const confidenceSummary = findings.reduce(
        (acc: any, finding: any) => {
            const confidence = String(finding.validation?.confidence || 'LOW').toLowerCase();
            if (acc[confidence] !== undefined) {
                acc[confidence] += 1;
            }
            return acc;
        },
        { high: 0, medium: 0, low: 0 }
    );

    const byCategory = findings.reduce((acc: any, finding: any) => {
        const category = finding.category || 'Media Compliance';
        acc[category] = (acc[category] || 0) + 1;
        return acc;
    }, {});

    return {
        project_path: mediaResult.project_path,
        overall_risk_score: mediaResult.compliance_score ?? 100,
        overall_risk_level: mediaResult.risk_level ?? 'LOW',
        total_findings: findings.length,
        confidence_summary: confidenceSummary,
        grouped_summary: {
            by_source: { 'media-compliance': findings.length },
            by_confidence: {
                HIGH: confidenceSummary.high,
                MEDIUM: confidenceSummary.medium,
                LOW: confidenceSummary.low,
            },
            by_category: byCategory,
        },
        top_issues: findings.slice(0, 5).map((finding: any) => ({
            category: finding.category,
            message: finding.message,
            severity: finding.severity,
            confidence: finding.validation?.confidence,
            file: finding.file,
            line: finding.line,
            cwe: finding.cwe,
            owasp: finding.owasp,
        })),
        remediation_plan: findings.length
            ? findings.slice(0, 5).map((finding: any) => ({
                priority: finding.severity === 'HIGH' ? 'P0' : 'P1',
                category: finding.category,
                action: finding.recommendation || 'Verify media ownership, license, attribution, or replace the asset.',
            }))
            : [{
                priority: 'P2',
                category: 'Media Compliance',
                action: 'Keep proof of license or ownership for all shipped media assets.',
            }],
        findings,
        media_compliance: mediaResult,
        errors: mediaResult.success === false ? [mediaResult.error || 'Media compliance scan failed'] : [],
    };
}

export function deactivate() {}

function applyDiagnostics(
    findings: any[],
    projectPath: string,
    diagnosticCollection: vscode.DiagnosticCollection
) {
    const diagnosticMap = new Map<string, vscode.Diagnostic[]>();

    for (const finding of findings) {
        const findingPath = finding.file_path || finding.file;
        if (!findingPath || findingPath === 'unknown') {
            continue;
        }

        const resolvedPath = resolveFilePath(findingPath, projectPath);
        if (!resolvedPath) {
            continue;
        }

        const uri = vscode.Uri.file(resolvedPath);
        const line = Math.max((finding.line || 1) - 1, 0);
        const column = Math.max((finding.column || 1) - 1, 0);
        const range = new vscode.Range(line, column, line, column + 80);
        const diagnostic = new vscode.Diagnostic(
            range,
            formatDiagnosticMessage(finding),
            toDiagnosticSeverity(finding.severity)
        );

        diagnostic.source = 'AutoShield';
        diagnostic.code = finding.cwe || finding.cwe_id || 'CWE-Unknown';

        const existing = diagnosticMap.get(uri.toString()) ?? [];
        existing.push(diagnostic);
        diagnosticMap.set(uri.toString(), existing);
    }

    diagnosticMap.forEach((diagnostics, uriString) => {
        diagnosticCollection.set(vscode.Uri.parse(uriString), diagnostics);
    });
}

function resolveFilePath(filePath: string, projectPath: string): string | null {
    if (!filePath || filePath === 'unknown') {
        return null;
    }

    if (path.isAbsolute(filePath) && fs.existsSync(filePath)) {
        return filePath;
    }

    if (projectPath) {
        const joined = path.join(projectPath, filePath);
        if (fs.existsSync(joined)) {
            return joined;
        }

        const stripped = filePath.replace(/^[/\\]+/, '');
        const strippedJoined = path.join(projectPath, stripped);
        if (fs.existsSync(strippedJoined)) {
            return strippedJoined;
        }
    }

    if (path.isAbsolute(filePath)) {
        return filePath;
    }

    return null;
}

function toDiagnosticSeverity(severity: string): vscode.DiagnosticSeverity {
    switch ((severity ?? '').toUpperCase()) {
        case 'CRITICAL':
        case 'ERROR':
        case 'HIGH':
            return vscode.DiagnosticSeverity.Error;
        case 'WARNING':
        case 'MEDIUM':
            return vscode.DiagnosticSeverity.Warning;
        default:
            return vscode.DiagnosticSeverity.Information;
    }
}

function formatDiagnosticMessage(finding: any): string {
    const category = finding.category ?? 'Security Issue';
    const confidence = finding.validation?.confidence ?? 'UNKNOWN';
    const message = finding.message ?? finding.rule_id ?? finding.cwe ?? 'Finding';
    return `[${category} | ${confidence}] ${message}`;
}
