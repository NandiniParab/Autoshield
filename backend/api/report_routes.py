from datetime import datetime
from typing import Any, Dict, Optional
import html

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel


router = APIRouter()


class ExportReportRequest(BaseModel):
    report: Dict[str, Any]
    format: Optional[str] = "json"


@router.post("/export")
def export_report(request: ExportReportRequest):
    export_format = (request.format or "json").lower()
    report = request.report

    if export_format == "html":
        return HTMLResponse(content=generate_html_report(report))

    return JSONResponse(content=report)


def generate_html_report(report: Dict[str, Any]) -> str:
    score = report.get("overall_risk_score", "N/A")
    level = report.get("overall_risk_level", "UNKNOWN")
    total = report.get("total_findings", 0)
    findings = report.get("findings", [])
    top_issues = report.get("top_issues", [])
    remediation_plan = report.get("remediation_plan", [])
    grouped = report.get("grouped_summary", {})
    agent_trace = report.get("agent_trace", [])

    def safe(value: Any) -> str:
        return html.escape(str(value or ""))

    findings_html = ""
    for finding in findings:
        validation = finding.get("validation", {}) or {}
        findings_html += f"""
        <div class="finding">
            <h3>{safe(finding.get("category", "Security Issue"))}</h3>
            <p><strong>Message:</strong> {safe(finding.get("message"))}</p>
            <p><strong>Severity:</strong> {safe(finding.get("severity"))}</p>
            <p><strong>Confidence:</strong> {safe(validation.get("confidence"))}</p>
            <p><strong>CWE:</strong> {safe(finding.get("cwe") or finding.get("cwe_id"))}</p>
            <p><strong>OWASP:</strong> {safe(finding.get("owasp"))}</p>
            <p><strong>Location:</strong> {safe(finding.get("file"))}:{safe(finding.get("line"))}</p>
            <pre>{safe(finding.get("code_snippet"))}</pre>
            <details>
                <summary>Explanation</summary>
                <pre>{safe(finding.get("explanation"))}</pre>
            </details>
        </div>
        """

    top_issues_html = "".join(
        [
            f"<li><strong>{safe(issue.get('category'))}</strong> - "
            f"{safe(issue.get('severity'))} - {safe(issue.get('file'))}:{safe(issue.get('line'))}</li>"
            for issue in top_issues
        ]
    )

    remediation_html = "".join(
        [
            f"<li><strong>{safe(item.get('priority'))}</strong> - "
            f"{safe(item.get('category'))}: {safe(item.get('action'))}</li>"
            for item in remediation_plan
        ]
    )

    source_summary_html = "".join(
        [
            f"<li>{safe(source)}: {safe(count)}</li>"
            for source, count in grouped.get("by_source", {}).items()
        ]
    )

    category_summary_html = "".join(
        [
            f"<li>{safe(category)}: {safe(count)}</li>"
            for category, count in grouped.get("by_category", {}).items()
        ]
    )

    agent_trace_html = "".join(
        [
            f"<li>{safe(item.get('agent'))} - {safe(item.get('status'))}</li>"
            for item in agent_trace
        ]
    )

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>AutoShield Security Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f5f5f5;
                color: #111827;
                margin: 0;
                padding: 24px;
            }}
            .container {{
                max-width: 1100px;
                margin: auto;
                background: white;
                padding: 24px;
                border-radius: 8px;
                box-shadow: 0 4px 16px rgba(0,0,0,0.08);
            }}
            .header {{
                border-bottom: 2px solid #e5e7eb;
                padding-bottom: 16px;
                margin-bottom: 20px;
            }}
            .score {{
                font-size: 36px;
                font-weight: bold;
            }}
            .level {{
                display: inline-block;
                padding: 6px 12px;
                border-radius: 999px;
                background: #111827;
                color: white;
                font-weight: bold;
            }}
            .grid {{
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 16px;
                margin: 20px 0;
            }}
            .card {{
                background: #f9fafb;
                border: 1px solid #e5e7eb;
                border-radius: 8px;
                padding: 16px;
            }}
            .finding {{
                border: 1px solid #e5e7eb;
                border-radius: 8px;
                padding: 16px;
                margin-bottom: 16px;
                background: #ffffff;
            }}
            pre {{
                background: #111827;
                color: #f9fafb;
                padding: 12px;
                border-radius: 8px;
                overflow-x: auto;
                white-space: pre-wrap;
            }}
            h1, h2, h3 {{
                margin-top: 0;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>AutoShield Security Report</h1>
                <p>Generated: {safe(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}</p>
                <p><strong>Project:</strong> {safe(report.get("project_path"))}</p>
                <p><strong>Runtime URL:</strong> {safe(report.get("runtime_url"))}</p>
            </div>

            <div class="card">
                <h2>Executive Summary</h2>
                <div class="score">{safe(score)}/100</div>
                <p class="level">{safe(level)}</p>
                <p><strong>Total Findings:</strong> {safe(total)}</p>
            </div>

            <div class="grid">
                <div class="card">
                    <h3>Findings by Source</h3>
                    <ul>{source_summary_html}</ul>
                </div>
                <div class="card">
                    <h3>Findings by Category</h3>
                    <ul>{category_summary_html}</ul>
                </div>
                <div class="card">
                    <h3>Agent Trace</h3>
                    <ul>{agent_trace_html}</ul>
                </div>
            </div>

            <div class="card">
                <h2>Top Issues</h2>
                <ul>{top_issues_html}</ul>
            </div>

            <div class="card">
                <h2>Remediation Plan</h2>
                <ul>{remediation_html}</ul>
            </div>

            <h2>Detailed Findings</h2>
            {findings_html}
        </div>
    </body>
    </html>
    """
