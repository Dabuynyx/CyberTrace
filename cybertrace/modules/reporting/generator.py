"""Module 6: Forensic Reporting Engine (JSON, HTML, and PDF formats)."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List
from jinja2 import Template
from sqlalchemy.orm import Session

from cybertrace.case_management.manager import CaseManager
from cybertrace.database.models import EvidenceModel, FindingModel, CorrelationModel, TimelineEventModel

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CyberTrace Forensic Investigation Report - {{ case.id }}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #1e293b;
            background: #f8fafc;
            margin: 0;
            padding: 40px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: #ffffff;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
        }
        .header {
            border-bottom: 2px solid #0f172a;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0 0 10px 0;
            color: #0f172a;
            font-size: 26px;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            font-size: 12px;
            font-weight: 600;
            border-radius: 4px;
            text-transform: uppercase;
        }
        .badge-critical { background: #fee2e2; color: #991b1b; }
        .badge-high { background: #ffedd5; color: #9a3412; }
        .badge-medium { background: #fef9c3; color: #854d0e; }
        .badge-low { background: #e0f2fe; color: #075985; }
        .badge-info { background: #f1f5f9; color: #475569; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 14px;
        }
        th, td {
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid #e2e8f0;
        }
        th {
            background: #f1f5f9;
            color: #334155;
            font-weight: 600;
        }
        .code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: #f8fafc;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 13px;
        }
        .finding-card {
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 16px;
        }
        .disclaimer {
            font-size: 12px;
            color: #64748b;
            border-top: 1px solid #e2e8f0;
            margin-top: 40px;
            padding-top: 20px;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>CyberTrace Forensic Investigation Report</h1>
        <div><strong>Case ID:</strong> {{ case.id }} &nbsp;|&nbsp; <strong>Title:</strong> {{ case.title }}</div>
        <div><strong>Investigator:</strong> {{ case.investigator }} &nbsp;|&nbsp; <strong>Date Generated:</strong> {{ report_time }} UTC</div>
    </div>

    <h2>1. Evidence Inventory & Verification</h2>
    <table>
        <thead>
            <tr>
                <th>Evidence ID</th>
                <th>File Name</th>
                <th>Size</th>
                <th>Format</th>
                <th>SHA-256 Hash</th>
                <th>Integrity</th>
            </tr>
        </thead>
        <tbody>
            {% for ev in evidence %}
            <tr>
                <td class="code">{{ ev.id }}</td>
                <td>{{ ev.file_name }}</td>
                <td>{{ ev.file_size }} bytes</td>
                <td>{{ ev.file_type or "Unknown" }}</td>
                <td class="code" style="word-break: break-all;">{{ ev.sha256 }}</td>
                <td><strong>{{ ev.integrity_status }}</strong></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <h2>2. Technical Forensic Findings</h2>
    {% for f in findings %}
    <div class="finding-card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <strong style="font-size: 16px;">{{ f.title }}</strong>
            <span class="badge badge-{{ f.severity.lower() }}">{{ f.severity }}</span>
        </div>
        <p style="margin: 0 0 8px 0;">{{ f.description }}</p>
        <div style="font-size: 13px; color: #475569;">
            <strong>Technical Source:</strong> <span class="code">{{ f.source_technical }}</span> &nbsp;|&nbsp;
            <strong>Evidence Item:</strong> <span class="code">{{ f.evidence_id }}</span>
        </div>
        {% if f.limitations %}
        <div style="margin-top: 8px; font-size: 12px; color: #b45309; background: #fffbeb; padding: 6px 10px; border-radius: 4px;">
            <strong>Limitations:</strong> {{ f.limitations }}
        </div>
        {% endif %}
    </div>
    {% else %}
    <p>No critical findings recorded for this case.</p>
    {% endfor %}

    <h2>3. Multi-Evidence Correlations</h2>
    {% if correlations %}
    <table>
        <thead>
            <tr>
                <th>Source</th>
                <th>Target</th>
                <th>Relationship</th>
                <th>Technical Reasoning</th>
            </tr>
        </thead>
        <tbody>
            {% for c in correlations %}
            <tr>
                <td class="code">{{ c.source_evidence_id }}</td>
                <td class="code">{{ c.target_evidence_id }}</td>
                <td><strong>{{ c.relationship_type }}</strong></td>
                <td>{{ c.reasoning }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p>No cross-evidence correlations detected.</p>
    {% endif %}

    <h2>4. Investigation Chronological Timeline</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp (UTC)</th>
                <th>Type</th>
                <th>Source</th>
                <th>Summary</th>
            </tr>
        </thead>
        <tbody>
            {% for t in timeline %}
            <tr>
                <td class="code">{{ t.timestamp }}</td>
                <td>{{ t.timestamp_type }}</td>
                <td>{{ t.source_description }}</td>
                <td>{{ t.event_summary }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <div class="disclaimer">
        <strong>Forensic Integrity Notice:</strong> This report was deterministically generated by CyberTrace v0.1.0 without heuristic score inflation or external commercial AI inference. Every finding references its technical observation source and verifiable hash chain.
    </div>
</div>
</body>
</html>
"""

class ForensicReportGenerator:
    """Generates JSON, HTML, and PDF investigation reports."""

    def __init__(self, db: Session):
        self.db = db
        self.case_mgr = CaseManager(db)

    def _gather_case_data(self, case_id: str) -> Dict[str, Any]:
        case = self.case_mgr.get_case(case_id)
        evidence = self.db.query(EvidenceModel).filter_by(case_id=case_id).all()
        findings = (
            self.db.query(FindingModel)
            .join(EvidenceModel, FindingModel.evidence_id == EvidenceModel.id)
            .filter(EvidenceModel.case_id == case_id)
            .all()
        )
        correlations = self.db.query(CorrelationModel).filter_by(case_id=case_id).all()
        timeline = (
            self.db.query(TimelineEventModel)
            .filter_by(case_id=case_id)
            .order_by(TimelineEventModel.timestamp.asc())
            .all()
        )

        return {
            "case": case,
            "evidence": evidence,
            "findings": findings,
            "correlations": correlations,
            "timeline": timeline,
            "report_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        }

    def generate_json(self, case_id: str, output_path: str) -> str:
        """Export case findings and evidence verification as structured JSON."""
        data = self._gather_case_data(case_id)
        case = data["case"]

        payload = {
            "cybertrace_version": "0.1.0",
            "generated_at": data["report_time"],
            "case": {
                "id": case.id,
                "title": case.title,
                "description": case.description,
                "investigator": case.investigator,
                "status": case.status
            },
            "evidence_inventory": [
                {
                    "id": e.id,
                    "file_name": e.file_name,
                    "file_size": e.file_size,
                    "file_type": e.file_type,
                    "mime_type": e.mime_type,
                    "md5": e.md5,
                    "sha1": e.sha1,
                    "sha256": e.sha256,
                    "integrity_status": e.integrity_status,
                    "source_path": e.source_path
                }
                for e in data["evidence"]
            ],
            "findings": [
                {
                    "evidence_id": f.evidence_id,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "source_technical": f.source_technical,
                    "limitations": f.limitations,
                    "supporting_data": json.loads(f.supporting_data_json) if f.supporting_data_json else {}
                }
                for f in data["findings"]
            ],
            "correlations": [
                {
                    "source_evidence_id": c.source_evidence_id,
                    "target_evidence_id": c.target_evidence_id,
                    "relationship_type": c.relationship_type,
                    "reasoning": c.reasoning,
                    "supporting_data": json.loads(c.supporting_data_json) if c.supporting_data_json else {}
                }
                for c in data["correlations"]
            ],
            "timeline": [
                {
                    "timestamp": t.timestamp,
                    "timestamp_type": t.timestamp_type,
                    "source": t.source_description,
                    "summary": t.event_summary
                }
                for t in data["timeline"]
            ]
        }

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        return os.path.abspath(output_path)

    def generate_html(self, case_id: str, output_path: str) -> str:
        """Render high-fidelity HTML forensic investigation report."""
        data = self._gather_case_data(case_id)
        tmpl = Template(HTML_REPORT_TEMPLATE)
        rendered = tmpl.render(**data)

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered)

        return os.path.abspath(output_path)

    def generate_pdf(self, case_id: str, output_path: str) -> str:
        """Generate PDF report via ReportLab."""
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        
        data = self._gather_case_data(case_id)
        case = data["case"]
        evidence = data["evidence"]
        findings = data["findings"]

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter

        # Header
        c.setFont("Helvetica-Bold", 18)
        c.drawString(50, height - 50, "CyberTrace Forensic Investigation Report")
        c.setFont("Helvetica", 10)
        c.drawString(50, height - 70, f"Case: {case.title} ({case.id}) | Investigator: {case.investigator}")
        c.drawString(50, height - 85, f"Generated: {data['report_time']} UTC")

        c.setStrokeColorRGB(0.1, 0.1, 0.2)
        c.setLineWidth(1)
        c.line(50, height - 95, width - 50, height - 95)

        y = height - 120
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Evidence Inventory & Cryptographic Hashes:")
        y -= 20

        c.setFont("Helvetica", 9)
        for ev in evidence:
            c.drawString(60, y, f"• {ev.id}: {ev.file_name} ({ev.file_size} bytes, format: {ev.file_type or 'Unknown'})")
            y -= 14
            c.drawString(70, y, f"SHA-256: {ev.sha256} [{ev.integrity_status}]")
            y -= 18
            if y < 80:
                c.showPage()
                y = height - 50

        y -= 10
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"Technical Findings ({len(findings)} Total):")
        y -= 20

        c.setFont("Helvetica", 9)
        for f in findings:
            c.setFont("Helvetica-Bold", 9)
            c.drawString(60, y, f"[{f.severity}] {f.title}")
            y -= 14
            c.setFont("Helvetica", 8)
            c.drawString(70, y, f"Source: {f.source_technical} | Evidence: {f.evidence_id}")
            y -= 14
            c.drawString(70, y, f"Detail: {f.description[:90]}")
            y -= 18
            if y < 80:
                c.showPage()
                y = height - 50

        c.save()
        return os.path.abspath(output_path)
