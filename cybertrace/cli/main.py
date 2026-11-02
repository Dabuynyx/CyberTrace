"""CyberTrace Command Line Interface."""

import json
import os
import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from cybertrace.database.models import init_db, SessionLocal, CaseModel, EvidenceModel
from cybertrace.case_management.manager import CaseManager
from cybertrace.core.engine import ForensicEngine
from cybertrace.modules.reporting.generator import ForensicReportGenerator
from cybertrace.modules.file_intelligence.analyzer import FileIntelligenceModule
from cybertrace.modules.metadata_forensics.analyzer import MetadataForensicsModule
from cybertrace.modules.malware_triage.analyzer import MalwareTriageModule
from cybertrace.modules.artifact_analysis.analyzer import ArtifactAnalysisModule
from cybertrace.modules.evidence_correlation.timeline import TimelineEngine
from cybertrace.utils.crypto import format_bytes

app = typer.Typer(
    name="cybertrace",
    help="CyberTrace: Professional Modular Digital Forensics & Investigation Framework.",
    no_args_is_help=True
)
case_app = typer.Typer(help="Manage investigation cases.")
evidence_app = typer.Typer(help="Manage evidence acquisition and integrity verification.")
analyze_app = typer.Typer(help="Run forensic analysis modules on standalone files or case evidence.")
report_app = typer.Typer(help="Generate investigation reports in JSON, HTML, or PDF format.")

app.add_typer(case_app, name="case")
app.add_typer(evidence_app, name="evidence")
app.add_typer(analyze_app, name="analyze")
app.add_typer(report_app, name="report")

console = Console()

@app.command()
def init():
    """Initialize local database and storage repositories."""
    init_db()
    home = Path.home() / ".cybertrace"
    console.print(Panel(f"[bold green]CyberTrace initialized successfully![/bold green]\nWorking directory: {home}", title="System Initialized"))

@app.command()
def version():
    """Display CyberTrace version and system details."""
    console.print("[bold cyan]CyberTrace[/bold cyan] v0.1.1 — Digital Forensics & Investigation Framework")

@app.command()
def status():
    """Display current system status and repository statistics."""
    init_db()
    db = SessionLocal()
    try:
        cases_count = db.query(CaseModel).count()
        ev_count = db.query(EvidenceModel).count()
        table = Table(title="CyberTrace System Status")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("Version", "0.1.0")
        table.add_row("Active Investigations", str(cases_count))
        table.add_row("Stored Evidence Items", str(ev_count))
        table.add_row("Local Storage Path", str(Path.home() / ".cybertrace"))
        console.print(table)
    finally:
        db.close()

# Top-level direct analysis aliases for CLI ergonomics
@app.command("scan")
def scan_direct_cmd(
    target: str = typer.Argument(..., help="Path to file to analyze or Case ID to analyze."),
    yara_rules: Optional[str] = typer.Option(None, "--yara-rules", "-y", help="Optional path to YARA rules file.")
):
    """Scan and analyze a file or case directly (e.g. 'cybertrace scan CASE_ID' or 'cybertrace scan path/to/file')."""
    if os.path.exists(target):
        analyze_file_cmd(target)
    else:
        init_db()
        db = SessionLocal()
        try:
            mgr = CaseManager(db)
            mgr.get_case(target)
            engine = ForensicEngine(db)
            res = engine.analyze_case(target, yara_rules=yara_rules)
            console.print(f"[bold green]Case Analysis Complete for {target}.[/bold green] Processed {res['total_evidence_analyzed']} evidence item(s).")
        except Exception as e:
            console.print(f"[bold red]Error analyzing '{target}':[/bold red] {e}")
            raise typer.Exit(code=1)
        finally:
            db.close()

# Case Commands
@case_app.command("create")
def case_create(title: str, description: str = typer.Option("", "--desc", "-d"), investigator: str = typer.Option("Forensic Analyst", "--investigator", "-i")):
    """Create a new forensic investigation case."""
    init_db()
    db = SessionLocal()
    try:
        mgr = CaseManager(db)
        case = mgr.create_case(title, description, investigator)
        console.print(f"[bold green]Case created successfully:[/bold green] {case.id} - [bold]{case.title}[/bold]")
    finally:
        db.close()

@case_app.command("list")
def case_list():
    """List all registered investigation cases."""
    init_db()
    db = SessionLocal()
    try:
        cases = CaseManager(db).list_cases()
        if not cases:
            console.print("[yellow]No cases found. Create one using 'cybertrace case create <title>'[/yellow]")
            return

        table = Table(title="Investigation Cases")
        table.add_column("Case ID", style="cyan", no_wrap=True)
        table.add_column("Title", style="bold")
        table.add_column("Investigator", style="blue")
        table.add_column("Status", style="green")
        table.add_column("Created (UTC)")

        for c in cases:
            table.add_row(c.id, c.title, c.investigator, c.status, str(c.created_at))
        console.print(table)
    finally:
        db.close()

@case_app.command("show")
def case_show(case_id: str):
    """View details of a specific investigation case."""
    init_db()
    db = SessionLocal()
    try:
        mgr = CaseManager(db)
        case = mgr.get_case(case_id)
        evidence = db.query(EvidenceModel).filter_by(case_id=case_id).all()

        console.print(Panel(
            f"[bold]Title:[/bold] {case.title}\n"
            f"[bold]Investigator:[/bold] {case.investigator}\n"
            f"[bold]Status:[/bold] {case.status}\n"
            f"[bold]Description:[/bold] {case.description or 'N/A'}\n"
            f"[bold]Created:[/bold] {case.created_at}",
            title=f"Case Details: {case.id}"
        ))

        table = Table(title=f"Evidence Items in Case ({len(evidence)})")
        table.add_column("Evidence ID", style="cyan")
        table.add_column("Filename", style="bold")
        table.add_column("Size")
        table.add_column("Format")
        table.add_column("Integrity", style="green")

        for e in evidence:
            table.add_row(e.id, e.file_name, format_bytes(e.file_size), e.file_type or "Unknown", e.integrity_status)
        console.print(table)
    finally:
        db.close()

# Evidence Commands
@evidence_app.command("add")
def evidence_add(case_id: str, file_path: str):
    """Acquire evidence into an investigation case with cryptographic hashing."""
    init_db()
    db = SessionLocal()
    try:
        mgr = CaseManager(db)
        ev = mgr.add_evidence(case_id, file_path)
        console.print(Panel(
            f"[bold green]Evidence Acquired Successfully[/bold green]\n"
            f"Evidence ID: [bold]{ev.id}[/bold]\n"
            f"Original Source: {ev.source_path}\n"
            f"Size: {format_bytes(ev.file_size)}\n"
            f"SHA-256: [cyan]{ev.sha256}[/cyan]\n"
            f"Integrity Status: [green]{ev.integrity_status}[/green]",
            title="Evidence Intake"
        ))
    finally:
        db.close()

@evidence_app.command("list")
def evidence_list(case_id: str):
    """List all evidence acquired in a case."""
    init_db()
    db = SessionLocal()
    try:
        evidence = db.query(EvidenceModel).filter_by(case_id=case_id).all()
        table = Table(title=f"Evidence for Case {case_id}")
        table.add_column("Evidence ID", style="cyan")
        table.add_column("Filename")
        table.add_column("Size")
        table.add_column("SHA-256 (Truncated)", style="magenta")
        table.add_column("Integrity", style="green")

        for e in evidence:
            table.add_row(e.id, e.file_name, format_bytes(e.file_size), f"{e.sha256[:16]}...", e.integrity_status)
        console.print(table)
    finally:
        db.close()

@app.command("verify")
def verify_case(case_id: str):
    """Verify cryptographic integrity of all evidence in a case."""
    init_db()
    db = SessionLocal()
    try:
        mgr = CaseManager(db)
        evidence = db.query(EvidenceModel).filter_by(case_id=case_id).all()
        table = Table(title=f"Integrity Verification for Case {case_id}")
        table.add_column("Evidence ID")
        table.add_column("File")
        table.add_column("Integrity", style="bold green")
        table.add_column("Verified At")

        for ev in evidence:
            res = mgr.verify_evidence(ev.id)
            table.add_row(res["evidence_id"], res["file_name"], res["status"], res["verified_at"])
        console.print(table)
    finally:
        db.close()

# Analysis Commands
@analyze_app.command("case")
def analyze_case_cmd(case_id: str, yara_rules: Optional[str] = typer.Option(None, "--yara-rules", "-y")):
    """Run all forensic modules across all evidence in a case."""
    init_db()
    db = SessionLocal()
    try:
        engine = ForensicEngine(db)
        res = engine.analyze_case(case_id, yara_rules=yara_rules)
        console.print(f"[bold green]Case Analysis Complete.[/bold green] Processed {res['total_evidence_analyzed']} evidence item(s).")
    finally:
        db.close()

@analyze_app.command("file")
def analyze_file_cmd(file_path: str):
    """Inspect standalone file: magic signature, MIME type, hashes, entropy, and extension check."""
    mod = FileIntelligenceModule()
    res = mod.analyze(file_path)
    if res.status == "ERROR":
        console.print(f"[bold red]Error:[/bold red] {res.warnings}")
        return

    meta = res.raw_metadata
    hashes = meta.get("hashes", {})
    table = Table(title=f"File Intelligence: {Path(file_path).name}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="magenta")
    table.add_row("Detected Format", meta.get("detected_format"))
    table.add_row("MIME Type", meta.get("detected_mime"))
    table.add_row("File Size", meta.get("file_size_human"))
    table.add_row("Shannon Entropy", f"{meta.get('entropy')} / 8.0")
    table.add_row("MD5", hashes.get("md5"))
    table.add_row("SHA-1", hashes.get("sha1"))
    table.add_row("SHA-256", hashes.get("sha256"))
    console.print(table)

    if res.findings:
        console.print(f"\n[bold yellow]Findings ({len(res.findings)}):[/bold yellow]")
        for f in res.findings:
            console.print(f"• [{f.severity}] [bold]{f.title}[/bold]: {f.description}")

@analyze_app.command("metadata")
def analyze_meta_cmd(file_path: str):
    """Extract metadata, EXIF, and camera/software footprints."""
    mod = MetadataForensicsModule()
    res = mod.analyze(file_path)
    console.print(Panel(f"Analyzed {file_path} in {res.execution_time_seconds}s with {len(res.findings)} findings.", title="Metadata Forensics"))
    if res.findings:
        for f in res.findings:
            console.print(f"• [{f.severity}] [bold]{f.title}[/bold]: {f.description}")

@analyze_app.command("malware")
def analyze_malware_cmd(file_path: str, yara_rules: Optional[str] = typer.Option(None, "--yara-rules", "-y")):
    """Static malware triage: PE/ELF inspection, suspicious imports, strings, and YARA."""
    mod = MalwareTriageModule()
    res = mod.analyze(file_path, yara_rules=yara_rules)
    console.print(Panel(f"Static Triage: {Path(file_path).name}\nFindings: {len(res.findings)}", title="Malware Triage"))
    for f in res.findings:
        console.print(f"• [{f.severity}] [bold]{f.title}[/bold]: {f.description}")

@analyze_app.command("artifact")
def analyze_artifact_cmd(file_path: str):
    """Parse digital forensics artifact (SQLite database or log file)."""
    mod = ArtifactAnalysisModule()
    res = mod.analyze(file_path)
    console.print(Panel(f"Artifact Analysis: {Path(file_path).name}\nFindings: {len(res.findings)}", title="Artifact Parser"))
    for f in res.findings:
        console.print(f"• [{f.severity}] [bold]{f.title}[/bold]: {f.description}")

@app.command("timeline")
def timeline_cmd(case_id: str):
    """View chronologically reconstructed investigation timeline."""
    init_db()
    db = SessionLocal()
    try:
        t_engine = TimelineEngine(db)
        events = t_engine.get_case_timeline(case_id)
        if not events:
            console.print("[yellow]No timeline events recorded yet. Run analysis first.[/yellow]")
            return

        table = Table(title=f"Investigation Timeline: Case {case_id}")
        table.add_column("Timestamp (UTC)", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Source")
        table.add_column("Summary")

        for ev in events:
            table.add_row(ev["timestamp"], ev["timestamp_type"], ev["source_description"], ev["event_summary"])
        console.print(table)
    finally:
        db.close()

@app.command("correlate")
def correlate_cmd(case_id: str):
    """Correlate evidence items across case (shared hashes, IPs, identities)."""
    init_db()
    db = SessionLocal()
    try:
        engine = ForensicEngine(db)
        corrs = engine.correlator.correlate_case(case_id)
        if not corrs:
            console.print("[yellow]No multi-artifact correlations discovered.[/yellow]")
            return

        table = Table(title=f"Evidence Correlations: Case {case_id}")
        table.add_column("Source", style="cyan")
        table.add_column("Target", style="cyan")
        table.add_column("Relationship", style="bold magenta")
        table.add_column("Reasoning")

        for c in corrs:
            table.add_row(c["source_evidence_id"], c["target_evidence_id"], c["relationship_type"], c["reasoning"])
        console.print(table)
    finally:
        db.close()

# Report Commands
@report_app.command("generate")
def report_generate(
    case_id: str,
    format: str = typer.Option("html", "--format", "-f", help="Output format: html, json, or pdf"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Custom output path")
):
    """Generate professional forensic report in HTML, JSON, or PDF format."""
    init_db()
    db = SessionLocal()
    try:
        gen = ForensicReportGenerator(db)
        default_dir = Path.home() / ".cybertrace" / "reports"
        default_dir.mkdir(parents=True, exist_ok=True)
        out_path = output or str(default_dir / f"{case_id}_report.{format.lower()}")

        if format.lower() == "json":
            res = gen.generate_json(case_id, out_path)
        elif format.lower() == "html":
            res = gen.generate_html(case_id, out_path)
        elif format.lower() == "pdf":
            res = gen.generate_pdf(case_id, out_path)
        else:
            console.print(f"[red]Unsupported format: {format}. Use html, json, or pdf.[/red]")
            return

        console.print(f"[bold green]Report successfully generated:[/bold green] {res}")
    finally:
        db.close()
