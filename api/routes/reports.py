"""
Report API Routes
Generate and download reports via the REST API.
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pathlib import Path
from typing import Optional
from pydantic import BaseModel

router = APIRouter()

OUTPUT_DIR = Path("reports/output")


class ReportRequest(BaseModel):
    scan_id:    str
    formats:    list[str] = ["html", "json", "markdown"]
    output_dir: Optional[str] = None


@router.post("/generate", status_code=202)
async def generate_report(
    req: ReportRequest,
    background_tasks: BackgroundTasks,
):
    """
    Trigger async report generation.
    Returns immediately — report is generated in the background.
    """
    output_dir = Path(req.output_dir) if req.output_dir else OUTPUT_DIR

    background_tasks.add_task(
        _run_report_generation,
        req.scan_id,
        req.formats,
        output_dir,
    )
    return {
        "message":  "Report generation started",
        "scan_id":  req.scan_id,
        "formats":  req.formats,
        "output_dir": str(output_dir),
    }


async def _run_report_generation(
    scan_id: str,
    formats: list[str],
    output_dir: Path,
):
    """Background task that generates all requested report formats."""
    from modules.reporter.html_report import HTMLReportGenerator, PDFReportGenerator
    from modules.reporter.exporters   import JSONReportExporter, MarkdownReportExporter
    from loguru import logger

    generators = {
        "html":     lambda: HTMLReportGenerator(scan_id, output_dir).generate(),
        "pdf":      lambda: PDFReportGenerator(scan_id, output_dir).generate(),
        "json":     lambda: JSONReportExporter(scan_id, output_dir).generate(),
        "markdown": lambda: MarkdownReportExporter(scan_id, output_dir).generate(),
    }

    for fmt in formats:
        if fmt in generators:
            try:
                path = await generators[fmt]()
                logger.info(f"[API] Report generated: {path}")
            except Exception as e:
                logger.error(f"[API] Report {fmt} failed: {e}")


@router.get("/list")
async def list_reports():
    """List all generated report files."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    files = []
    for f in sorted(OUTPUT_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        stat = f.stat()
        files.append({
            "filename":   f.name,
            "format":     f.suffix.lstrip("."),
            "size_bytes": stat.st_size,
            "size_human": f"{stat.st_size / 1024:.1f} KB",
            "created_at": stat.st_mtime,
            "path":       str(f),
        })
    return {"reports": files, "count": len(files)}


@router.get("/download/{filename}")
async def download_report(filename: str):
    """Download a specific report file."""
    filepath = OUTPUT_DIR / filename

    # Security: prevent path traversal
    try:
        filepath.resolve().relative_to(OUTPUT_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename")

    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    media_types = {
        ".html": "text/html",
        ".pdf":  "application/pdf",
        ".json": "application/json",
        ".md":   "text/markdown",
    }
    media_type = media_types.get(filepath.suffix, "application/octet-stream")

    return FileResponse(
        path=str(filepath),
        filename=filename,
        media_type=media_type,
    )


@router.get("/{scan_id}/summary")
async def get_report_summary(scan_id: str):
    """Get a quick JSON summary of a scan's findings without generating a file."""
    try:
        from modules.reporter.collector import ReportCollector
        collector = ReportCollector(scan_id)
        data      = await collector.collect()
        return {
            "report_id":    data["report_id"],
            "target":       data["target_url"],
            "overall_risk": data["overall_risk"],
            "stats":        data["stats"],
            "owasp":        data["owasp_coverage"],
            "scan_duration":data["scan_duration"],
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    