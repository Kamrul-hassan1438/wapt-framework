import asyncio
import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from core import stealth
from core.config import settings
from modules.vulns.auth import AuthTesterModule

console = Console()


@click.group()
@click.version_option(version=settings.app.version)
def cli():
    """
    WAPT Framework — Web Application Penetration Testing Tool.

    IMPORTANT: Only use against targets you have explicit written
    permission to test. Unauthorized testing is illegal.
    """
    pass


@cli.command()
def info():
    """Show framework version and configuration."""
    table = Table(title=f"{settings.app.name} v{settings.app.version}", show_header=False)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Environment", settings.app.env)
    table.add_row("Database", settings.db.url)
    table.add_row("Rate Limit", f"{settings.scan.default_rate_limit} req/s")
    table.add_row("Timeout", f"{settings.scan.default_timeout}s")
    table.add_row("Log Level", settings.log.level)
    console.print(table)


@cli.command()
@click.argument("target_url")
@click.option("--type",   "scan_type", default="full",
              type=click.Choice(["full","recon","scan","vuln","auth"]))
@click.option("--rate-limit", default=None, type=int)
@click.option("--timeout",    default=None, type=int)
@click.option(
    "--stealth",
    type=click.Choice(["normal", "polite", "stealth"]),
    default="normal",
    help="Request stealth mode",
)
def scan(target_url: str, scan_type: str, rate_limit, timeout, stealth):
    """
    Run a penetration test against TARGET_URL.

    Example: python cli.py scan http://localhost:8080 --type recon
    """
    rprint(f"\n[bold red]⚠  LEGAL NOTICE[/bold red]")
    rprint("[yellow]You must have explicit written permission to test this target.[/yellow]")
    rprint("[yellow]Unauthorized testing is illegal and unethical.[/yellow]\n")

    confirmed = click.confirm("Do you confirm you have permission to test this target?")
    if not confirmed:
        rprint("[red]Scan cancelled.[/red]")
        return

    rprint(f"\n[cyan]Target:[/cyan]    {target_url}")
    rprint(f"[cyan]Scan type:[/cyan] {scan_type}")
    rprint(f"[cyan]Rate limit:[/cyan] {rate_limit or settings.scan.default_rate_limit} req/s\n")

    asyncio.run(_run_scan(target_url, scan_type, rate_limit, timeout, stealth))



async def _run_scan(target_url: str, scan_type: str, rate_limit, timeout, stealth):
    from core.engine import ScanEngine, ReconPipeline, ScannerPipeline, VulnPipeline
    from db.models import ScanType, Scan, ScanStatus, Target
    from db.database import AsyncSessionLocal
    from sqlalchemy import select
    import uuid

    scan_id = str(uuid.uuid4())
    console.print(f"[green]Scan ID:[/green] {scan_id}\n")

    # Persist target and scan records so reports can be generated later
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Target).where(Target.url == target_url))
        target = result.scalars().first()
        if not target:
            target = Target(name=target_url, url=target_url)
            session.add(target)
            await session.commit()

        scan = Scan(
            id=scan_id,
            target_id=target.id,
            scan_type=ScanType(scan_type),
            status=ScanStatus.PENDING,
        )
        session.add(scan)
        await session.commit()

    # Route modules by scan type
    module_map = {
        "recon":  ReconPipeline.get_modules(),
        "scan":   ScannerPipeline.get_modules(),
        "full":  VulnPipeline.get_full_pipeline(),
        "auth":  [AuthTesterModule],
        "vuln":  VulnPipeline.get_modules(),
    }
    modules = module_map.get(scan_type, ReconPipeline.get_modules())

    async with ScanEngine(
        target_url=target_url,
        scan_id=scan_id,
        scan_type=ScanType(scan_type),
        rate_limit=rate_limit,
        timeout=timeout,
        modules=modules,
        stealth_mode=stealth, 
    ) as engine:
        summary = await engine.run()

    # Pretty-print findings table
    from rich.table import Table
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        summary["findings"],
        key=lambda f: severity_order.get(f["severity"], 5)
    )

    table = Table(title=f"Findings — {summary['findings_count']} total")
    table.add_column("Severity", style="bold")
    table.add_column("Type", max_width=25)
    table.add_column("Title", max_width=55)

    severity_colors = {
        "critical": "bright_red",
        "high":     "red",
        "medium":   "yellow",
        "low":      "cyan",
        "info":     "dim",
    }
    for f in sorted_findings:
        color = severity_colors.get(f["severity"], "white")
        table.add_row(
            f"[{color}]{f['severity'].upper()}[/{color}]",
            f["vuln_type"],
            f["title"][:55],
        )

    console.print(table)
    console.print(f"\n[bold green]✓ Scan complete![/bold green]  "
                  f"Status: {summary['status']} | "
                  f"Duration: {summary.get('duration', 'N/A')}")


@cli.command()
def server():
    """Start the FastAPI web server."""
    import uvicorn
    rprint(f"[cyan]Starting server on {settings.app.host}:{settings.app.port}[/cyan]")
    uvicorn.run(
        "main:app",
        host=settings.app.host,
        port=settings.app.port,
        reload=(settings.app.env == "development"),
        log_level=settings.log.level.lower(),
    )



@cli.command()
@click.argument("scan_id")
@click.option(
    "--format", "fmt",
    type=click.Choice(["html", "pdf", "json", "markdown", "all"]),
    default="all",
    show_default=True,
    help="Report format to generate",
)
@click.option(
    "--output-dir",
    default="reports/output",
    show_default=True,
    help="Directory to save the report",
)
def report(scan_id: str, fmt: str, output_dir: str):
    """
    Generate a report for a completed scan.

    \b
    Example:
      python cli.py report 8a6d0172-847c-403c-a515-2555efd2b4a2
      python cli.py report <scan_id> --format pdf
      python cli.py report <scan_id> --format markdown
    """
    asyncio.run(_generate_report(scan_id, fmt, Path(output_dir)))


async def _generate_report(scan_id: str, fmt: str, output_dir: Path):
    from modules.reporter.html_report import HTMLReportGenerator, PDFReportGenerator
    from modules.reporter.exporters   import JSONReportExporter, MarkdownReportExporter

    output_dir.mkdir(parents=True, exist_ok=True)
    generated = []

    generators = {
        "html":     lambda: HTMLReportGenerator(scan_id, output_dir).generate(),
        "pdf":      lambda: PDFReportGenerator(scan_id, output_dir).generate(),
        "json":     lambda: JSONReportExporter(scan_id, output_dir).generate(),
        "markdown": lambda: MarkdownReportExporter(scan_id, output_dir).generate(),
    }

    targets = list(generators.keys()) if fmt == "all" else [fmt]

    for target_fmt in targets:
        try:
            console.print(f"[cyan]Generating {target_fmt.upper()} report...[/cyan]")
            path = await generators[target_fmt]()
            generated.append((target_fmt, path))
            console.print(f"[green]✓[/green] {target_fmt.upper()}: {path}")
        except Exception as e:
            console.print(f"[red]✗[/red] {target_fmt.upper()} failed: {e}")

    if generated:
        console.print(f"\n[bold green]Reports generated:[/bold green] {len(generated)} file(s)")
        for fmt_name, path in generated:
            file_size = Path(path).stat().st_size
            size_str  = (
                f"{file_size / 1024:.1f} KB" if file_size < 1_000_000
                else f"{file_size / 1_048_576:.1f} MB"
            )
            console.print(f"  {fmt_name.upper():<10} {size_str:<10} {path}")

if __name__ == "__main__":
    cli()