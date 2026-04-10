import asyncio
import click
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from core.config import settings

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
@click.option("--type", "scan_type", default="full",
              type=click.Choice(["full", "recon", "scan", "vuln", "auth"]),
              help="Type of scan to run")
@click.option("--rate-limit", default=None, type=int, help="Requests per second")
@click.option("--timeout", default=None, type=int, help="Request timeout in seconds")
def scan(target_url: str, scan_type: str, rate_limit, timeout):
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

    asyncio.run(_run_scan(target_url, scan_type, rate_limit, timeout))


# Replace the _run_scan function in cli.py with this:

async def _run_scan(target_url: str, scan_type: str, rate_limit, timeout):
    from core.engine import ScanEngine, ReconPipeline
    from db.models import ScanType
    import uuid

    scan_id = str(uuid.uuid4())
    console.print(f"[green]Scan ID:[/green] {scan_id}\n")

    modules = []
    if scan_type in ("full", "recon"):
        modules = ReconPipeline.get_modules()

    async with ScanEngine(
        target_url=target_url,
        scan_id=scan_id,
        scan_type=ScanType(scan_type),
        rate_limit=rate_limit,
        timeout=timeout,
        modules=modules,
    ) as engine:
        summary = await engine.run()

    # Pretty-print findings to terminal
    from rich.table import Table
    table = Table(title=f"Findings — {summary['findings_count']} total")
    table.add_column("Severity", style="bold")
    table.add_column("Type")
    table.add_column("Title")

    severity_colors = {
        "critical": "red", "high": "red",
        "medium": "yellow", "low": "cyan", "info": "dim"
    }
    for f in summary["findings"]:
        color = severity_colors.get(f["severity"], "white")
        table.add_row(
            f"[{color}]{f['severity'].upper()}[/{color}]",
            f["vuln_type"],
            f["title"][:60],
        )
    console.print(table)
    console.print(f"\n[bold green]Scan complete![/bold green] Status: {summary['status']}")

    
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


if __name__ == "__main__":
    cli()