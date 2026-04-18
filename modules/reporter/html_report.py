"""
HTML and PDF Report Generator
Renders the Jinja2 template with collected scan data,
then converts to PDF via WeasyPrint.
"""
import asyncio
from pathlib import Path
from typing import Optional
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from loguru import logger

from modules.reporter.collector import ReportCollector


TEMPLATE_DIR  = Path("modules/reporter/templates")
OUTPUT_DIR    = Path("reports/output")


class HTMLReportGenerator:
    """
    Generates a self-contained HTML report from scan findings.
    """

    def __init__(self, scan_id: str, output_dir: Optional[Path] = None):
        self.scan_id    = scan_id
        self.output_dir = output_dir or OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        # Add custom filters
        self.jinja_env.filters["selectattr"] = self._selectattr_filter

    def _selectattr_filter(self, items, attr, op, value):
        """Jinja2 selectattr helper for filtering lists of dicts."""
        if op == "equalto":
            return [i for i in items if i.get(attr) == value]
        return items

    async def generate(self) -> Path:
        """
        Collect data and render HTML report.
        Returns the path to the generated file.
        """
        logger.info(f"[Reporter] Generating HTML report for scan {self.scan_id}")

        # Collect all report data from DB
        collector   = ReportCollector(self.scan_id)
        report_data = await collector.collect()

        # Render Jinja2 template
        template  = self.jinja_env.get_template("report.html")
        html_content = template.render(**report_data)

        # Write to file
        filename = (
            f"WAPT-{self.scan_id[:8].upper()}-"
            f"{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
        )
        output_path = self.output_dir / filename
        output_path.write_text(html_content, encoding="utf-8")

        logger.success(f"[Reporter] HTML report saved: {output_path}")
        return output_path


class PDFReportGenerator:
    """
    Converts the HTML report to PDF using WeasyPrint.
    WeasyPrint renders the same HTML/CSS as a browser would.
    """

    def __init__(self, scan_id: str, output_dir: Optional[Path] = None):
        self.scan_id    = scan_id
        self.output_dir = output_dir or OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def generate(self) -> Path:
        """Generate HTML first, then convert to PDF."""
        logger.info(f"[Reporter] Generating PDF report for scan {self.scan_id}")

        # Generate HTML first
        html_gen  = HTMLReportGenerator(self.scan_id, self.output_dir)
        html_path = await html_gen.generate()

        # Convert HTML → PDF in thread pool (WeasyPrint is synchronous)
        loop = asyncio.get_event_loop()
        pdf_path = await loop.run_in_executor(
            None, self._convert_to_pdf, html_path
        )

        logger.success(f"[Reporter] PDF report saved: {pdf_path}")
        return pdf_path

    def _convert_to_pdf(self, html_path: Path) -> Path:
        """Synchronous WeasyPrint conversion."""
        try:
            from weasyprint import HTML, CSS
            from weasyprint.text.fonts import FontConfiguration

            pdf_path = html_path.with_suffix(".pdf")
            font_config = FontConfiguration()

            # Additional print CSS
            print_css = CSS(string="""
                @page {
                    size: A4;
                    margin: 15mm 15mm 20mm 15mm;
                    @bottom-center {
                        content: "Page " counter(page) " of " counter(pages);
                        font-size: 10px;
                        color: #aaa;
                    }
                }
                .cover { page-break-after: always; }
                .finding-card { page-break-inside: avoid; }
                .section { page-break-inside: avoid; }
            """, font_config=font_config)

            HTML(filename=str(html_path)).write_pdf(
                str(pdf_path),
                stylesheets=[print_css],
                font_config=font_config,
            )
            return pdf_path

        except ImportError as e:
            message = (
                "WeasyPrint dependencies are missing. "
                "Install WeasyPrint and the required native libraries: "
                "https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation"
            )
            logger.error(f"[Reporter] PDF conversion failed: {message} ({e})")
            raise RuntimeError(message) from e
        except Exception as e:
            logger.error(f"[Reporter] PDF conversion failed: {e}")
            raise
        
        