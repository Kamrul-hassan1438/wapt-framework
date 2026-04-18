"""
Finding Saver
Persists scan findings to the database at the end of each module run.
Called by the engine after each module completes.
"""
from datetime import datetime, timezone
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from db.models import Finding, Scan, ScanStatus
from db.database import AsyncSessionLocal
from loguru import logger


async def save_findings(scan_id: str, findings: List[dict]) -> int:
    """
    Persist a list of finding dicts to the database.
    Returns the number of findings saved.
    """
    if not findings:
        return 0

    saved = 0
    async with AsyncSessionLocal() as session:
        try:
            for f in findings:
                finding = Finding(
                    scan_id=          scan_id,
                    title=            f.get("title", "Untitled"),
                    severity=         f.get("severity", "info"),
                    cvss_score=       f.get("cvss_score"),
                    vuln_type=        f.get("vuln_type", "unknown"),
                    url=              f.get("url", ""),
                    parameter=        f.get("parameter"),
                    payload_used=     f.get("payload_used"),
                    evidence=         f.get("evidence"),
                    description=      f.get("description"),
                    remediation=      f.get("remediation"),
                    references=       f.get("references", []),
                    is_false_positive=f.get("is_false_positive", False),
                    confirmed=        f.get("confirmed", False),
                )
                session.add(finding)
                saved += 1

            await session.commit()
            logger.debug(f"[DB] Saved {saved} findings for scan {scan_id}")
        except Exception as e:
            await session.rollback()
            logger.error(f"[DB] Failed to save findings: {e}")

    return saved


async def update_scan_status(
    scan_id: str,
    status: ScanStatus,
    error_msg: str = None
) -> None:
    """Update the scan record's status and timestamps."""
    async with AsyncSessionLocal() as session:
        try:
            scan = await session.get(Scan, scan_id)
            if scan:
                scan.status = status
                if status == ScanStatus.RUNNING:
                    scan.started_at = datetime.now(timezone.utc)
                elif status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                    scan.finished_at = datetime.now(timezone.utc)
                if error_msg:
                    scan.error_msg = error_msg
                await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"[DB] Status update failed: {e}")


            