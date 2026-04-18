from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db.database import get_session
from db.models import Scan, Target, ScanType, ScanStatus
from api.models.schemas import ScanCreate, ScanResponse
from typing import List, Optional
import uuid
import asyncio
from pydantic import BaseModel, HttpUrl

router = APIRouter()


class ScanRunRequest(BaseModel):
    """Request model for starting a scan from URL."""
    url: str
    scan_type: str = "full"
    rate_limit: Optional[int] = None
    timeout: Optional[int] = None


async def _execute_scan(scan_id: str, target_url: str, scan_type: str, rate_limit: Optional[int], timeout: Optional[int]):
    """Background task to execute the scan."""
    from core.engine import ScanEngine, ReconPipeline, ScannerPipeline, VulnPipeline
    from core.config import settings
    from db.database import AsyncSessionLocal
    from modules.vulns.auth import AuthTesterModule
    from datetime import datetime, timezone
    
    try:
        # Update scan status to running
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.now(timezone.utc)
                await session.commit()
        
        # Module routing
        module_map = {
            "recon":  ReconPipeline.get_modules(),
            "scan":   ScannerPipeline.get_modules(),
            "full":   VulnPipeline.get_full_pipeline(),
            "auth":   [AuthTesterModule],
            "vuln":   VulnPipeline.get_modules(),
        }
        modules = module_map.get(scan_type, ReconPipeline.get_modules())
        
        # Run the scan
        async with ScanEngine(
            target_url=target_url,
            scan_id=scan_id,
            scan_type=ScanType(scan_type),
            rate_limit=rate_limit,
            timeout=timeout,
            modules=modules,
            stealth_mode="normal",
        ) as engine:
            summary = await engine.run()
        
        # Update scan status to completed
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.finished_at = datetime.now(timezone.utc)
                scan.error_msg = None
                await session.commit()
    
    except Exception as e:
        import traceback
        from loguru import logger
        logger.error(f"Scan {scan_id} failed: {str(e)}\n{traceback.format_exc()}")
        
        # Update scan status to failed
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.finished_at = datetime.now(timezone.utc)
                scan.error_msg = str(e)
                await session.commit()


@router.post("/run", response_model=ScanResponse, status_code=202)
async def run_scan(
    request: ScanRunRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_session)
):
    """
    Start a new scan from a URL.
    
    Returns immediately with scan ID (202 Accepted).
    The scan runs in the background.
    
    Example:
    ```json
    {
      "url": "https://elms.uiu.ac.bd",
      "scan_type": "full",
      "rate_limit": 10,
      "timeout": 30
    }
    ```
    """
    # Create or get target
    result = await db.execute(select(Target).where(Target.url == request.url))
    target = result.scalars().first()
    
    if not target:
        target = Target(
            name=request.url.split("//")[1].split("/")[0],  # Extract domain
            url=request.url.rstrip("/")
        )
        db.add(target)
        await db.flush()
    
    # Create scan record
    scan = Scan(
        id=str(uuid.uuid4()),
        target_id=target.id,
        scan_type=ScanType(request.scan_type),
        status=ScanStatus.PENDING,
        config_used={"rate_limit": request.rate_limit, "timeout": request.timeout},
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    # Queue background task to run scan
    background_tasks.add_task(
        _execute_scan,
        scan.id,
        request.url,
        request.scan_type,
        request.rate_limit,
        request.timeout
    )
    
    return scan


@router.post("/", response_model=ScanResponse, status_code=202)
async def create_scan(
    data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_session)
):
    """Create and immediately execute a scan for a target."""
    target = await db.get(Target, data.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    scan = Scan(
        id=str(uuid.uuid4()),
        target_id=data.target_id,
        scan_type=data.scan_type,
        status=ScanStatus.PENDING,
        config_used={"rate_limit": data.rate_limit, "timeout": data.timeout},
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    # Queue background task to run scan
    background_tasks.add_task(
        _execute_scan,
        scan.id,
        target.url,
        data.scan_type.value,
        data.rate_limit,
        data.timeout
    )
    
    return scan


@router.get("/", response_model=List[ScanResponse])
async def list_scans(db: AsyncSession = Depends(get_session)):
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_session)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

from db.models import Finding

@router.get("/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    db: AsyncSession = Depends(get_session)
):
    """Get all findings for a scan, sorted by severity."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.severity)
    )
    findings = result.scalars().all()

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    finding_list = [
        {
            "id":           f.id,
            "title":        f.title,
            "severity":     f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "cvss_score":   f.cvss_score,
            "vuln_type":    f.vuln_type,
            "url":          f.url,
            "parameter":    f.parameter,
            "confirmed":    f.confirmed,
            "description":  f.description,
            "remediation":  f.remediation,
        }
        for f in findings
    ]
    finding_list.sort(key=lambda x: sev_order.get(x["severity"], 99))
    return {"findings": finding_list, "total": len(finding_list)}

