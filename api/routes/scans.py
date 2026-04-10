from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db.database import get_session
from db.models import Scan, Target
from api.models.schemas import ScanCreate, ScanResponse
from typing import List
import uuid

router = APIRouter()


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(data: ScanCreate, db: AsyncSession = Depends(get_session)):
    target = await db.get(Target, data.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    scan = Scan(
        id=str(uuid.uuid4()),
        target_id=data.target_id,
        scan_type=data.scan_type,
        config_used={"rate_limit": data.rate_limit, "timeout": data.timeout},
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
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