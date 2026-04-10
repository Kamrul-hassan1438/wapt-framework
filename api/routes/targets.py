from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db.database import get_session
from db.models import Target
from api.models.schemas import TargetCreate, TargetResponse
from typing import List

router = APIRouter()


@router.post("/", response_model=TargetResponse, status_code=201)
async def create_target(data: TargetCreate, db: AsyncSession = Depends(get_session)):
    target = Target(**data.model_dump())
    db.add(target)
    await db.flush()
    await db.refresh(target)
    return target


@router.get("/", response_model=List[TargetResponse])
async def list_targets(db: AsyncSession = Depends(get_session)):
    result = await db.execute(select(Target).where(Target.is_active == True))
    return result.scalars().all()


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: str, db: AsyncSession = Depends(get_session)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: str, db: AsyncSession = Depends(get_session)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.is_active = False  # soft delete
    return None