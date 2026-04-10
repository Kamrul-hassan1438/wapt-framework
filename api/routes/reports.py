from fastapi import APIRouter
router = APIRouter()

@router.get("/")
async def list_reports():
    return {"message": "Report endpoints coming in Phase 4"}