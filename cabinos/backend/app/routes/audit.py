from fastapi import APIRouter, HTTPException
from sqlalchemy.exc import SQLAlchemyError

from app.audit import chain_hash
from app.database import SessionLocal
from app.models import AuditEvent
from app.schemas import AuditLogRequest, AuditLogResponse

router = APIRouter()


@router.post("/log", response_model=AuditLogResponse)
def audit_log(req: AuditLogRequest) -> AuditLogResponse:
    ts, chain = chain_hash(req.prev_hash, req.action, None)

    db = SessionLocal()
    try:
        row = AuditEvent(ts=ts, action=req.action, prev_hash=req.prev_hash, chain_hash=chain)
        db.add(row)
        db.commit()
        db.refresh(row)
        return AuditLogResponse(audit_id=row.id, ts=row.ts, prev_hash=row.prev_hash, chain_hash=row.chain_hash)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"audit_log_failed: {exc}") from exc
    finally:
        db.close()
