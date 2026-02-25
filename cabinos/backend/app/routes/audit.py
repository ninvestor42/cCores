from fastapi import APIRouter, HTTPException
from app.database import SessionLocal
from app.models import AuditEvent
from app.audit import chain_hash
router=APIRouter()
@router.post('/log')
def audit_log(req:dict):
    action=req.get('action')
    prev_hash=req.get('prev_hash') or '0'*64
    if not action: raise HTTPException(400,'missing action')
    ts,ch=chain_hash(prev_hash, action, None)
    db=SessionLocal()
    try:
        row=AuditEvent(ts=ts, action=action, prev_hash=prev_hash, chain_hash=ch)
        db.add(row); db.commit(); db.refresh(row)
        return {'audit_id':row.id,'ts':ts,'prev_hash':prev_hash,'chain_hash':ch}
    except Exception as e:
        db.rollback(); raise HTTPException(400, f'audit_log_failed: {e}')
    finally:
        db.close()
