import secrets
from fastapi import APIRouter
from app.crypto import sha256_hex
from app.database import SessionLocal
from app.models import DaemonToken
router=APIRouter()
@router.post('/create')
def create_daemon(req:dict):
    name=req.get('name','mesh-daemon')
    token=secrets.token_urlsafe(32)
    h=sha256_hex(token)
    db=SessionLocal()
    try:
        row=DaemonToken(name=name, token_hash=h)
        db.add(row); db.commit(); db.refresh(row)
        return {'daemon_id':row.id,'name':name,'token':token}
    finally:
        db.close()
