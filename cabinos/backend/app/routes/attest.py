import time
from fastapi import APIRouter, HTTPException
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from app.config import settings
from app.database import SessionLocal
from app.models import AuditKey, AuditEvent
from app.crypto import canonical_bytes, decrypt_private_key
router=APIRouter()

def _get_active_audit_key(db):
    ak=db.query(AuditKey).filter(AuditKey.is_active==1).first()
    if not ak: raise HTTPException(500,'no active audit key')
    return ak

def _sign(db, envelope:dict)->dict:
    ak=_get_active_audit_key(db)
    priv_hex=decrypt_private_key(settings.MASTER_KEY_BYTES, ak.encrypted_private_key)
    sk=SigningKey(priv_hex, encoder=HexEncoder)
    sig=sk.sign(canonical_bytes(envelope)).signature.hex()
    return {**envelope,'sig_alg':'ed25519','sig':sig,'signer_key_id':ak.key_id}

@router.post('/attest_daily')
def attest_daily(req:dict):
    day=req.get('day') or time.strftime('%Y-%m-%d', time.gmtime())
    db=SessionLocal()
    try:
        last=db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
        if not last: raise HTTPException(400,'no audit events')
        ts=int(time.time())
        envelope={'did':'audit-key','pub':_get_active_audit_key(db).public_key,'ts':ts,'nonce':f'audit-head:{day}:{ts}','topic':'audit.chain_head.daily','payload':{'day':day,'audit_chain_head':last.chain_hash,'audit_id':last.id,'ts':ts}}
        return _sign(db, envelope)
    finally:
        db.close()
