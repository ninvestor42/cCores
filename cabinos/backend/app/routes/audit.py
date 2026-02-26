import time
from fastapi import APIRouter, HTTPException
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from app.config import settings
from app.database import SessionLocal
from app.models import AuditEvent, AuditKey
from app.audit import chain_hash
from app.crypto import canonical_bytes, decrypt_private_key, generate_ed25519, encrypt_private_key
router=APIRouter()

def _get_active_audit_key(db):
    ak=db.query(AuditKey).filter(AuditKey.is_active==1).first()
    if not ak: raise HTTPException(500,'no active audit key')
    return ak

def _sign_with_audit_key(db, msg:dict)->tuple[str,str]:
    ak=_get_active_audit_key(db)
    priv_hex=decrypt_private_key(settings.MASTER_KEY_BYTES, ak.encrypted_private_key)
    sk=SigningKey(priv_hex, encoder=HexEncoder)
    sig=sk.sign(canonical_bytes(msg)).signature.hex()
    return ak.key_id, sig

@router.post('/init_key')
def init_audit_key():
    priv,pub=generate_ed25519(); enc=encrypt_private_key(settings.MASTER_KEY_BYTES, priv)
    db=SessionLocal()
    try:
        db.query(AuditKey).update({AuditKey.is_active:0})
        ak=AuditKey(key_id='active', public_key=pub, encrypted_private_key=enc, is_active=1)
        db.add(ak); db.commit(); db.refresh(ak)
        return {'audit_key_id':ak.key_id,'public_key':pub}
    finally:
        db.close()

@router.post('/rotate_key')
def rotate_key(req:dict):
    new_id=req.get('new_key_id') or f'k{int(time.time())}'
    priv,pub=generate_ed25519(); enc=encrypt_private_key(settings.MASTER_KEY_BYTES, priv)
    db=SessionLocal()
    try:
        old=_get_active_audit_key(db)
        payload=f'key_rotation: {old.key_id}->{new_id} pub={pub}'
        prev=db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
        prev_hash=(prev.chain_hash if prev else '0'*64)
        ts,ch=chain_hash(prev_hash, payload, None)
        msg={'ts':ts,'action':payload,'prev_hash':prev_hash,'chain_hash':ch}
        signer_id,sig=_sign_with_audit_key(db, msg)
        ev=AuditEvent(ts=ts, action=payload, prev_hash=prev_hash, chain_hash=ch, signer_key_id=signer_id, sig=sig)
        db.add(ev)
        old.is_active=0
        nk=AuditKey(key_id=new_id, public_key=pub, encrypted_private_key=enc, is_active=1)
        db.add(nk)
        db.commit(); db.refresh(nk)
        return {'rotated':True,'new_key_id':new_id,'new_public_key':pub,'rotation_event_chain_hash':ch}
    finally:
        db.close()

@router.post('/log')
def audit_log(req:dict):
    action=req.get('action')
    if not action: raise HTTPException(400,'missing action')
    db=SessionLocal()
    try:
        prev=db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
        prev_hash=(prev.chain_hash if prev else '0'*64)
        ts,ch=chain_hash(prev_hash, action, None)
        msg={'ts':ts,'action':action,'prev_hash':prev_hash,'chain_hash':ch}
        signer_id,sig=_sign_with_audit_key(db, msg)
        row=AuditEvent(ts=ts, action=action, prev_hash=prev_hash, chain_hash=ch, signer_key_id=signer_id, sig=sig)
        db.add(row); db.commit(); db.refresh(row)
        return {'audit_id':row.id,'ts':ts,'prev_hash':prev_hash,'chain_hash':ch,'signer_key_id':signer_id,'sig':sig}
    finally:
        db.close()

@router.get('/head')
def audit_head():
    db=SessionLocal()
    try:
        last=db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
        if not last: return {'head':None}
        return {'head':{'audit_id':last.id,'ts':last.ts,'chain_hash':last.chain_hash,'prev_hash':last.prev_hash,'signer_key_id':last.signer_key_id,'sig':last.sig}}
    finally:
        db.close()
