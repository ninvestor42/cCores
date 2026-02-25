from fastapi import APIRouter, HTTPException
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from app.crypto import decrypt_private_key, canonical_bytes
from app.config import settings
from app.database import SessionLocal
from app.models import Identity
router=APIRouter()
@router.post('/sign')
def mesh_sign(req:dict):
    identity_id=req.get('identity_id')
    if not identity_id: raise HTTPException(400,'missing identity_id')
    topic=req.get('topic','telemetry.daily')
    ts=int(req.get('ts') or 0)
    nonce=str(req.get('nonce') or '')
    payload=req.get('payload')
    if not ts or not nonce or payload is None: raise HTTPException(400,'missing ts/nonce/payload')
    db=SessionLocal()
    try:
        ident=db.query(Identity).filter(Identity.id==int(identity_id)).first()
        if not ident: raise HTTPException(404,'identity_not_found')
        priv_hex=decrypt_private_key(settings.MASTER_KEY_BYTES, ident.encrypted_private_key)
        sk=SigningKey(priv_hex, encoder=HexEncoder)
        envelope={'did':ident.did,'pub':ident.public_key,'ts':ts,'nonce':nonce,'topic':topic,'payload':payload}
        sig=sk.sign(canonical_bytes(envelope)).signature.hex()
        return {**envelope,'sig':sig,'sig_alg':'ed25519'}
    finally:
        db.close()
