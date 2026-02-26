from fastapi import APIRouter, HTTPException
from app.crypto import generate_ed25519, encrypt_private_key, did_from_pubkey_hex
from app.config import settings
from app.database import SessionLocal
from app.models import Identity
router=APIRouter()
@router.post('/create')
def create_identity():
    priv,pub=generate_ed25519(); did=did_from_pubkey_hex(pub)
    enc=encrypt_private_key(settings.MASTER_KEY_BYTES, priv)
    db=SessionLocal()
    try:
        row=Identity(did=did, public_key=pub, encrypted_private_key=enc)
        db.add(row); db.commit(); db.refresh(row)
        return {'identity_id':row.id,'did':did,'public_key':pub}
    except Exception as e:
        db.rollback(); raise HTTPException(400, f'identity_create_failed: {e}')
    finally:
        db.close()
