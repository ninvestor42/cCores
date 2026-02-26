from fastapi import APIRouter, HTTPException
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings
from app.crypto import did_from_pubkey_hex, encrypt_private_key, generate_ed25519
from app.database import SessionLocal
from app.models import Identity
from app.schemas import IdentityCreateResponse

router = APIRouter()


@router.post("/create", response_model=IdentityCreateResponse)
def create_identity() -> IdentityCreateResponse:
    private_key, public_key = generate_ed25519()
    did = did_from_pubkey_hex(public_key)
    encrypted_private_key = encrypt_private_key(settings.MASTER_KEY_BYTES, private_key)

    db = SessionLocal()
    try:
        row = Identity(did=did, public_key=public_key, encrypted_private_key=encrypted_private_key)
        db.add(row)
        db.commit()
        db.refresh(row)
        return IdentityCreateResponse(identity_id=row.id, did=row.did, public_key=row.public_key)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"identity_create_failed: {exc}") from exc
    finally:
        db.close()
