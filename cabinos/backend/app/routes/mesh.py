from fastapi import APIRouter, HTTPException
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from app.config import settings
from app.crypto import canonical_bytes, decrypt_private_key
from app.database import SessionLocal
from app.models import Identity
from app.schemas import MeshSignRequest, MeshSignResponse

router = APIRouter()


@router.post("/sign", response_model=MeshSignResponse)
def mesh_sign(req: MeshSignRequest) -> MeshSignResponse:
    db = SessionLocal()
    try:
        ident = db.query(Identity).filter(Identity.id == req.identity_id).first()
        if not ident:
            raise HTTPException(status_code=404, detail="identity_not_found")

        private_key_hex = decrypt_private_key(settings.MASTER_KEY_BYTES, ident.encrypted_private_key)
        signing_key = SigningKey(private_key_hex, encoder=HexEncoder)

        envelope = {
            "did": ident.did,
            "pub": ident.public_key,
            "ts": req.ts,
            "nonce": req.nonce,
            "topic": req.topic,
            "payload": req.payload,
        }
        signature = signing_key.sign(canonical_bytes(envelope)).signature.hex()

        return MeshSignResponse(**envelope, sig=signature, sig_alg="ed25519")
    finally:
        db.close()
