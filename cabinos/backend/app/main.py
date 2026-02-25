import base64
import hashlib
import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from pydantic import BaseModel

app = FastAPI(title="CabinOS API")


def _build_aesgcm(master_key: str) -> AESGCM:
    """Derive a stable 32-byte key from MASTER_KEY using SHA-256."""
    derived_key = hashlib.sha256(master_key.encode("utf-8")).digest()
    return AESGCM(derived_key)


def generate_identity() -> Tuple[str, str]:
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    private_key_hex = signing_key.encode(encoder=HexEncoder).decode("utf-8")
    public_key_hex = verify_key.encode(encoder=HexEncoder).decode("utf-8")
    return private_key_hex, public_key_hex


def encrypt_private_key(private_key_hex: str, master_key: str) -> str:
    aesgcm = _build_aesgcm(master_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, private_key_hex.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


class HealthResponse(BaseModel):
    status: str


class IdentityResponse(BaseModel):
    public_key: str
    encrypted_private: str


@app.get("/", response_model=HealthResponse)
def root() -> HealthResponse:
    return HealthResponse(status="CabinOS Node Active")


@app.post("/identity/create", response_model=IdentityResponse)
def create_identity() -> IdentityResponse:
    master_key = os.environ.get("MASTER_KEY", "supersecret_master_key")
    private_key, public_key = generate_identity()
    encrypted_private = encrypt_private_key(private_key, master_key)
    return IdentityResponse(public_key=public_key, encrypted_private=encrypted_private)
