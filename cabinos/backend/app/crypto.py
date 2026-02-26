import base64
import hashlib
import json
import os
from typing import Any, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey


def generate_ed25519() -> Tuple[str, str]:
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    private_key_hex = signing_key.encode(encoder=HexEncoder).decode("utf-8")
    public_key_hex = verify_key.encode(encoder=HexEncoder).decode("utf-8")
    return private_key_hex, public_key_hex


def did_from_pubkey_hex(pub_hex: str) -> str:
    return hashlib.sha256(pub_hex.encode("utf-8")).hexdigest()


def encrypt_private_key(master_key: bytes, private_key_hex: str) -> str:
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, private_key_hex.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_private_key(master_key: bytes, encrypted_b64: str) -> str:
    raw = base64.b64decode(encrypted_b64)
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(master_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
