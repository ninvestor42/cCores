import os,base64,hashlib,json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError

def generate_ed25519():
    sk=SigningKey.generate(); vk=sk.verify_key
    return sk.encode(encoder=HexEncoder).decode(), vk.encode(encoder=HexEncoder).decode()

def did_from_pubkey_hex(pub_hex:str)->str:
    return hashlib.sha256(pub_hex.encode()).hexdigest()

def encrypt_private_key(master_key:bytes, private_key_hex:str)->str:
    aes=AESGCM(master_key); nonce=os.urandom(12)
    ct=aes.encrypt(nonce, private_key_hex.encode(), None)
    return base64.b64encode(nonce+ct).decode()

def decrypt_private_key(master_key:bytes, encrypted_b64:str)->str:
    raw=base64.b64decode(encrypted_b64)
    nonce,ct=raw[:12],raw[12:]
    aes=AESGCM(master_key)
    return aes.decrypt(nonce, ct, None).decode()

def canonical_bytes(obj)->bytes:
    return json.dumps(obj, separators=(',',':'), sort_keys=True, ensure_ascii=False).encode()

def sha256_hex(s:str)->str:
    return hashlib.sha256(s.encode()).hexdigest()

def verify_ed25519(pub_hex:str, msg_bytes:bytes, sig_hex:str)->bool:
    try:
        vk=VerifyKey(bytes.fromhex(pub_hex))
        vk.verify(msg_bytes, bytes.fromhex(sig_hex))
        return True
    except (BadSignatureError,ValueError):
        return False
