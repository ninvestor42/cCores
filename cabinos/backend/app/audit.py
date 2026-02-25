import time,hashlib

def chain_hash(prev_hash:str, payload:str, ts:int|None=None)->tuple[int,str]:
    if ts is None: ts=int(time.time())
    raw=f'{prev_hash}|{ts}|{payload}'.encode()
    return ts, hashlib.sha256(raw).hexdigest()
