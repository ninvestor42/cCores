import hashlib
import time
from typing import Optional, Tuple


def chain_hash(prev_hash: str, payload: str, ts: Optional[int] = None) -> Tuple[int, str]:
    timestamp = int(time.time()) if ts is None else ts
    raw = f"{prev_hash}|{timestamp}|{payload}".encode("utf-8")
    return timestamp, hashlib.sha256(raw).hexdigest()
