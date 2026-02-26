import time
from fastapi import APIRouter, HTTPException, Depends
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from sqlalchemy.exc import IntegrityError
from app.crypto import decrypt_private_key, canonical_bytes, verify_ed25519
from app.config import settings
from app.database import SessionLocal
from app.models import Identity, Peer, ReplayNonce, AuditKey, AuditEvent
from app.redis_client import r
from app.auth import require_daemon_token
from app.audit import chain_hash
router=APIRouter()

def _apply_trust_decay(peer:Peer, now:int):
    if peer.last_seen_ts and peer.last_seen_ts < now:
        dt=now-peer.last_seen_ts
        hours=dt/3600.0
        peer.trust=max(peer.trust - settings.TRUST_DECAY_PER_HOUR*hours, -100.0)
    peer.last_seen_ts=now

def _update_status(peer:Peer):
    if peer.trust < settings.TRUST_QUARANTINE_BELOW:
        peer.status='quarantine'
    elif peer.status=='quarantine' and peer.trust >= settings.TRUST_UNQUARANTINE_AT:
        peer.status='active'

def _get_active_audit_key(db):
    ak=db.query(AuditKey).filter(AuditKey.is_active==1).first()
    if not ak: raise HTTPException(500,'no active audit key')
    return ak

def _sign_with_audit_key(db, msg:dict)->tuple[str,str,str]:
    ak=_get_active_audit_key(db)
    priv_hex=decrypt_private_key(settings.MASTER_KEY_BYTES, ak.encrypted_private_key)
    sk=SigningKey(priv_hex, encoder=HexEncoder)
    sig=sk.sign(canonical_bytes(msg)).signature.hex()
    return ak.key_id, ak.public_key, sig

def _append_audit_event(db, action:str)->AuditEvent:
    prev=db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    prev_hash=(prev.chain_hash if prev else '0'*64)
    ts,ch=chain_hash(prev_hash, action, None)
    msg={'ts':ts,'action':action,'prev_hash':prev_hash,'chain_hash':ch}
    signer_id,_,sig=_sign_with_audit_key(db, msg)
    row=AuditEvent(ts=ts, action=action, prev_hash=prev_hash, chain_hash=ch, signer_key_id=signer_id, sig=sig)
    db.add(row); db.commit(); db.refresh(row)
    return row

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

@router.post('/ingest')
def mesh_ingest(envelope:dict, daemon=Depends(require_daemon_token)):
    ts=int(envelope.get('ts') or 0); now=int(time.time())
    if not ts: raise HTTPException(400,'missing ts')
    if abs(now-ts)>settings.SKEW_SECONDS: raise HTTPException(400,'timestamp skew')
    did=str(envelope.get('did') or '')
    nonce=str(envelope.get('nonce') or '')
    pub=str(envelope.get('pub') or '')
    sig_hex=str(envelope.get('sig') or '')
    topic=str(envelope.get('topic') or '')
    payload=envelope.get('payload')
    if not did or not nonce or not pub or not sig_hex or payload is None: raise HTTPException(400,'missing fields')
    rkey=f'replay:{did}:{nonce}'
    if not r.set(rkey,'1',nx=True,ex=settings.REPLAY_TTL_SECONDS):
        raise HTTPException(409,'replay detected (redis)')
    db=SessionLocal()
    try:
        db.add(ReplayNonce(did=did, nonce=nonce, ts=ts))
        try:
            db.commit()
        except IntegrityError:
            db.rollback(); raise HTTPException(409,'replay detected (db)')
        unsigned={'did':did,'pub':pub,'ts':ts,'nonce':nonce,'topic':topic,'payload':payload}
        ok=verify_ed25519(pub, canonical_bytes(unsigned), sig_hex)
        peer=db.query(Peer).filter(Peer.did==did).first()
        if not peer:
            peer=Peer(did=did, trust=0.0, status='active', last_seen_ts=0)
            db.add(peer); db.commit(); db.refresh(peer)
        _apply_trust_decay(peer, now)
        if ok:
            peer.trust=min(peer.trust+1.0, 100.0)
        else:
            peer.trust=max(peer.trust-5.0, -100.0)
        _update_status(peer)
        db.add(peer); db.commit(); db.refresh(peer)
        if peer.status=='banned': raise HTTPException(403,'peer banned')
        if peer.status=='quarantine': raise HTTPException(403,'peer quarantined')
        if not ok: raise HTTPException(400,'bad signature')
        return {'ingested':True,'peer':{'did':peer.did,'trust':peer.trust,'status':peer.status,'last_seen_ts':peer.last_seen_ts},'by_daemon':daemon['daemon_name']}
    finally:
        db.close()

@router.get('/peers')
def list_peers(limit:int=50):
    db=SessionLocal()
    try:
        rows=db.query(Peer).order_by(Peer.trust.desc()).limit(limit).all()
        return {'peers':[{'did':p.did,'trust':p.trust,'status':p.status,'last_seen_ts':p.last_seen_ts} for p in rows]}
    finally:
        db.close()

@router.post('/peers/{did}/action')
def peer_action(did:str, req:dict):
    action=req.get('action')
    delta=float(req.get('delta') or 0.0)
    op=req.get('op') or 'operator'
    reason=req.get('reason') or ''
    now=int(time.time())
    db=SessionLocal()
    try:
        p=db.query(Peer).filter(Peer.did==did).first()
        if not p: raise HTTPException(404,'peer not found')
        if action=='ban': p.status='banned'; p.trust=-100.0
        elif action=='quarantine': p.status='quarantine'
        elif action=='unquarantine': p.status='active'
        elif action=='adjust': p.trust=max(min(p.trust+delta,100.0),-100.0)
        else: raise HTTPException(400,'invalid action')
        db.add(p); db.commit(); db.refresh(p)
        ev=_append_audit_event(db, f'peer_action:{action} did={did} delta={delta} by={op} reason={reason}')
        envelope={'did':'audit-key','pub':_get_active_audit_key(db).public_key,'ts':now,'nonce':f'ops:{did}:{now}','topic':'ops.peer.action','payload':{'target_did':did,'action':action,'delta':delta,'reason':reason,'operator':op,'peer_status':p.status,'peer_trust':p.trust,'audit_chain_hash':ev.chain_hash}}
        signer_id,_,sig=_sign_with_audit_key(db, envelope)
        ops={**envelope,'sig_alg':'ed25519','sig':sig,'signer_key_id':signer_id}
        return {'peer':{'did':p.did,'trust':p.trust,'status':p.status,'last_seen_ts':p.last_seen_ts},'audit_event':{'id':ev.id,'chain_hash':ev.chain_hash},'ops_envelope':ops}
    finally:
        db.close()
