from fastapi import FastAPI
from app.database import Base, engine
from app.routes import identity, daemon, mesh, audit, attest
app=FastAPI(title='CabinOS Trial Node L6')
@app.on_event('startup')
def _startup():
    Base.metadata.create_all(bind=engine)
app.include_router(identity.router, prefix='/identity')
app.include_router(daemon.router, prefix='/daemon')
app.include_router(mesh.router, prefix='/mesh')
app.include_router(audit.router, prefix='/audit')
app.include_router(attest.router, prefix='/attest')
@app.get('/')
def health():
    return {'status':'CabinOS Node Active','level':6}
