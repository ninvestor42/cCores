from fastapi import FastAPI
from app.database import Base, engine
from app.routes import identity, mesh, audit
app=FastAPI(title='CabinOS Trial Node L2')
@app.on_event('startup')
def _startup():
    Base.metadata.create_all(bind=engine)
app.include_router(identity.router, prefix='/identity')
app.include_router(mesh.router, prefix='/mesh')
app.include_router(audit.router, prefix='/audit')
@app.get('/')
def health():
    return {'status':'CabinOS Node Active','level':2}
