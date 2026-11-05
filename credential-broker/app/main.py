import os, logging, uuid, time
from fastapi import FastAPI, Request, Header, HTTPException, Depends, Response
from fastapi.responses import JSONResponse
from threading import Lock
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.config import get_settings
from app.vault.openbao import OpenBaoClient
from app.policy.opa_client import OPAClient
from app.storage.lease_repository import LeaseRepository
from app.broker.service import BrokerService
from app.audit.logger import audit
from app.api.routes import health,credentials,leases,internal

settings=get_settings(); logging.basicConfig(level=logging.INFO)
repo=LeaseRepository(settings.database_path,settings.lease_claim_ttl_seconds); service=BrokerService(settings,OpenBaoClient(settings),OPAClient(settings),repo)
def get_service(): return service
app=FastAPI(title="Runtime Shield Credential Broker",version="0.1.0",docs_url="/docs" if settings.environment!="production" else None,openapi_url="/openapi.json" if settings.environment!="production" else None)
limiter=Limiter(key_func=get_remote_address,default_limits=["120/minute"]); app.state.limiter=limiter; app.add_exception_handler(RateLimitExceeded,_rate_limit_exceeded_handler)
_rate_lock=Lock(); _rate_state={}
@app.middleware("http")
async def correlation(request:Request,call_next):
    cid=request.headers.get("X-Request-ID") or str(uuid.uuid4()); request.state.correlation_id=cid
    peer=request.client.host if request.client else "unknown"; now=time.monotonic()
    with _rate_lock:
        start,count=_rate_state.get(peer,(now,0))
        if now-start>=60: start,count=now,0
        count+=1; _rate_state[peer]=(start,count)
    if count>120: return JSONResponse({"detail":"Rate limit exceeded","request_id":cid},status_code=429,headers={"X-Request-ID":cid})
    try: response=await call_next(request)
    except Exception: audit("request_error",request_id=cid,path=request.url.path); response=JSONResponse({"detail":"Request failed","request_id":cid},status_code=500)
    response.headers["X-Request-ID"]=cid; return response
app.include_router(health.router); app.include_router(leases.router); app.include_router(internal.router)
from app.api.routes.credentials import build_router
app.include_router(build_router())
