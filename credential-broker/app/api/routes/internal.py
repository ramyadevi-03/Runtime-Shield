from fastapi import APIRouter, Depends, Header, HTTPException
from app.security.jwt_validator import verify_token
router=APIRouter(prefix="/internal/v1",tags=["internal egress only"])
def service_dep():
    from app.main import get_service
    return get_service()
@router.post("/leases/{lease_id}/redeem")
async def redeem(lease_id:str,authorization:str|None=Header(default=None),svc=Depends(service_dep)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Authentication required")
    ident=verify_token(authorization[7:],svc.s.jwt_audience_egress,svc.s)
    if "egress" not in ident.roles or "agent" in ident.roles or "admin" in ident.roles: raise HTTPException(403,"Forbidden")
    value,error=await svc.redeem(lease_id,ident.workload)
    if error: raise HTTPException(409,"Lease cannot be redeemed")
    return {"credential":value}
