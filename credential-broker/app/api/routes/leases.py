from fastapi import APIRouter, Depends, Header, HTTPException
from app.api.schemas.models import LeaseRequest
from app.security.jwt_validator import verify_token
from app.audit.logger import audit
router=APIRouter(prefix="/v1",tags=["leases"])
def service_dep():
    from app.main import get_service
    return get_service()
@router.post("/leases")
async def create_lease(body:LeaseRequest,authorization:str|None=Header(default=None),svc=Depends(service_dep)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Authentication required")
    identity=verify_token(authorization[7:],svc.s.jwt_audience_agent,svc.s)
    if "agent" not in identity.roles: raise HTTPException(403,"Forbidden")
    result,error=await svc.issue(identity,body)
    if error: raise HTTPException(403,"Lease request denied")
    return result
@router.delete("/leases/{lease_id}")
def revoke(lease_id:str,authorization:str|None=Header(default=None),svc=Depends(service_dep)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Authentication required")
    ident=verify_token(authorization[7:],svc.s.jwt_audience_agent,svc.s)
    if "agent" not in ident.roles: raise HTTPException(403,"Forbidden")
    row=svc.repo.get(lease_id)
    if not row: raise HTTPException(404,"Lease not found")
    if row['agent']!=ident.subject: raise HTTPException(403,"Forbidden")
    status=svc.repo.revoke(lease_id); audit("lease_revoked",lease_id=lease_id,agent=ident.subject,status=status)
    return {"lease_id":lease_id,"status":status}
