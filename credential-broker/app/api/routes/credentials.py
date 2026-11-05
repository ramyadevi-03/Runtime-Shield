from fastapi import APIRouter, Header, HTTPException, Response
from app.api.schemas.models import ProvisionRequest,check_alias
from app.security.jwt_validator import verify_token

def build_router():
    router=APIRouter(prefix="/v1/admin/credentials",tags=["credentials"])
    def auth(authorization,svc):
        if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Authentication required")
        ident=verify_token(authorization[7:],svc.s.jwt_audience_admin,svc.s)
        if "admin" not in ident.roles or "agent" in ident.roles or "egress" in ident.roles: raise HTTPException(403,"Forbidden")
        return ident
    @router.put("/{alias}",status_code=204)
    async def provision(alias:str,body:ProvisionRequest,authorization:str|None=Header(default=None)):
        from app.main import get_service
        svc=get_service(); auth(authorization,svc)
        try: check_alias(alias); await svc.provision(alias,body.value)
        except ValueError: raise HTTPException(422,"Invalid credential alias")
        except Exception: raise HTTPException(503,"Credential backend unavailable")
        return Response(status_code=204)
    @router.delete("/{alias}",status_code=204)
    async def delete(alias:str,authorization:str|None=Header(default=None)):
        from app.main import get_service
        svc=get_service(); auth(authorization,svc)
        try: check_alias(alias); await svc.delete_credential(alias)
        except ValueError: raise HTTPException(422,"Invalid credential alias")
        except Exception: raise HTTPException(503,"Credential backend unavailable")
        return Response(status_code=204)
    return router
