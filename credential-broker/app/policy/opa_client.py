import httpx
from app.config import Settings
class OPAUnavailable(Exception): pass
class OPAClient:
    def __init__(self, settings: Settings): self.s=settings
    async def authorize(self, input_data: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=2) as c:
                r=await c.post(self.s.opa_url,json={"input":input_data}); r.raise_for_status(); result=r.json()["result"]
            if result is True: return {"allow":True}
            if not isinstance(result,dict) or result.get("allow") is not True: return {"allow":False,"reason":"policy_denied"}
            return result
        except Exception as e: raise OPAUnavailable from e
