import httpx
from app.config import Settings

class OpenBaoClient:
    def __init__(self, settings: Settings): self.s=settings; self._token=None
    async def _ensure_token(self):
        if self._token: return
        if not (self.s.openbao_role_id and self.s.openbao_secret_id): raise RuntimeError("OpenBao authentication is not configured")
        async with httpx.AsyncClient(timeout=5) as c:
            r=await c.post(f"{self.s.openbao_addr}/v1/auth/approle/login",json={"role_id":self.s.openbao_role_id,"secret_id":self.s.openbao_secret_id}); r.raise_for_status(); self._token=r.json()["auth"]["client_token"]
    async def _request(self, method, path, **kwargs):
        await self._ensure_token()
        async with httpx.AsyncClient(timeout=5) as c:
            r=await c.request(method,f"{self.s.openbao_addr}/v1/{path}",headers={"X-Vault-Token":self._token},**kwargs)
            if r.status_code == 403 and self.s.openbao_role_id and self.s.openbao_secret_id:
                self._token = None
                await self._ensure_token()
                r=await c.request(method,f"{self.s.openbao_addr}/v1/{path}",headers={"X-Vault-Token":self._token},**kwargs)
        if r.status_code == 404 and method == "DELETE": return
        r.raise_for_status(); return r
    def _path(self, alias): return f"{self.s.openbao_mount}/data/credentials/{alias}"
    async def put(self, alias, value): await self._request("POST",self._path(alias),json={"data":value})
    async def get(self, alias): return (await self._request("GET",self._path(alias))).json()["data"]["data"]
    async def delete(self, alias): await self._request("DELETE",self._path(alias))
