import uuid
from datetime import datetime, timedelta, timezone
from app.audit.logger import audit
from app.broker.authorization import authorize
from app.broker.delegation import Delegation
from app.broker.manifest import verify_manifest

class BrokerService:
    def __init__(self,settings,vault,opa,repo): self.s=settings; self.vault=vault; self.opa=opa; self.repo=repo
    async def provision(self,alias,value): await self.vault.put(alias,value); audit("credential_provisioned",alias=alias)
    async def delete_credential(self,alias): await self.vault.delete(alias); audit("credential_deleted",alias=alias)
    async def issue(self,identity,req):
        if not verify_manifest(req.manifest_hash,self.s.manifest_hashes):
            audit("lease_denied",agent=identity.subject,reason="manifest_invalid"); return None,"manifest_invalid"
        delegation=req.delegation_context
        if delegation:
            # The API currently has no trusted parent-lease/delegation-chain
            # store or signature verifier. Caller-supplied parent claims cannot
            # establish authority, so delegated issuance remains fail-closed.
            audit("lease_denied",agent=identity.subject,reason="delegation_invalid"); return None,"delegation_invalid"
        p=await authorize(self.opa,{"agent":identity.subject,"workload":identity.workload,"credential_alias":req.credential_alias,"tool":req.tool,"operation":req.operation,"resource":req.resource,"manifest_hash":req.manifest_hash,"delegation":delegation.model_dump(mode="json") if delegation else None,"lease_seconds":min(req.lease_seconds,self.s.lease_max_seconds)})
        if p.get("allow") is not True: audit("lease_denied",agent=identity.subject,reason=p.get("reason","policy_denied")); return None,p.get("reason","policy_denied")
        try: await self.vault.get(req.credential_alias)
        except Exception: audit("lease_denied",agent=identity.subject,reason="credential_unavailable"); return None,"credential_unavailable"
        now=datetime.now(timezone.utc); lid=str(uuid.uuid4()); seconds=min(req.lease_seconds,self.s.lease_max_seconds); exp=now+timedelta(seconds=seconds)
        self.repo.create({"id":lid,"agent":identity.subject,"workload":identity.workload,"alias":req.credential_alias,"tool":req.tool,"operation":req.operation,"resource":req.resource,"manifest_hash":req.manifest_hash,"delegation_id":delegation.delegation_id if delegation else None,"decision_ref":str(p.get("decision_id",uuid.uuid4())),"created":now.isoformat(),"expires":exp.isoformat(),"max_uses":min(req.max_uses,self.s.lease_max_uses),"uses":0,"status":"active","audience":identity.workload})
        audit("lease_issued",lease_id=lid,agent=identity.subject,alias=req.credential_alias,expires=exp.isoformat()); return {"lease_id":lid,"status":"authorized","credential_alias":req.credential_alias,"expires_at":exp,"scope":[req.operation]},None
    async def redeem(self,lid,audience):
        row,claim,reason=self.repo.claim(lid,audience)
        if reason!="ok": audit("lease_redemption_denied",lease_id=lid,reason=reason); return None,reason
        try:
            value=await self.vault.get(row['alias'])
        except Exception:
            self.repo.release(lid,claim)
            audit("lease_redemption_denied",lease_id=lid,reason="credential_unavailable")
            return None,"credential_unavailable"
        except BaseException:
            self.repo.release(lid,claim)
            raise
        if not self.repo.finalize(lid,claim):
            audit("lease_redemption_denied",lease_id=lid,reason="inactive")
            return None,"inactive"
        audit("lease_redeemed",lease_id=lid,workload=row['workload'],alias=row['alias']); return value,None
