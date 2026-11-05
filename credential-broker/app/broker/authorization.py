from app.policy.opa_client import OPAUnavailable
async def authorize(opa, data):
    try: return await opa.authorize(data)
    except OPAUnavailable: return {"allow":False,"reason":"policy_unavailable"}
