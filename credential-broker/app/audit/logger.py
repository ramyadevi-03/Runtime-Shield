import json, logging
from datetime import datetime, timezone
log=logging.getLogger("credential_broker.audit")
def audit(event, **fields):
    safe={k:v for k,v in fields.items() if k not in {"secret","token","credential","payload"}}
    log.info(json.dumps({"event":event,"at":datetime.now(timezone.utc).isoformat(),**safe},separators=(",",":")))
