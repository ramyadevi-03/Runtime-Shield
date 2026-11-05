import re
_SECRET_KEYS = re.compile(r"(?i)(token|secret|password|credential|api[_-]?key|authorization)")
def redact(value):
    if isinstance(value, dict): return {k: ("[REDACTED]" if _SECRET_KEYS.search(k) else redact(v)) for k,v in value.items()}
    if isinstance(value, list): return [redact(v) for v in value]
    return value
