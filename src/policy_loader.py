import logging

logger = logging.getLogger(__name__)

def init_policies():
    logger.info("Initializing ARD policies (mock loader)")

def search(query: str = ""):
    return []

async def auto_refresh_catalog():
    pass
