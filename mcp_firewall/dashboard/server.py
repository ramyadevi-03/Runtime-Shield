import uvicorn
import threading
from .app import app

def start_dashboard(port: int = 9090, host: str = "0.0.0.0"):
    """Starts the dashboard server in a background thread."""
    def run():
        uvicorn.run(app, host=host, port=port, log_level="error")
    
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread
