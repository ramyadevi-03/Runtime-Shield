import subprocess
import json
import sys
import os
import time

# Ensure terminal standard streams handle UTF-8/emojis correctly on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def test_run_drills_tool():
    print("🚀 Starting integration test for keycloak_run_drills tool...")
    
    # Clean up telemetry database files to force fresh seeding
    import glob
    for db_file in glob.glob(os.path.join(PROJECT_DIR, "telemetry.db*")):
        try:
            os.remove(db_file)
            print(f"🧹 Removed old database file: {os.path.basename(db_file)}")
        except Exception as e:
            print(f"⚠️ Failed to remove {db_file}: {e}")
            
    # Start the bridge in a subprocess, redirecting stderr to devnull to ignore debug logs
    proc = subprocess.Popen(
        ["venv/Scripts/python.exe", "bridge.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=PROJECT_DIR,
        text=True,
        encoding="utf-8"
    )
    
    # Wait a bit for the bridge to initialize
    time.sleep(3)
    
    # Create the JSON-RPC request payload
    req = {
        "jsonrpc": "2.0",
        "id": 12345,
        "method": "tools/call",
        "params": {
            "name": "keycloak_run_drills",
            "arguments": {
                "role": "admin"
            }
        }
    }
    
    try:
        print("📨 Sending JSON-RPC request for keycloak_run_drills...")
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        
        # Read the response
        print("📖 Reading response from bridge...")
        response_line = proc.stdout.readline()
        if not response_line:
            print("❌ No response received from bridge.")
            proc.terminate()
            return False
            
        print("📥 Received response:")
        resp = json.loads(response_line)
        print(json.dumps(resp, indent=2))
        
        # Validate response structure and results
        if "error" in resp:
            print(f"❌ Bridge returned error: {resp['error']}")
            proc.terminate()
            return False
            
        result = resp.get("result", {})
        content = result.get("content", [])
        if not content:
            print("❌ Response result does not contain content.")
            proc.terminate()
            return False
            
        text = content[0].get("text", "")
        if "POLICY VERIFICATION COMPLIANCE REPORT" in text and "PASSED" in text:
            print("🟢 SUCCESS: keycloak_run_drills execution returned compliance report successfully!")
            proc.terminate()
            return True
        else:
            print("❌ Compliance report content validation failed.")
            proc.terminate()
            return False
            
    except Exception as e:
        print(f"❌ Integration test failed with exception: {e}")
        proc.terminate()
        return False

if __name__ == "__main__":
    success = test_run_drills_tool()
    sys.exit(0 if success else 1)
