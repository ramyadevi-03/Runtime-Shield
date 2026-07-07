#!/bin/bash

# =====================================================================
# RUNTIME SHIELD & DVLA INTEGRATED DEMO LAUNCHER
# =====================================================================

# Color helpers
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}🛡️  Runtime Shield & DVLA Bot Integration Demo Launcher 🛡️${NC}"
echo -e "${BLUE}======================================================${NC}"

# Find absolute script path
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Clean any existing background jobs on SIGINT
cleanup() {
    echo -e "\n${YELLOW}🛑 Shutting down servers gracefully...${NC}"
    if [ ! -z "$BRIDGE_PID" ]; then
        echo "Killing Bridge Proxy ($BRIDGE_PID)..."
        kill -9 "$BRIDGE_PID" 2>/dev/null
    fi
    if [ ! -z "$STREAMLIT_PID" ]; then
        echo "Killing Streamlit Chatbot ($STREAMLIT_PID)..."
        kill -9 "$STREAMLIT_PID" 2>/dev/null
    fi
    echo -e "${GREEN}✨ Shutdown complete. Have a secure day!${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM

echo -e "${YELLOW}🧹 Cleaning up old processes and logs for a fresh start...${NC}"
# Kill any ghost processes that might be lingering
pkill -f "bridge.py" 2>/dev/null
pkill -f "streamlit run main.py" 2>/dev/null

# Remove old telemetry database to ensure fresh dashboard
rm -f telemetry.db*
sleep 1

# 1. Start Runtime Shield Bridge
echo -e "${GREEN}🚀 Starting Runtime Shield Bridge & Live Dashboard...${NC}"
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo -e "${RED}⚠️ Global Virtual Environment 'venv' not found. Trying global python...${NC}"
fi

# Run bridge.py in the background
# Direct all logs to bridge_demo.log
python bridge.py > bridge_demo.log 2>&1 &
BRIDGE_PID=$!
echo -e "${GREEN}✅ Bridge process launched (PID: $BRIDGE_PID). Logging to bridge_demo.log.${NC}"

# Wait for the FastAPI server to initialize
echo "Waiting for proxy to start on port 5001..."
sleep 4

# 2. Start Damn Vulnerable LLM Agent Chatbot
echo -e "${GREEN}🚀 Starting Damn Vulnerable LLM Agent (DVLA) Streamlit app...${NC}"
cd damn-vulnerable-llm-agent
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo -e "${RED}⚠️ Chatbot Local Virtual Environment 'venv' not found in subfolder!${NC}"
fi

# Run streamlit
streamlit run main.py --server.port 8501 > streamlit_demo.log 2>&1 &
STREAMLIT_PID=$!
echo -e "${GREEN}✅ Streamlit chatbot launched (PID: $STREAMLIT_PID).${NC}"

# 3. Open Browser Tabs
echo -e "${BLUE}🌐 Opening browser interfaces...${NC}"
sleep 2

# Check OS and open browser
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "http://localhost:9090" # Shield Dashboard
    open "http://localhost:8501" # Chatbot Interface
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open "http://localhost:9090" 2>/dev/null
    xdg-open "http://localhost:8501" 2>/dev/null
else
    echo -e "${YELLOW}👉 Please open your browser manually:${NC}"
    echo -e "   - Shield Live Dashboard: ${BLUE}http://localhost:9090${NC}"
    echo -e "   - Secured Banking Bot:   ${BLUE}http://localhost:8501${NC}"
fi

echo -e "${YELLOW}======================================================${NC}"
echo -e "🎉 Demo is running live! Press ${RED}Ctrl+C${NC} to stop both servers."
echo -e "${YELLOW}======================================================${NC}"

# Keep the script running to wait for SIGINT
while true; do
    sleep 1
done
