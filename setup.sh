#!/bin/bash
set -e

# Configuration
APP_NAME="gemini-api-proxy"
APP_DIR="/opt/$APP_NAME"
SERVICE_NAME="$APP_NAME.service"
REPO_URL="https://github.com/IT-BAER/gemini-api-proxy.git"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== Gemini API Proxy Setup ===${NC}"

# Check for root
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}Please run as root (sudo ./setup.sh)${NC}"
  exit 1
fi

# Install dependencies
echo -e "${GREEN}Installing system dependencies...${NC}"
apt-get update
apt-get install -y python3 python3-venv python3-pip git

# Create directory
if [ ! -d "$APP_DIR" ]; then
    echo -e "${GREEN}Creating directory $APP_DIR...${NC}"
    mkdir -p "$APP_DIR"
    # Assuming script is run from the repo source, copy files
    cp -r * "$APP_DIR/"
else
    echo -e "${GREEN}Directory exists. Updating files...${NC}"
    cp -r * "$APP_DIR/"
fi

# Setup Virtual Environment
echo -e "${GREEN}Setting up Python environment...${NC}"
cd "$APP_DIR"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Install requirements
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# Setup Service
echo -e "${GREEN}Installing systemd service...${NC}"
cp "$APP_NAME.service" "/etc/systemd/system/$SERVICE_NAME"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo -e "${GREEN}=== Setup Complete! ===${NC}"
echo "Service status:"
systemctl status "$SERVICE_NAME" --no-pager
echo ""
echo "Manage service with:"
echo "  sudo systemctl start/stop/restart $APP_NAME"
echo "  sudo journalctl -u $APP_NAME -f"
echo ""
echo "Setup auth at: http://localhost:8081/setup"
