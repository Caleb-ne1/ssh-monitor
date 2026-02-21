#!/bin/bash
set -e

# --- Configuration ---
# GitHub username/repo/branch
USERNAME="Caleb-ne1"
REPO="ssh-monitor"
BRANCH="main"
RUN_USER="$(whoami)"
APP_NAME="ssh-monitor"
BIN_NAME="$APP_NAME"
BIN_URL="https://raw.githubusercontent.com/$USERNAME/$REPO/$BRANCH/dist/$BIN_NAME"
BIN_PATH="/usr/local/bin/$APP_NAME"

CONFIG_DIR="$HOME/.config/$APP_NAME"
SERVICE_FILE="/etc/systemd/system/$APP_NAME.service"

# Download the binary
echo "📥 Downloading $APP_NAME binary..."
sudo curl -L -o "$BIN_PATH" "$BIN_URL"
sudo chmod +x "$BIN_PATH"
echo "✅ Binary installed to $BIN_PATH"

# create config folder
if [ ! -d "$CONFIG_DIR" ]; then
    mkdir -p "$CONFIG_DIR"
    echo "📁 Created config folder at $CONFIG_DIR"
fi

# Create systemd service
echo "🔧 Setting up systemd service..."
sudo tee $SERVICE_FILE > /dev/null <<EOF
[Unit]
Description=SSH Monitor Service
After=network.target

[Service]
Type=simple
User=$RUN_USER
ExecStart=$BIN_PATH
Restart=on-failure
RestartSec=5s
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=$APP_NAME

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start service
sudo systemctl daemon-reload
sudo systemctl enable $APP_NAME.service
sudo systemctl start $APP_NAME.service

echo "✅ $APP_NAME installed and running!"
echo "📄 Config folder: $CONFIG_DIR"
echo "💡 To check logs: sudo journalctl -u $APP_NAME -f"