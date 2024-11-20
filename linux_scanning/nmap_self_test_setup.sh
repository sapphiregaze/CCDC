#!/bin/bash

# Check if Nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "Nmap is not installed. Installing Nmap..."
    sudo apt-get update && sudo apt-get install -y nmap
fi

# Directory for Nmap scripts (you can customize this path)
SCRIPT_DIR="/usr/share/nmap/scripts"

# Download nmap-vulners if it doesn't exist
if [ ! -f "$SCRIPT_DIR/nmap-vulners.nse" ]; then
    echo "Downloading nmap-vulners script..."
    sudo wget -O "$SCRIPT_DIR/nmap-vulners.nse" https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/nmap-vulners.nse
    sudo nmap --script-updatedb
fi

TARGET="127.0.0.1"

# Run Nmap with the specified scripts
echo "Running Nmap scan with vulners, vuln, banner, and ftp-vsftpd-backdoor scripts..."
sudo nmap -sV --script vulners,vuln,banner,ftp-vsftpd-backdoor "$TARGET"
