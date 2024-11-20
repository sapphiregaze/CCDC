#!/bin/bash

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this script as root or with sudo."
    exit 1
fi

# Install Lynis
echo "Installing Lynis..."
if ! command -v lynis &> /dev/null; then
    # Update package list
    apt-get update -y

    # Install Lynis
    apt-get install -y lynis
else
    echo "Lynis is already installed."
fi

# Perform a system scan with Lynis
echo "Running a Lynis security scan..."
lynis audit system > /var/log/lynis_scan.log

# Display the location of the scan report
echo "Lynis scan completed."
echo "The scan results are stored in /var/log/lynis_scan.log"
echo "For more detailed results, you can check the Lynis report files typically found in /var/log/lynis/."

