#!/bin/bash

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this script as root or with sudo."
    exit 1
fi

# Update the package list
echo "Updating package list..."
apt-get update -y

# Install OpenVAS (Greenbone Vulnerability Management)
echo "Installing OpenVAS (Greenbone)..."
apt-get install -y openvas

# Initial setup for OpenVAS (Greenbone)
echo "Running initial OpenVAS setup (this may take some time)..."
gvm-setup

# Check setup status
if [ $? -ne 0 ]; then
    echo "There was an issue with the initial setup of OpenVAS. Please check the output for details."
    exit 1
fi

# Start the OpenVAS services
echo "Starting OpenVAS services..."
gvm-start

# Display status of the installation
echo "Checking installation status..."
gvm-check-setup

# Get admin user credentials
ADMIN_USER="admin"
ADMIN_PASSWORD=$(sudo cat /var/lib/gvm/users/admin/password)

# Display login information
echo "OpenVAS installation is complete."
echo "You can access the Greenbone Security Assistant web interface at:"
echo "https://localhost:9392 (or https://<your-server-ip>:9392)"
echo "Login with the following credentials:"
echo "Username: $ADMIN_USER"
echo "Password: $ADMIN_PASSWORD"

echo "Please note that you should change the default password after logging in for security purposes."
