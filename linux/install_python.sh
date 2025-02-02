#!/bin/bash

set -e

##########################
# Check for root privileges
##########################
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root (or with sudo)."
    exit 1
fi

##########################
# Distro detection and installation of Python and Nmap
##########################
if [ -f /etc/os-release ]; then
    . /etc/os-release
    distro=$ID
else
    echo "Cannot determine your Linux distribution (missing /etc/os-release)."
    exit 1
fi

echo "Detected Linux distribution: $PRETTY_NAME"

case "$distro" in
    ubuntu|debian|linuxmint)
        echo "Updating package lists..."
        apt update

        echo "Installing Python and Nmap..."
        apt install -y python3 python3-pip nmap
        ;;

    fedora)
        echo "Installing Python and Nmap on Fedora..."
        dnf install -y python3 python3-pip nmap
        ;;

    centos|rhel)
        echo "Enabling EPEL repository (if not already enabled)..."
        if ! rpm -q epel-release >/dev/null 2>&1; then
            yum install -y epel-release
        fi

        echo "Installing Python and Nmap on CentOS/RHEL..."
        yum install -y python3 python3-pip nmap
        ;;

    opensuse*|sles)
        echo "Refreshing repositories on openSUSE/SLES..."
        zypper refresh

        echo "Installing Python and Nmap on openSUSE/SLES..."
        zypper install -y python3 python3-pip nmap
        ;;

    arch)
        echo "Installing Python and Nmap on Arch Linux..."
        pacman -Sy --noconfirm python python-pip nmap
        ;;

    alpine)
        echo "Updating package index on Alpine Linux..."
        apk update

        echo "Installing Python and Nmap on Alpine Linux..."
        apk add python3 py3-pip nmap
        ;;

    *)
        echo "Unsupported or unrecognized Linux distribution: $distro"
        exit 1
        ;;
esac

echo "Python installation complete."
echo "--------------------------------"

