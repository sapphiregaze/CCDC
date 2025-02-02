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
# Distro detection and Ansible installation
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

        echo "Installing prerequisites..."
        apt install -y software-properties-common

        echo "Adding Ansible PPA..."
        apt-add-repository --yes --update ppa:ansible/ansible

        echo "Installing Ansible..."
        apt install -y ansible
        ;;

    fedora)
        echo "Installing Ansible on Fedora..."
        dnf install -y ansible
        ;;

    centos|rhel)
        echo "Enabling EPEL repository..."
        if ! rpm -q epel-release >/dev/null 2>&1; then
            yum install -y epel-release
        fi

        echo "Installing Ansible on CentOS/RHEL..."
        yum install -y ansible
        ;;

    opensuse*|sles)
        echo "Refreshing repositories on openSUSE/SLES..."
        zypper refresh

        echo "Installing Ansible on openSUSE/SLES..."
        zypper install -y ansible
        ;;

    arch)
        echo "Installing Ansible on Arch Linux..."
        pacman -Sy --noconfirm ansible
        ;;

    alpine)
        echo "Updating package index on Alpine Linux..."
        apk update

        echo "Installing Ansible on Alpine Linux..."
        apk add ansible
        ;;

    *)
        echo "Unsupported or unrecognized Linux distribution: $distro"
        exit 1
        ;;
esac

echo "Ansible installation complete."
echo "--------------------------------"

##########################
# SSH Key Generation using ECDSA (elliptic curve)
##########################
SSH_KEY="$HOME/.ssh/id_ecdsa"
PUB_SSH_KEY="$HOME/.ssh/id_ecdsa.pub"
if [ ! -f "$SSH_KEY" ]; then
    echo "Generating a new ECDSA SSH key at $SSH_KEY ..."
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    # -t: key type, -b: bits, -f: filename, -N: empty passphrase (adjust as needed)
    ssh-keygen -t ecdsa -b 521 -f "$SSH_KEY" -N ""
    echo "SSH key generated."
else
    echo "SSH key already exists at $SSH_KEY. Skipping key generation."
fi

