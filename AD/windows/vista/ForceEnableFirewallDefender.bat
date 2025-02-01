@echo off
echo Enabling Windows Firewall...
netsh advfirewall set allprofiles state on

echo Checking Windows Firewall status...
netsh advfirewall show allprofiles

echo Starting Windows Defender service...
sc config WinDefend start= auto
sc start WinDefend

echo Checking Windows Defender service status...
sc query WinDefend

pause
