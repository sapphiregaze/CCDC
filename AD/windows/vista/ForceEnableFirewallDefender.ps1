# Enable Windows Firewall
Write-Output "Enabling Windows Firewall..."
Start-Process -FilePath "netsh" -ArgumentList "advfirewall set allprofiles state on" -NoNewWindow -Wait

# Verify Windows Firewall status
Write-Output "Checking Windows Firewall status..."
Start-Process -FilePath "netsh" -ArgumentList "advfirewall show allprofiles" -NoNewWindow -Wait

# Enable Windows Defender service
Write-Output "Starting Windows Defender service..."
Start-Service -Name "WinDefend"

# Set Windows Defender to start automatically
Write-Output "Setting Windows Defender to start automatically..."
Set-Service -Name "WinDefend" -StartupType Automatic

# Verify Windows Defender status
Write-Output "Checking Windows Defender service status..."
Get-Service -Name "WinDefend"
