<# 
.SYNOPSIS
    Patches a Windows Server 2016 domain controller against the ZeroLogon (CVE-2020-1472) vulnerability
    by installing the required OS updates and optionally configuring Netlogon enforcement mode.

.DESCRIPTION
    This script will:
    1. Check if the relevant Security Update (KB4577015 or later cumulative updates that contain the fix) is installed.
    2. If not installed, it will install the patch from Windows Update.
    3. (Optional) Enable Netlogon enforcement mode in the registry by setting the "FullSecureChannelProtection" key.

.NOTES
    Make sure to run PowerShell as Administrator (elevated).
    The script requires the PSWindowsUpdate module, which you can install via the PSGallery if not present.

    CVE-2020-1472 details: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472
#>

# --- PARAMETERS ---

param(
    [switch]$EnableEnforcementMode  # If provided, sets the Netlogon enforcement registry key
)

# --- PRELIMINARIES ---

# 1. Ensure script runs with administrative privileges
If (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script in an elevated PowerShell session (Run as Administrator)."
    Break
}

# 2. Install or import PSWindowsUpdate if needed
try {
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Host "PSWindowsUpdate module not found. Installing..."
        Install-Module PSWindowsUpdate -Force
    }
    Import-Module PSWindowsUpdate -Force
}
catch {
    Write-Error "Failed to install or import PSWindowsUpdate. Ensure you have the PSGallery repository available."
    Break
}

# --- CHECK AND INSTALL THE PATCH ---

# For Windows Server 2016, the September 2020 patch for ZeroLogon was in KB4577015 (or later cumulative updates).
# You can adjust or add more KB numbers if you're dealing with monthly cumulative updates beyond that point.
$requiredKBs = @("KB4577015")

Write-Host "Checking if any of the required KB(s) ($($requiredKBs -join ', ')) are already installed..."

# Retrieve installed updates
$installedUpdates = (Get-HotFix)

# Determine if patch is missing
$missingKBs = $requiredKBs | Where-Object { 
    $kb = $_
    -not $installedUpdates -match $kb
}

If ($missingKBs) {
    Write-Host "The following KB(s) are missing: $($missingKBs -join ', ')"
    Write-Host "Attempting to install via Windows Update..."
    
    # Enable Microsoft Update (to get all updates, not just WSUS or Windows-only)
    Set-PSWUSettings -MicrosoftUpdate $true -Confirm:$false
    
    # Install the missing KB(s)
    # Note: If the KB is included in a current rollup, you may just do a blanket "Get-WindowsUpdate -Install"
    # for the latest cumulative. Below tries specifically for the missingKBs by ID:
    Get-WindowsUpdate -KBArticleID $missingKBs -Install -AcceptAll -AutoReboot
}
else {
    Write-Host "ZeroLogon patch (or a superseding cumulative update) appears to be already installed."
}

# --- (OPTIONAL) SET NETLOGON ENFORCEMENT MODE ---

if ($EnableEnforcementMode) {
    # Netlogon Enforcement Mode registry location and key name
    $netlogonRegPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $enforcementKey   = "FullSecureChannelProtection"
    
    Write-Host "Enabling Netlogon Enforcement Mode by setting the registry key..."
    try {
        New-ItemProperty -Path $netlogonRegPath `
                         -Name $enforcementKey `
                         -Value 1 `
                         -PropertyType DWORD `
                         -Force | Out-Null
        
        Write-Host "`nNetlogon Enforcement Mode has been enabled. Registry key details:"
        Get-ItemProperty -Path $netlogonRegPath -Name $enforcementKey
    }
    catch {
        Write-Error "Could not set Netlogon enforcement registry key. Error: $_"
    }
}
else {
    Write-Host "`nNetlogon Enforcement Mode not enabled. (Use -EnableEnforcementMode switch if desired.)"
}

Write-Host "`nScript completed."
