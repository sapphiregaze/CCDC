<#
.SYNOPSIS
    Installs PingCastle on Windows Server 2016 by downloading the latest release and extracting it.

.DESCRIPTION
    1. Verifies that the script is running with Administrator privileges.
    2. Creates a destination folder (e.g. C:\Tools\PingCastle).
    3. Downloads the PingCastle ZIP from the official site (or a mirror).
    4. Extracts the content of the ZIP into the destination.
    5. (Optional) Adds the PingCastle folder to the PATH environment variable (machine-level).
#>
# 1. Check for Administrator privileges
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script in an elevated PowerShell session (Run as Administrator)."
    return
}

if (-not (Test-Path -Path 'C:\tmp')) {
    Write-Host "Creating C:\tmp directory"
    New-Item -ItemType Directory -Path 'C:\tmp' | Out-Null
}

# 2. Create the destination directory if it does not exist
if (-not (Test-Path -Path 'C:\tmp\PingCastle')) {
    Write-Host "Creating directory: 'C:\tmp\PingCastle'"
    New-Item -ItemType Directory -Path 'C:\tmp\PingCastle' | Out-Null
} else {
    Write-Host "Destination directory already exists: 'C:\tmp\PingCastle'"
}

# 3. Download PingCastle ZIP
$downloadUrl = "https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip"

Write-Host "Downloading PingCastle from $downloadUrl ..."
$zipFilePath = Join-Path -Path $env:TEMP -ChildPath $pingCastleZipName

try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFilePath
    Write-Host "Download completed. Saved to $zipFilePath"
}
catch {
    Write-Error "Failed to download PingCastle from $downloadUrl. $($_.Exception.Message)"
    return
}

# 4. Extract the PingCastle ZIP into the destination folder
Write-Host "Extracting PingCastle to $DestinationPath ..."
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFilePath, $DestinationPath)
    Write-Host "Extraction completed."
}
catch {
    Write-Error "Failed to extract $zipFilePath. $($_.Exception.Message)"
    return
}

Write-Host "Adding $DestinationPath to the system PATH ..."
$oldPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
if ($oldPath -notlike "*$DestinationPath*") {
    $newPath = $oldPath + ";" + $DestinationPath
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    Write-Host "Added to PATH. (You may need to restart shells or sign out/in for this to take effect.)"
}
else {
    Write-Host "PingCastle path is already in PATH. No change made."
}

# Cleanup: Remove the ZIP file after extraction (optional)
Write-Host "Removing the downloaded ZIP file..."
Remove-Item $zipFilePath -Force

Write-Host "`nPingCastle installation complete."
Write-Host "You can run PingCastle by navigating to $DestinationPath and executing PingCastle.exe."
