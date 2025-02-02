# Install .NET Framework 3.5

if (-not (Test-Path "C:\tmp\dotnetfx35.exe")) {
    Invoke-WebRequest -Uri "http://pscho.xyz/AD/windows/installers/dotnetfx35.exe" -OutFile "C:\tmp\dotnetfx35.exe"
}

Start-Process "C:\tmp\dotnetfx35.exe" -ArgumentList "/q" -Wait
try {
    Remove-Item "C:\tmp\dotnetfx35.exe"
} catch {
    Write-Output "Failed to remove .NET Framework 3.5 installer."
}
# Install PingCastle

if (-not (Test-Path "C:\tmp\ping.exe")) {
    Invoke-WebRequest -Uri "http://pscho.xyz/AD/windows/installers/oldping.exe" -OutFile "C:\tmp\ping.exe"
}