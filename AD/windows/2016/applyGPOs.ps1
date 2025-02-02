# detects if windows server is 2012, 2016, or 2019 and applies GPOs accordingly

# Download gpos to C:\tmp\newGPOs
if (-not (Test-Path "C:\tmp")) {
    New-Item -ItemType Directory -Path "C:\tmp"
}

if (-not (Test-Path "C:\tmp\gpos.zip")) {
    Invoke-WebRequest -Uri "http://pscho.xyz/AD/windows/gpos.zip" -OutFile "C:\tmp\gpos.zip"
}

if (-not (Test-Path "C:\tmp\LGPO.exe")) {
    Invoke-WebRequest -Uri "http://pscho.xyz/AD/windows/installers/LGPO.exe" -OutFile "C:\tmp\LGPO.exe"
}

# Unzip GPOs
if (-not (Test-Path "C:\tmp\gpos")) {
    Expand-Archive -Path "C:\tmp\gpos.zip" -DestinationPath "C:\tmp\"
}

#GPO Configurations
function Import-GPOs([string]$gposdir) {
    Write-Host "Importing Group Policies from $gposdir ..." -ForegroundColor Green
    Foreach ($gpoitem in Get-ChildItem $gposdir) {
        Write-Host "Importing $gpoitem GPOs..." -ForegroundColor White
        $gpopath = "$gposdir\$gpoitem"
        #Write-Host "Importing $gpo" -ForegroundColor White
        C:\tmp\LGPO.exe /g $gpopath > $null 2>&1
        #Write-Host "Done" -ForegroundColor Green
    }
}

# detect if windows server is 2012, 2016, or 2019
$os = Get-WmiObject -Class Win32_OperatingSystem
if ($os.Version -eq "6.2.9200") {
    Write-Output "Windows Server 2012 detected."
    # apply GPOs for Windows Server 2012
    Import-GPOs -gposdir "C:\tmp\gpos\2012"
} elseif ($os.Version -eq "6.3.9600") {
    Write-Output "Windows Server 2012 R2 detected."
    # apply GPOs for Windows Server 2012 R2
    Import-GPOs -gposdir "C:\tmp\gpos\2012"
} elseif ($os.Version -eq "10.0.14393") {
    Write-Output "Windows Server 2016 detected."
    # apply GPOs for Windows Server 2016
    Import-GPOs -gposdir "C:\tmp\gpos\2016"
} elseif ($os.Version -eq "10.0.17763") {
    Write-Output "Windows Server 2019 detected."
    # apply GPOs for Windows Server 2019
    Import-GPOs -gposdir "C:\tmp\gpos\2019"
} else {
    Write-Output "Unsupported Windows version detected."
}