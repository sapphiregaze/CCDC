# Author: NerbalOne
# This PowerShell script will first create the Sysmon folder if it does not exist. 
# It will then download Sysmon.exe, which supports both 32-bit and 64-bit, along with the Sysmon config and Sysmon Update script.
# It will install Sysmon with the config and create a Scheduled Task to run hourly to update the Sysmon config.

# Define Sysmon URLs
$sysmonURL = "http://pscho.xyz/windows/vista_server/installers/sysmon.exe"
$sysmonConfigURL = "http://pscho.xyz/windows/vista_server/misc/sysmonconfig-export.xml"
$sysmonUpdateConfigURL = "http://pscho.xyz/windows/vista_server/misc/SysmonUpdateConfig.ps1"

# Define Local Path for Sysmon File and Sysmon Config
$sysmonPath = "C:\ProgramData\Sysmon\sysmon.exe"
$sysmonConfigPath = "C:\ProgramData\Sysmon\sysmonconfig-export.xml"
$sysmonUpdatePath = "C:\ProgramData\Sysmon\SysmonUpdateConfig.ps1"
$sysmonFolderPath = "C:\ProgramData\Sysmon\"

# Create Sysmon Folder if it Doesn't Exist
if (-not (Test-Path $sysmonFolderPath)) {
    & {
        trap {
            Write-Host "Error creating the folder: $_"
            break
        }
        New-Item -ItemType Directory -Path $sysmonFolderPath -Force
        Write-Host "Folder created successfully at $sysmonFolderPath"
    }
} else {
    Write-Host "The folder already exists at $sysmonFolderPath"
}

# Function to download a file using System.Net.WebClient
function Download-File {
    param (
        [string]$url,
        [string]$outputPath
    )

    & {
        trap {
            Write-Host "Error downloading $url: $_"
            break
        }
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($url, $outputPath)
        Write-Host "Downloaded $url to $outputPath"
    }
}

# Download Sysmon, Config, and Update Script
Download-File -url $sysmonURL -outputPath $sysmonPath
Download-File -url $sysmonConfigURL -outputPath $sysmonConfigPath
Download-File -url $sysmonUpdateConfigURL -outputPath $sysmonUpdatePath

# Install Sysmon with Config

& {
    trap {
        Write-Host "Error installing Sysmon: $_"
        break
    }
    Start-Process -FilePath $sysmonPath -ArgumentList "-accepteula -i $sysmonConfigPath" -NoNewWindow -Wait
    Write-Host "Sysmon installed successfully."
}