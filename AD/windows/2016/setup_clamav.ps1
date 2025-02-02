if (-not (Test-Path "C:\tmp")) {
    New-Item -ItemType Directory -Path "C:\tmp"
}

Invoke-WebRequest -Uri "https://pscho.xyz/AD/windows/installers/clamav.msi" -OutFile "C:\tmp\clamav.msi"
Start-Process "C:\tmp\clamav.msi" -ArgumentList "/quiet" -Wait

Copy-Item "C:\Program Files\ClamAV\conf_examples\clamd.conf.sample" "C:\Program Files\ClamAV\clamd.conf"
Copy-Item "C:\Program Files\ClamAV\conf_examples\freshclam.conf.sample" "C:\Program Files\ClamAV\freshclam.conf"

(Get-Content "C:\Program Files\ClamAV\clamd.conf") -replace '^Example$','' | Set-Content "C:\Program Files\ClamAV\clamd.conf"
(Get-Content "C:\Program Files\ClamAV\freshclam.conf") -replace '^Example$','' | Set-Content "C:\Program Files\ClamAV\freshclam.conf"

& 'C:\Program Files\ClamAV\clamd.exe' --install
& 'C:\Program Files\ClamAV\freshclam.exe'

net start clamd