# Ensure NuGet is installed
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::SecurityProtocol

#place .nupkg in C:\Program Files\WindowsPowerShell\Modules
Invoke-WebRequest -Uri "http://pscho.xyz/windows/windows_scripts/misc/packagemanagement.1.1.0.nupkg" -OutFile "C:\Program Files\WindowsPowerShell\Modules\packagemanagement.1.1.0.nupkg"

# Install-Module -Name PackageManagement -RequiredVersion 1.1.0.0

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false

Register-PSRepository -Default -InstallationPolicy Trusted

#Install and apply modules
Install-Module -Name PSWindowsUpdate -Force -Confirm:$false
Install-Module -Name ActiveDirectory -Force -Confirm:$false
Install-Module -Name GroupPolicy -Force -Confirm:$false

Import-Module -Name PSWindowsUpdate
Import-Module -Name ActiveDirectory
Import-Module -Name GroupPolicy

# Change Administrator password
$admin = Get-LocalUser -Name Administrator
$password = Read-Host -AsSecureString "Enter new password: "
Set-LocalUser -Name Administrator -Password $password

#Disable Guest Account
Set-ADUser -Identity "Guest" -Enabled $false
Set-LocalUser -Name Guest -Enabled $false

# Get Default Naming Context
$defaultNamingContext = (Get-ADRootDSE).defaultNamingContext

$anotherPassword = Read-Host -AsSecureString "Enter new password for new admin: "

$usersOU = "OU=Users,$defaultNamingContext"

# Make backup Admin account
New-ADUSer  -Name "Inconspicious User" `
            -SamAccountName "iuser" `
            -UserPrincipalName "iuser@$env:USERDNSDOMAIN" `
            -Path $usersOU `
            -AccountPassword $anotherPassword `
            -Enabled $true

# Add backup Admin to Domain Admins, Enterprise Admins, Schema Admins, Administrators, DNSADmins, and Remote Desktop Users
Add-ADGroupMember -Identity "Domain Admins" -Members "iuser"
Add-ADGroupMember -Identity "Enterprise Admins" -Members "iuser"
Add-ADGroupMember -Identity "Schema Admins" -Members "iuser"
Add-ADGroupMember -Identity "Administrators" -Members "iuser"
Add-ADGroupMember -Identity "DNSAdmins" -Members "iuser"
Add-ADGroupMember -Identity "Remote Desktop Users" -Members "iuser"

# Remove all Users from Domain Admins, Enterprise Admins, Schema Admins, Administrators, and Remote Desktop Users except for the backup admin and the built-in admin
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" | Where-Object { $_.SamAccountName -ne "Administrator" -and $_.SamAccountName -ne "iuser" }
$enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" | Where-Object { $_.SamAccountName -ne "Administrator" -and $_.SamAccountName -ne "iuser" }
$schemaAdmins = Get-ADGroupMember -Identity "Schema Admins" | Where-Object { $_.SamAccountName -ne "Administrator" -and $_.SamAccountName -ne "iuser" }
$administrators = Get-ADGroupMember -Identity "Administrators" | Where-Object { $_.SamAccountName -ne "Administrator" -and $_.SamAccountName -ne "iuser" }
$dnsAdmins = Get-ADGroupMember -Identity "DNSAdmins" | Where-Object { $_.SamAccountName -ne "Administrator" -and $_.SamAccountName -ne "iuser" }
$remoteDesktopUsers = Get-ADGroupMember -Identity "Remote Desktop Users" | Where-Object { $_.SamAccountName -ne "Administrator" -and $_.SamAccountName -ne "iuser" }

foreach ($user in $domainAdmins) {
    Remove-ADGroupMember -Identity "Domain Admins" -Members $user -Confirm:$false
}
foreach ($user in $enterpriseAdmins) {
    Remove-ADGroupMember -Identity "Enterprise Admins" -Members $user -Confirm:$false
}
foreach ($user in $schemaAdmins) {
    Remove-ADGroupMember -Identity "Schema Admins" -Members $user -Confirm:$false
}
foreach ($user in $administrators) {
    Remove-ADGroupMember -Identity "Administrators" -Members $user -Confirm:$false
}
foreach ($user in $dnsAdmins) {
    Remove-ADGroupMember -Identity "DNSAdmins" -Members $user -Confirm:$false
}
foreach ($user in $remoteDesktopUsers) {
    Remove-ADGroupMember -Identity "Remote Desktop Users" -Members $user -Confirm:$false
}

#Make C:\tmp directory
New-Item -Path "C:\tmp" -ItemType Directory

#Make C:\tmp\gpos directory
New-Item -Path "C:\tmp\gpos" -ItemType Directory

#Backup GPOs
Backup-GPO -All -Path "C:\tmp\gpos"

#Backup AD
$backupPath = "C:\tmp\ADBackup"
New-Item -Path $backupPath -ItemType Directory
ntdsutil "activate instance ntds" "ifm" "create full $backupPath" "quit" "quit"

#Remove all GPOs
Get-GPO -All | Remove-GPO -Confirm:$false

#Unlink default domain policy and default domain controller policy
Get-GPO -All | Where-Object { $_.DisplayName -eq "Default Domain Policy" -or $_.DisplayName -eq "Default Domain Controllers Policy" } | ForEach-Object { $_ | Remove-GPLink -Target "dc=$env:USERDNSDOMAIN" }

#Remake default domain policy and default domain controller policy
New-GPO -Name "Default Domain Policy" -Comment "Default Domain Policy" | New-GPLink -Target "dc=$env:USERDNSDOMAIN" -LinkEnabled Yes
New-GPO -Name "Default Domain Controllers Policy" -Comment "Default Domain Controllers Policy" | New-GPLink -Target "dc=$env:USERDNSDOMAIN" -LinkEnabled Yes
dcgpofix /ignoreschema /target:both

#Attempt DNS Backup
$dnsBackupPath = "C:\tmp\DNSBackup"
New-Item -Path $dnsBackupPath -ItemType Directory
dnscmd /enumzones > $dnsBackupPath\zones.txt
foreach ($zone in Get-Content $dnsBackupPath\zones.txt | Where-Object { $_ -match "Zone name" }) {
    $zoneName = $zone -replace ".*: ", ""
    dnscmd /zoneexport $zoneName $dnsBackupPath\$zoneName.bak
}

# Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Enable Remote Desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

# Enable Remote Desktop Firewall Rule
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Add Administrator and iuser to Remote Desktop Users
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Administrator"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "iuser"

# Enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableBlockAtFirstSeen $false
Set-MpPreference -HighThreatDefaultAction 6
Set-MpPreference -ModerateThreatDefaultAction 6
Set-MpPreference -LowThreatDefaultAction 6
Set-MpPreference -SevereThreatDefaultAction 6
Set-MpPreference -PUAProtection 1

#Disable PSRemoting
Disable-PSRemoting

#Get User Accounts that are used as Service Accounts
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

#Disable Windows Remote Management
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowKerberos" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowNegotiate" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowCertificate" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowCredSSP" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowRemoteShellAccess" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowAutoConfig" -Value 0 -Type DWord

Stop-Service -Name WinRM
Set-Service -Name WinRM -StartupType Disabled

# Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false

# Disable LLMNR
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord

# Disable NetBIOS
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableLmhosts" -Value 0 -Type DWord

# Disable WPAD
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "EnableAutoProxyResultCache" -Value 0 -Type DWord

# Disable AppLocker (counter trolling)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -Name "EnforcementMode" -Value 0 -Type DWord

#list shadow copies
vssadmin list shadows

# Enable SMB Encryption
Write-Output "Enabling SMB Encryption"
Set-SmbServerConfiguration –EncryptData $true -Confirm:$false

# Enable SMB Signing
Write-Output "Enabling SMB Signing"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord

# Enable NTLMv2
Write-Output "Enabling NTLMv2"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord

# Disable LM
Write-Output "Disabling LM"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 0 -Type DWord

# Temporarily disable sshd
Write-Output "Temporarily disabling sshd service"
Stop-Service -Name sshd
Set-Service -Name sshd -StartupType Disabled

# Disable Spooler Service
Write-Output "Disabling Spooler Service"
Stop-Service -Name Spooler
Set-Service -Name Spooler -StartupType Disabled

#MORE MITIGATIONS, FROM WGU's deepend.ps1 script

#Disable SMB null sessions
Write-Output "Disabling SMB null sessions."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -name "RestrictAnonymous" -Type DWORD -Value 1 -Force

#disable anonymous enumeration of SAM accounts
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -name "RestrictAnonymousSAM" -Type DWORD -Value 1 -Force
#disable eveyone includes anonymous
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -name "EveryoneIncludesAnonymous" -Type DWORD -Value 0 -Force


#Harden LSA to protect from mimikatz etc
Write-Output "Enabling protections for LSA"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -name "AuditLevel" -Type DWORD -Value 8 -Force

Write-Output "Enabling PPL for LSA"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name "RunAsPPL" -Type DWORD -Value 1 -Force

#disable wdigest
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders" -Name "WDigest"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -name "UseLogonCredential" -Type DWORD -Value 0 -Force

#disable ntlm
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name "CredentialsDelegation"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -name "AllowProtectedCreds" -Type DWORD -Value 1 -Force

#disable netbios over tcp/ip and lmhosts lookups
$nics = Get-WmiObject win32_NetworkAdapterConfiguration
foreach ($nic in $nics) {
    $nic.settcpipnetbios(2) # 2 = disable netbios on interface
    # $nic.enablewins($false,$false) #disable wins
}
#enable powershell logging
Write-Output "Enabling powershell logging"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f

# enable script block logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# enable powershell transcription
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f

# enable powershell constrained language mode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

#Disable SMB Compression
#https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0796
Write-Output "Disabling SMB Compression for CVE 2020-0796"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v DisableCompression /t REG_DWORD /d 1 /f

## Appended more stuff cuz why not
# Author: Christopher Goes

# The following comes from this gist: https://gist.github.com/alirobe/7f3b34ad89a159e6daa1
# Which was derived from here: https://github.com/Disassembler0/Win10-Initial-Setup-Script/
# Raise UAC level
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1

# Disable sharing mapped drives between users
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections"

# Stop and disable Home Groups services
Write-Host "Stopping and disabling Home Groups services..."
Stop-Service "HomeGroupListener"
Set-Service "HomeGroupListener" -StartupType Disabled
Stop-Service "HomeGroupProvider"
Set-Service "HomeGroupProvider" -StartupType Disabled

# Disable Remote Assistance
Write-Host "Disabling Remote Assistance..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

# Disable Autoplay
Write-Host "Disabling Autoplay..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

#Disable Sticky keys prompt
Write-Host "Disabling Sticky keys prompt..." 
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"

# Show hidden files
Write-Host "Showing hidden files..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

#Verify secure channel is not already enforced
Get-ADComputer -Filter {OperatingSystem -Like "*Windows Server*"} | ForEach-Object {
    nltest /server:$_.Name /sc_verify
}

#Install Windows Updates
Get-WindowsUpdate -Install -AcceptAll -AutoReboot

#Patch ZeroLogon

#TODO
#ensure ZeroLogon is patched
#disable sensitive permissions on everyone group on shares
#disable sensitive permissions on everyone group on registry
#disable sensitive permissions on everyone group on services
#mitigate pass the hash attacks
#mitigate printnightmare


#enable enforcement of netlogon secure channel
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value 1 -Type DWord
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 1 -Type DWord
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "FullSecureChannelProtection" -Value 1 -Type DWord
