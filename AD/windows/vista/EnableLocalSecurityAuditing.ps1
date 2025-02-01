# Enable Advanced Audit Policy
Write-Output "Enabling advanced audit policies..."
auditpol.exe /set /category:"Account Logon" /success:enable /failure:enable
auditpol.exe /set /category:"Account Management" /success:enable /failure:enable
auditpol.exe /set /category:"Logon/Logoff" /success:enable /failure:enable

# Verify Audit Policies
Write-Output "Current Audit Policy Settings:"
auditpol.exe /get /category:*

# Enable Audit Policies via Local Security Policy
Write-Output "Configuring Local Security Policy for auditing..."
$securitySettings = @(
    @{
        Name = "Audit account logon events";
        Key = "MACHINE\System\CurrentControlSet\Services\Eventlog\Security";
        Value = 1 # Success and failure
    },
    @{
        Name = "Audit account management";
        Key = "MACHINE\System\CurrentControlSet\Services\Eventlog\Security";
        Value = 1 # Success and failure
    },
    @{
        Name = "Audit logon events";
        Key = "MACHINE\System\CurrentControlSet\Services\Eventlog\Security";
        Value = 1 # Success and failure
    }
)

foreach ($setting in $securitySettings) {
    Write-Output "Configuring $($setting.Name)..."
    secedit.exe /export /areas SECURITYPOLICY /cfg $env:TEMP\secpol.cfg
    (Get-Content $env:TEMP\secpol.cfg) -replace "($setting.Key)=.*", "`$1=$($setting.Value)" |
        Set-Content $env:TEMP\secpol.cfg
    secedit.exe /import /cfg $env:TEMP\secpol.cfg /quiet
}

# Update Policies
Write-Output "Updating Group Policy..."
gpupdate /force

Write-Output "Audit policies configured successfully."
