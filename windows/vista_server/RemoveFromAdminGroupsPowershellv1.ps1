# Get the default naming context for the domain
$rootDSE = [ADSI]"LDAP://RootDSE"
$defaultNamingContext = $rootDSE.defaultNamingContext

# Construct the paths for Users and Builtin containers
$usersPath = "CN=Users,$defaultNamingContext"
$builtinPath = "CN=Builtin,$defaultNamingContext"

Write-Output "Users container path: $usersPath"
Write-Output "Builtin container path: $builtinPath"

$DomainAdminOutputFile = "C:\tmp\DomainAdminsMembers.txt"
$RemoteDesktopOutputFile = "C:\tmp\RemoteDesktopUsersMembers.txt"
$EnterpriseAdminOutputFile = "C:\tmp\EnterpriseAdminsMembers.txt"
$AdministratorOutputFile = "C:\tmp\AdministratorsMembers.txt"
$RemoteManagementUsersOutputFile = "C:\tmp\RemoteManagementUsersMembers.txt"

$outputFiles = @($DomainAdminOutputFile, $RemoteDesktopOutputFile, $EnterpriseAdminOutputFile, $AdministratorOutputFile, $RemoteManagementUsersOutputFile)

$domainAdminsGroupDN = "CN=Domain Admins,$usersPath"
$remoteDesktopUsersGroupDN = "CN=Remote Desktop Users,$builtinPath"
$enterpriseAdminsGroupDN = "CN=Enterprise Admins,$usersPath"
$administratorsGroupDN = "CN=Administrators,$builtinPath"
$remoteManagementUsersGroupDN = "CN=Remote Management Users,$builtinPath"

$groupDNs = @($domainAdminsGroupDN, $remoteDesktopUsersGroupDN, $enterpriseAdminsGroupDN, $administratorsGroupDN, $remoteManagementUsersGroupDN)

function Run-Command {
    param (
        [string]$command,
        [string]$outputFile
    )

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName = "cmd.exe"
    $process.StartInfo.Arguments = "/c $command"
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardOutput = $true
    $process.Start()

    # Read output
    $output = $process.StandardOutput.ReadToEnd()
    $process.WaitForExit()

    # Save output to file
    $output | Out-File -FilePath $outputFile
}

for ($i = 0; $i -lt $groupDNs.Count; $i++) {
    $groupDN = $groupDNs[$i]
    $outputFile = $outputFiles[$i]

    $group = [ADSI]"LDAP://$groupDN"

    if ($group -eq $null) {
        Write-Output "Group not found: $groupDN"
        continue
    }

    "Current members of the group $($group.Name):" | Out-File -FilePath $outputFile

    if ($group.Member.Count -eq 0) {
        Write-Output "No members found for group: $($group.Name)"
        continue
    }

    foreach ($memberDN in $group.Member) {
        Write-Output "Member DN: $memberDN"
        if ($memberDN -eq $null) {
            Write-Output "Member DN is null"
            continue
        }
        $member = [ADSI]"LDAP://$memberDN"
        if ($member -eq $null) {
            Write-Output "Member not found: $memberDN"
            continue
        }
        Write-Output $member
        $member.sAMAccountName | Out-File -FilePath $outputFile -Append
    }

    $accountsToKeep = @("Administrator")

    foreach ($memberDN in $group.Member) {
        if ($memberDN -eq $null) {
            Write-Output "Member DN is null"
            continue
        }
        $member = [ADSI]"LDAP://$memberDN"
        if ($member -eq $null) {
            Write-Output "Member not found: $memberDN"
            continue
        }

        if ($accountsToKeep -notcontains $member.sAMAccountName) {
            $logMessage = "Removing user: $($member.sAMAccountName)"
            $logMessage | Out-File -FilePath $outputFile -Append
            $group.Remove("LDAP://$memberDN")
        }
    }

    "Updated members of the group $($group.Name):" | Add-Content -Path $outputFile
    foreach ($memberDN in $group.Member) {
        $member = [ADSI]"LDAP://$memberDN"
        $member.sAMAccountName | Out-File -FilePath $outputFile -Append
    }
}