# Import the Active Directory module
Import-Module ActiveDirectory

# Get the distinguished name (DN) for the Users container
$usersPath = (Get-ADObject -Filter { Name -eq "Users" }).DistinguishedName
Write-Output "Users container path: $usersPath"

# Get the distinguished name (DN) for the Builtin container
$builtinPath = (Get-ADObject -Filter { Name -eq "Builtin" }).DistinguishedName
Write-Output "Builtin container path: $builtinPath"

Write-Output "Users container path: $usersPath"
Write-Output "Builtin container path: $builtinPath"

$DomainAdminOutputFile = "C:DomainAdminsMembers.txt"
$RemoteDesktopOutputFile = "C:RemoteDesktopUsersMembers.txt"
$EnterpriseAdminOutputFile = "C:EnterpriseAdminsMembers.txt"
$AdministratorOutputFile = "C:AdministratorsMembers.txt"
$RemoteManagementUsersOutputFile = "C:RemoteManagementUsersMembers.txt"

$outputFiles = @($DomainAdminOutputFile, $RemoteDesktopOutputFile, $EnterpriseAdminOutputFile, $AdministratorOutputFile, $RemoteManagementUsersOutputFile)

$domainAdminsGroupDN = "CN=Domain Admins," + $usersPath
$remoteDesktopUsersGroupDN = "CN=Remote Desktop Users," + $builtinPath
$enterpriseAdminsGroupDN = "CN=Enterprise Admins," + $usersPath
$administratorsGroupDN = "CN=Administrators," + $builtinPath
$remoteManagementUsersGroupDN = "CN=Remote Management Users," + $builtinPath

$groupDNs = @($domainAdminsGroupDN, $remoteDesktopUsersGroupDN, $enterpriseAdminsGroupDN, $administratorsGroupDN, $remoteManagementUsersGroupDN)

for ($i = 0; $i -lt $groupDNs.Count; $i++) {
    $groupDN = $groupDNs[$i]
    $outputFile = $outputFiles[$i]

    $group = Get-ADGroup -Identity $groupDN

    if ($group -eq $null) {
        Write-Output "Group not found: $groupDN"
        continue
    }

    "Current members of the group $($group.Name):" | Out-File -FilePath $outputFile

    foreach ($member in Get-ADGroupMember -Identity $groupDN) {
        $member.sAMAccountName | Add-Content -Path $outputFile
    }

    $accountsToKeep = @("Administrator")

    foreach ($member in Get-ADGroupMember -Identity $groupDN) {
        if ($accountsToKeep -notcontains $member.sAMAccountName) {
            $logMessage = "Removing user: $($member.sAMAccountName)"
            $logMessage | Add-Content -Path $outputFile
            Remove-ADGroupMember -Identity $groupDN -Members $member -Confirm:$false
        }
    }

    "Updated members of the group $($group.Name):" | Add-Content -Path $outputFile
    foreach ($member in Get-ADGroupMember -Identity $groupDN) {
        $member.sAMAccountName | Add-Content -Path $outputFile
    }
}