# Get the default naming context for the domain
$rootDSE = [ADSI]"LDAP://RootDSE"
$defaultNamingContext = $rootDSE.defaultNamingContext

# Construct the paths for Users and Builtin containers
$usersPath = "LDAP://CN=Users,$defaultNamingContext"
$builtinPath = "LDAP://CN=Builtin,$defaultNamingContext"

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

    $group = [ADSI]"LDAP://$groupDN"

    "Current members of the group $($group.Name):" | Out-File -FilePath $outputFile

    foreach ($memberDN in $group.Member) {
        $member = [ADSI]"LDAP://$memberDN"
        $member.sAMAccountName | Add-Content -Path $outputFile
    }

    $accountsToKeep = @("Administrator")

    foreach ($memberDN in $group.Member) {
        $member = [ADSI]"LDAP://$memberDN"

        if ($accountsToKeep -notcontains $member.sAMAccountName) {
            $logMessage = "Removing user: $($member.sAMAccountName)"
            $logMessage | Add-Content -Path $outputFile
            $group.Remove("LDAP://$memberDN")
        }
    }

    "Updated members of the group $($group.Name):" | Add-Content -Path $outputFile
    foreach ($memberDN in $group.Member) {
        $member = [ADSI]"LDAP://$memberDN"
        $member.sAMAccountName | Add-Content -Path $outputFile
    }
}