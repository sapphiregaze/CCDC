param (
    [string]$password
)

function add-backupadmin {
    param (
        [string]$passwd
    )

    $Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"
    # $passwd = get-strongpwd
    $LocalAdmin = $Computer.Create("User", "BakAdmin")
    $LocalAdmin.SetPassword($passwd)
    $LocalAdmin.SetInfo()
    $LocalAdmin.FullName = "Backup Administrator"
    $LocalAdmin.SetInfo()
    # ADS_UF_PASSWD_CANT_CHANGE + ADS_UF_DONT_EXPIRE_PASSWD
    $LocalAdmin.UserFlags = 64 + 65536
    $LocalAdmin.SetInfo()
}

add-backupadmin -passwd $password