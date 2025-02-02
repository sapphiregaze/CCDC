# script to disable all powershell accounts except for those in a exclude file

# Get the list of accounts to exclude
$exclude = Get-Content -Path .\exclude.txt

# Get all the accounts
$accounts = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName | Where-Object {$_ -ne "Administrator" -and $_ -ne "IUSR"}

# Disable all accounts that are not in the exclude list
foreach ($account in $accounts) {
    if ($exclude -notcontains $account) {
        Disable-ADAccount -Identity $account
    }
}