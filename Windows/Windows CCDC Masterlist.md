# **Windows Playbook ¯\\\_₍⸍⸌̣ʷ̣̫⸍̣⸌₎\_/¯**

# First 10 minutes…

| Command Prompt |  |
| ----- | :---- |
| Disable guest/admins | `Net Administrator /active:no Net Guest /active:no` |
| Create your own admin and add them to Administrators | `Net user /add [new_admin_user] [password] Net localgroup Administrators [new_admin_user] /add DO NOT FUCK YOURSELF BY DISABLING ADMIN AND NOT REPLACING IT!!!!!` |
| List users | `Net user` |
| View files w/ nice lines | `tree c:\ /f | more` |
| View [NTFS perms](#ntfs-letter-guide) | `icacls C:\Windows` |
|  |  |
| Powershell |  |
| Get [version](#windows-version-guide-lol) and build | `Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber` |

# Command Guides

| USER/GROUP COMMAND GUIDE |  |
| ----- | :---- |
| win \+ r (Run) for UI | `lusrmgr.msc (easiest way to set password to change next logon)` |
| Command Prompt |  |
| List users | `Net user` |
| Create/delete group | `Net localgroup [Group Name] /<add/remove>` |
| Create/delete user | `Net user /<add/remove> [name] [password]` |
| Add user to group | `Net localgroup [Group Name] [User Name] /add` |
| Disable user | `Net user [specific_user] /active{yes|no}` |
| Update user password | `Net user [specific_user] [new password]` |
| Powershell |  |
| Get users/groups | `Get-WmiObject Win32_useraccount Get-WmiObject Win32_group Get-WmiObject Win32_groupuser` |
| Get admins (idk I stole this like crazy) | `Get-WmiObject win32_groupuser | Where-Object { $_.groupcomponent -match 'administrators' } | ForEach-Object {[wmi]$_.partcomponent}` |
| Create a user object | `[adsi]$userVar = "winNT://<ComputerName>/<username>"` |
| Mess with userVars | `$userVar.lastlogin $userVar.badpasswordattempts $userVar.setpassword("[password]")` |

# Extra Guides

| Windows Version Guide LOL |  |
| ----- | :---: |
| **OS Name** | **Version Number** |
| Windows NT 4	 | 4.0 |
| Windows 2000 | 5.0 |
| Windows XP | 5.1 |
| Windows Server 2003, 2003 R2 | 5.2 |
| Windows Vista, Server 2008 | 6.0 |
| Windows 7, Server 2008 R2 | 6.1 |
| Windows 8, Server 2012 | 6.2 |
| Windows 8.1, Server 2012 | 6.3 |
| Windows 10, Server 2016, Server 2019 | 10.0 |

| NTFS Letter Guide |  |
| :---: | ----- |
| **Letters** | **Meaning** |
| CI | container inherit |
| OI | object inherit |
| IO | inherit only |
| NP | do not propagate inherit |
| I | permission inherited from parent container |
| F | full access |
| D | delete access |
| N | no access |
| M | modify access |
| RX | read and execute access |
| R | read-only access |
| W | write-only access |

# Sexy Online Resources ;)

## Windows Hardening Script

[https://github.com/xFaraday/EzScript](https://github.com/xFaraday/EzScript)

* In globalAudit(), change user on /user:”Domain Admins”  
* Comment out functions you don’t want to run/services within functions you don’t wanna disable

## New Process Monitor

[https://github.com/andyjsmith/Command-Spy](https://github.com/andyjsmith/Command-Spy) 

## Windows Debloat Ansible

[https://github.com/ccdc-opensource/ansible-role-debloat-windows](https://github.com/ccdc-opensource/ansible-role-debloat-windows) 

## SSH Brute-Force Defense

[https://github.com/backslashspace/Windows-SSH-Fail2Ban](https://github.com/backslashspace/Windows-SSH-Fail2Ban) 

## Windows Theme Repair

[https://github.com/UCI-CCDC/CCDC/tree/master/Windows/Fix-Themes](https://github.com/UCI-CCDC/CCDC/tree/master/Windows/Fix-Themes) 

## Windows Event Log Analyzer

[https://github.com/Yamato-Security/WELA](https://github.com/Yamato-Security/WELA) 

## SSH Guide

[https://gist.github.com/teocci/5a96568ab9bf93a592d7a1a237ebb6ea](https://gist.github.com/teocci/5a96568ab9bf93a592d7a1a237ebb6ea) 

## Somebody’s Playbook

[https://ccdc-handbook.firebaseapp.com/Windows/](https://ccdc-handbook.firebaseapp.com/Windows/) 

# Previous CCDC Guide

* Event Viewer is your friend  
* Autoruns is your friend  
* Process Explorer and TCP View are your friend  
* OSSEC works for windows too   
  * (agent only, must talk to a Linux server for reporting)  
* Change passwords and fast\! (Automate if possible)  
* Remove unused users and services  
* Turn your firewall on and REMOVE EXCEPTIONS  
* Turn off Teredo  
* Passwords  
  * Program one:  
    * AutoIt (make a binary to do it faster)  
  * Download one:  
    * http://bit.ly/bulkpasswordcontrol (AD only \- not local)  
    * Advantage: pseudo random passwords  
  * Built in one:  
    * dsquery user ou=Users,dc=testlab,dc=net | dsmod user \-pwd RedTeamSucks\! \-mustchpwd yes  
    * LAPS for local admin passwords (Not built in, but it is Microsoft tool) https://technet.microsoft.com/en-us/library/security/3062591.aspx  
* Group Policy  
  * Some specific Windows Group Policy to set  
  * Security Options  
    * Network security: LAN Manager authentication level \- Send NTLMv2  response only\\refuse NTLM & LM  
    * Network security: Do not store LAN Manager hash value on next password change \- Enabled  
    * Network access: Do not allow anonymous enumeration of SAM accounts and shares \- Enabled  
    * Network access: Do not allow anonymous enumeration of SAM accounts \- Enabled  
    * Network access: Allow anonymous SID/name translation \- Disabled  
    * Accounts: Rename administrator account \- Rename to something unique (but remember it)  
    * Interactive logon: Message text for users attempting to log on \- sometimes an inject  
* Audit Policy  
  * Learn to configure windows audit logs and understand the events.  
  * Audit process tracking \- Successes  
  * Audit account management \- Successes, Failures  
  * Audit logon events \- Successes, Failures  
  * Audit account logon events \- Successes, Failures  
* Local GPO is much faster to push out on small networks, and can be applied to any Windows system, not just domain joined ones (plus if the attacker kicks a box off the domain, domain GPO goes away). There isn't an easy way to do it for all GPO settings, but for security ones 'secedit' is your friend.  
  * \-- Export a config from a VM or other default install for reference:  
  * secedit /export /cfg checkme.inf  
  * \-- Edit to to have more secure settings then import onto your target system:   
  * secedit	 /configure /db secedit.sdb /cfg securecheckme.inf  
* Event Viewer, /var/logs, .bash\_history  
* Priorities  
  * If XP/2k3 then PATCH MS08\_067  
    * [https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067)   
  * If Vista/7/2k8 then PATCH MS09\_050  
    * [https://learn.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-050](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-050)   
    * [https://support.microsoft.com/en-us/topic/ms09-050-vulnerabilities-in-smb-could-allow-remote-code-execution-fb6e89ab-102f-5cd9-5d8b-00cad9836fb7](https://support.microsoft.com/en-us/topic/ms09-050-vulnerabilities-in-smb-could-allow-remote-code-execution-fb6e89ab-102f-5cd9-5d8b-00cad9836fb7) 

# NMAP Guide

[https://gist.github.com/amanelis/4705362](https://gist.github.com/amanelis/4705362) 

# Windows File Integrity Monitoring

[https://github.com/OWASP/www-project-winfim.net](https://github.com/OWASP/www-project-winfim.net) 