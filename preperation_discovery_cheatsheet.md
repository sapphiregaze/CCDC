# from: https://github.com/simeononsecurity/Blue-Team-Tools/blob/master/Windows/CCDCprep

# WGU CCDC Basic Windows Checklist / First Fifteen Minutes guidelines

You may want to pull up the [Windows Command Line Cheat Sheet](https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/blt4e45e00c2973546d/5eb08aae4461f75d77a48fd4/WindowsCommandLineSheetV1.pdf)

You should check if the [Deepend script](https://github.com/WGU-CCDC/Blue-Team-Tools/blob/master/Windows/deepend.ps1) will take care of the 1st 15 minutes here, if not, then all the steps are listed below. Then come back to the steps here and start at Step 15.

## Step 1
Make sure machine is in English
```
Control intl.cpl
```

## Step 2
Create backup administrator account
```
net user WGU-Admin * /ADD
net localgroup administrators WGU-Admin /add
```

## Step 3
Change all user passwords to strong passwords
```
Net localgroup administrators >>LocalAdministratorUsers.txt
Net user {username_here} *
Net user >>localUsers.txt
Net user {username} *
```

## Step 4
Delete or disable any unnecessary accounts

Disable
```
Net user accountname /active:no 
```
Delete
```
Net user accountname /delete
```

## Step 5
Enable Windows Firewall and allow some ports through 

**Important:** You only want to run the reset command if you are local to the box
```
netsh advfirewall reset
```

```
netsh advfirewall firewall delete rule *
netsh advfirewall firewall add rule dir=in action=allow protocol=tcp localport=3389 name=”Allow-TCP-3389-RDP”
```

```
netsh advfirewall firewall add rule dir=in action=allow protocol=icmpv4 name=”Allow ICMP V4”
netsh advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set allprofile state on

```

## Step 6
Check for any logged on users
```
Query session
Query user
Query process
```

## Step 7
Delete Unnecessary Shares on the Machine
```
Net share
Net share sharename /delete
```

## Step 8
Delete any scheduled tasks
```
schtasks /delete /tn * /f
```

## Step 9
Identify running services and processes
```
Get-service
Sc query type=service state=all
Tasklist >>RunningProcesses.Txt
```

## Step 10
Setup for Powershell Scripts

Powershell commands
```
Set-executionpolicy bypass -force
Disable-psremoting -force
Clear-item -path wsman:\localhost\client\trustedhosts -force
Add-windowsfeature powershell-ise
```

## Step 11
Enable and set to highest setting UAC
```
C:\windows\system32\UserAccountControlSettings.exe
```

## Step 12
Verify Certificate stores for any suspicious certs

Win 8 / 2012 or higher
```
certlm
```
```
mmc.exe 
File -> Add / Remove Snap-In -> Certificates -> Click Add->Computer Account->Local Computer->Finish
File -> Add / Remove Snap-In -> Certificates -> Click Add->My User Account->Finish
File -> Add / Remove Snap-In -> Certificates -> Click Add->Service Account->Local Computer->Select potential service accounts to review -> Finish
```

## Step 13
Check startup & disable unnecessary items via msconfig
```
msconfig
```

## Step 14
Uninstall any unnecessary software
```
Control appwiz.cpl
```
IE: remove tightvnc, aim, trillian, gaim, pidgin, any extraneous software that is not required by the given scenario.

Check browsers for any malicious or unnecessary toolbars etc
Reset the browsers if possible

## Step 15
Make sure Windows Defender is enabled and up to date
```ps1
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting 1
Set-MpPreference -SubmitSamplesConsent 1
Set-MpPreference -PUAProtection 1
Enable-MpProtection
Get-MpPreference
```


## Step 16
Configure local policies
```
Secpol.msc
```
1. Security Settings>Account Policies>Account Lockout Policy:
     - Account Lockout Duration: 30min
     - Account Lockout threshold: 2 failed logins
     - Reset account lockout counter after: 30 mins 

2. Local Policies>Audit Policy :
     - Enable all for failure and success

3. Security Options:
     - Accounts: Guest account status: Disabled
     - Domain member: Digitally encrypt or sign secure channel data (always): Enabled
     - Microsoft network client: Digitally sign communications (always): Enabled
     - Microsoft network server: Digitally sign communications (always): Enabled
     - Network access: Do not allow anonymous enumeration of SAM accounts: Enabled
     - Network access: Do not allow anonymous enumeration of SAM accounts and shares: Enabled
     - Network access: Let Everyone permissions apply to anonymous users: Disabled
     - Network security: LAN Manager authentication level: Send NTLMv2 response only. Refuse LM & NTLM
     - Network access: Named Pipes that can be accessed anonymously: None
     - Network access: Restrict anonymous access to Named Pipes and Shares: Enabled
     - Network access: Shares that can be accessed anonymously: None

4. Advanced Audit Policy Configuration
     - DS Access: Audit Directory Service Access: Success, Failure
     - Logon/Logoff: Audit Logoff: Success, Failure
     - Logon/Logoff: Audit Logon: Success, Failure
     - Logon/Logoff: Audit Other Logon/Logoff Events: Success, Failure
     - Object Access: Audit Detailed File Share: Success, Failure
     - Object Access: Audit File Share: Success, Failure
     - Object Access: Audit File System: Success, Failure
     - Object Access: Audit Registry: Success, Failure

## Step 17
Configure local group policy
1. Windows Settings -> Administrative Templates
    - Network -> Lanman Workstation: Enable insecure guest logons: Disabled
    - Network -> Network Provider: Hardened UNC Paths: Enabled
    - Printers -> Point and Print Restrictions: Enabled
    - Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security: Always prompt for password upon connection: Enabled
    - Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security: Require secure RPC communication: Enabled
    - Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security: Set client connection encryption level: High Level
    - Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security: Always prompt for password upon connection: Enabled
    - Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security: Require secure RPC communication: Enabled
    - Windows Components -> Windows PowerShell: Turn on PowerShell Transcription: Enabled
    - Windows Components -> WinRM: Allow Basic authentication: Disabled
    - Windows Components -> WinRM: Allow unencrypted traffic: Disabled
    - Windows Components -> WinRM: Disallow WinRM from storing RunAs credentials: Enabled
    - Windows Components -> Windows Remote Shell: Allow Remote Shell Access: Disabled

## Step 17
### Preliminary Hardening
* Disable SMBv1
    - Win 7 way is
        ```
        Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | ForEach-Object {Get-ItemProperty $_.pspath}
        ```
        ```
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force 
        ```
        Then restart
* Disable [Netbios](https://help.hcltechsw.com/docs/onprem_2.0/2.0_CR3_install_guide/guide/text/disable_netbios_on_windows_servers.html)
* Disable Login to Certain accounts
    - This is dependent on the business scenario we're given. So we'll have a snippet of how to perform the disabling but we might need to skip over this step

## Step 18
Get these tools onto the machine
* Sysinternals
    - [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
    - [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)
    - [AutoRuns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)
* [BlueSpawn](https://bluespawn.cloud/quickstart/)
* [EMET (If Windows 7)](https://www.microsoft.com/en-us/download/details.aspx?id=50766)
* [ProcessHacker](https://processhacker.sourceforge.io/)
* [**Microsoft Security Compliance Toolkit 1.0**](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

# Windows Intrusion Discovery
Purpose
System Administrators are often on the front lines of computer security. This guide aims to support System Administrators in finding indications of a system compromise.

How to Use This Sheet
On a periodic basis (daily, weekly, or each time you logon to a system you manage,) run through these quick steps to look for anomalous behavior that might be caused by a computer intrusion. Each of these commands runs locally on a system.

This list is split into these sections:
* Unusual Processes and Services
* Unusual Files and Reg Keys
* Unusual Network Usage
* Unusual Scheduled Tasks
* Unusual Accounts
* Unusual Log Entries
* Other Unusual Items
* Additional Supporting Tools

## Unusual Processes and Services Unusual Network Usage
Look for unusual/unexpected processes, and focus on processes with User Name “SYSTEM” or “Administrator” (or users in the Administrators' group). You need to be familiar with normal processes and services and search for deviations.

Using the GUI, run Task Manager:

```C:\> taskmgr.exe```

Using the command prompt:

```C:\> tasklist```

```C:\> wmic process list full```

Also look for unusual services. Using the GUI:

```C:\> services.msc```

Using the command prompt:

```C:\> net start```

```C:\> sc query```

For a list of services associated with each process:

```C:\> tasklist /svc``` 

## Unusual Files and Registry Keys

Check file space usage to look for sudden major decreases in free space, using the GUI (right-click on partition), or type:

```C:\> dir c:\```

Look for strange programs in startup registry keys in both HKLM & HKCU:
```
Software\Microsoft\Windows\CurrentVersion\Run
Software\Microsoft\Windows\CurrentVersion\Runonce
Software\Microsoft\Windows\CurrentVersion\RunonceEx
```

Using the GUI:

```C:\> regedit```

Using the command prompt:

```C:\> reg query <reg key>```

## Unusual Network Usage

Look at file shares, and make sure each has a defined business purpose:

```C:\> net view \\127.0.0.1```

List the open SMB sessions with this machine:

```C:\> net session```

List the SMB sessions this machine has opened with other systems:

```C:\> net use```

Look at NetBIOS over TCP/IP activity:

```C:\> nbtstat –S```

Look for unusual listening TCP and UDP ports:

```C:\> netstat –na```

For continuously updated and scrolling output of this command every 5 seconds:

```C:\> netstat –na 5```

The –o flag shows the owning process id:

```C:\> netstat –nao 5```

The –b flag shows the executable name and the DLLs loaded for the network connection.

```C:\> netstat –naob 5```

Again, you need to understand normal port usage for the system and look for deviations. Also check Windows Firewall configuration:

```C:\> netsh advfirewall firewall show rule name=all```

## Unusual Scheduled Tasks

Look for unusual scheduled tasks, especially those that run as a user in the Administrators group, as SYSTEM, or with a blank user name.

Using the GUI, run Task Scheduler: Start -> Programs -> Accessories -> System Tools -> Scheduled Tasks
Using the command prompt:

```C:\> schtasks```

Check other autostart items as well for unexpected entries, remembering to check user autostart directories and registry keys.

Using the GUI, run msconfig and look at the Startup tab:

Start -> Run, msconfig.exe

Using the command prompt:

```C:\> wmic startup list full```

## Unusual Accounts
Look for new, unexpected accounts in the Administrators group:

```C:\> lusrmgr.msc```

Click on Groups, Double Click on Administrators, then check members of this group.This can also be done at the command prompt:

```C:\> net user```

```C:\> net localgroup administrators```

## Unusual Log Entries

Check your logs for suspicious events, such as:
* “Event log service was stopped.”
* “Windows File Protection is not active on this system.”
* "The protected System file [file name] was not restored to its original, valid version because the Windows File Protection..."
* “The MS Telnet Service has started successfully.”
* Look for large number of failed logon attempts or locked out accounts.

To do this using the GUI, run the Windows event viewer:

```C:\> eventvwr.msc```

## Other Unusual Items

Additional Supporting Tools
Look for unusually sluggish performance and a single unusual process hogging the CPU:

Task Manager -> Process and Performance tabs

Or, run:

```C:\> taskmgr.exe```

Look for unusual system crashes, beyond the normal level for the given system.

## Additional Supporting Tools

The following tools are not built into Windows operating system but can be used to analyze security issues in more detail. Each is available for free download at the listed web site.

From [Microsoft Sysinternals](https://technet.microsoft.com/en-us/sysinternals):
* Psexec: Make a remote Windows machine run commands.
* Process Monitor: Analyze process activities indepth in real-time.
* Sysmon: Record detailed information about a multitude of Windows activities, including processes, services, network connections, and much more.

From http://processhacker.sourceforge.net:
* Process Hacker: Delve into the guts of processes to analyze their behaviors and interactions with the rest of the Windows system.

From http://www.dban.org:
* Darik’s Boot and Nuke: A drive erasure tool that overwrites files multiple times to ensure they cannot be recovered.

The Center for Internet Security has released various Windows security templates and security scoring tools for free at www.cisecurity.org.