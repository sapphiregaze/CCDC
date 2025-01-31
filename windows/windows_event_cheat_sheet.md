# Common Windows Event Viewer Event IDs

## Logon and Authentication Events

    - 4624: Successful logon.
    - 4625: Failed logon attempts (may indicate brute force attempts).
    - 4672: Special privileges assigned to new logon (indicates privilege escalation).
    - 4776: NTLM authentication (can indicate lateral movement).

## Account Management Events

    - 4720: A user account was created.
    - 4722: A user account was enabled.
    - 4723/4724: An attempt to change/reset the password was made.
    - 4732: A member was added to a privileged group (e.g., Administrators).

## Process Creation and Execution Events

    - 4688: A new process was created (look for suspicious or uncommon processes).
    - 4697: A service was installed (may indicate persistence techniques).
    - 7045: A new service was installed (visible in the System log).

## Object Access Events

    - 4663: An attempt was made to access an object (e.g., files, registry).
    - 5145: A network share object was accessed (suspicious access patterns).

## Firewall and Defender Events

    - 5025: The Windows Firewall Service was stopped.
    - 1116: Malware was detected by Windows Defender.

## Other Suspicious Indicators

    - 1102: The audit log was cleared (possible sign of tampering).
    - 4648: A logon was attempted using explicit credentials.

## Sysmon

### Installing Sysmon

    ```
    Manually:
    Create C:\Sysmon Directory
    Install Sysmon and config from: https://github.com/ion-storm/sysmon-config
    sysmon -accepteula -i CONFIG
    Automatically:
    https://github.com/ion-storm/sysmon-config/blob/master/Sysmon_Installer.ps1
    ```

### Sysmon Event IDs (Applications and Services Logs/Microsoft/Windows/Sysmon/Operational)

    - 1: Process creation
    - 2: A process changed a file creation time
    - 3: Network connection
    - 4: Sysmon service state changed
    - 5: Process terminated
    - 6: Driver loaded
    - 7: Image loaded
    - 8: CreateRemoteThread
    - 9: RawAccessRead (\\.\)
    - 10: ProcessAccess (ex. Lsass.exe)
    - 11: FileCreate
    - 12: RegistryEvent (Object create and delete)
    - 13: RegistryEvent (Value Set)
    - 14: RegistryEvent (Key and Value Rename)
    - 15: FileCreateStreamHash (mark of the web)
    - 16: ServiceConfigurationChange (sysmonconfigchange)
    - 17: PipeEvent (Pipe Created)
    - 18: PipeEvent (Pipe Connected)
    - 19: WmiEvent (WmiEventFilter activity detected)
    - 20: WmiEvent (WmiEventConsumer activity detected)
    - 21: WmiEvent (WmiEventConsumerToFilter activity detected)
    - 22: DNSEvent (DNS query)
    - 23: FileDelete (File Delete archived)
    - 24: ClipboardChange (New content in the clipboard)
    - 25: ProcessTampering (Process image change)
    - 26: FileDeleteDetected (File Delete logged)
    - 27: FileBlockExecutable
    - 28: FileBlockShredding
    - 29: FileExecutableDetected
    - 255: Error
