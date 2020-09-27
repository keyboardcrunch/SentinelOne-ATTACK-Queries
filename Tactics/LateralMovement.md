## Lateral Movement

### T1550 Pass the Hash & Pass the Ticket
Atomics: [T1550.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.002/T1550.002.md), [T1550.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.003/T1550.003.md)

Here we're focusing on detecting command line arguments of Mimikatz, so binary and powershell mimikatz will be detected assuming arguments haven't been modified before deployment. 

```
TgtProcCmdLine In Contains Anycase ("sekurlsa::pth","/ntlm:","kerberos::ptt")
```

### T1563.002 RDP Hijacking
Atomics: [T1563.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1563.002/T1563.002.md)

Detects RDS and RemoteApp session redirections for lateral movement.

```
SrcProcName = "tscon.exe" AND SrcProcCmdLine ContainsCIS "/dest:"
```

### T1021.001 Scripted Lateral RDP
Atomics: [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md)

Below query will catch both Atomic tests because it focuses on detecting the use of cmdkey for authenticating RDP sessions (often used for automated lateral movement).

```
TgtProcName = "cmdkey.exe" AND TgtProcCmdLine ContainsCIS "/generic:TERMSRV" AND TgtProcCmdLine ContainsCIS "/user:" AND TgtProcCmdLine ContainsCIS "/pass:"
```

### T1021.002 SMB/Windows Admin Shares
Atomics: [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md)

Detecting the creation and use of may catch a lot of legitimate activity, I wouldn't recommend subscribing to this query.

```
TgtProcCmdLine ContainsCIS "New-PSDrive" OR (TgtProcName = "net.exe" AND TgtProcCmdLine ContainsCIS "use ")
```

### T1021.006 Windows Remote Management
Atomics: [T1021.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.006/T1021.006.md)

The below query (in order) remote process executions through MMC, WMIC, and PsExec (by name or display name). Also of note, there are only 3 tests documented for this Atomic, yet there are 6 tests, so the below query focuses on detectability.

*PsExec detection may have a lot of noise depending on your environment, and may require additional filtering.*

```
(TgtProcCmdLine ContainsCIS "GetTypeFromProgID(" AND TgtProcCmdLine ContainsCIS "MMC20.application" AND TgtProcCmdLine ContainsCIS ".Document.ActiveView.ExecuteShellCommand(") OR (TgtProcName = "wmic.exe" AND TgtProcCmdLine ContainsCIS "/node:" AND TgtProcCmdLine ContainsCIS "process call create") OR ((SrcProcName ContainsCIS "psexec.exe" OR SrcProcDisplayName = "Execute processes remotely") AND DstIp Is Not Empty)
```