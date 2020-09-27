## Impact

### T1531 Account Access Removal
Atomics: [T1531](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1531/T1531.md)

Detects the deletion of a local user account or removal of Active Directory groups through powershell cmdlets. No detection for account password resets for purpose of impact due to false detections.

```
SrcProcCmdline RegExp "net\s+user(?:(?!\s+/delete)(?:.|\n))*\s+/delete" OR TgtProcCmdLine  ContainsCIS "Remove-ADGroupMember" OR SrcProcCmdScript ContainsCIS "Remove-ADGroupMember"
```

### T1485 Data Destruction
Atomics: [T1485](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md)

Detection of SDelete (by display name) and execution of DD command on *nix operating systems.

```
(AgentOS In ("linux","osx") AND TgtProcName = "dd" AND TgtProcCmdLine ContainsCIS "of=") OR TgtProcDisplayName = "Secure file delete"
```

### T1490 Inhibit System Recovery
Atomics: [T1490](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md)


### T1489 Service Stop
Atomics: [T1489](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md)


### T1529 System Shutdown/Reboot
Atomics: [T1529](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1529/T1529.md)


