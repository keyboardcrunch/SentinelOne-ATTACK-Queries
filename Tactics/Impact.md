## Impact

### T1531 Account Access Removal
Atomics: [T1531](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1531/T1531.md)

Detects the deletion of a local user account or removal of Active Directory groups through powershell cmdlets. No detection for account password resets for purpose of impact due to false detections.

```
SrcProcCmdline RegExp "net\s+user(?:(?!\s+/delete)(?:.|\n))*\s+/delete" OR TgtProcCmdLine  ContainsCIS "Remove-ADGroupMember" OR SrcProcCmdScript ContainsCIS "Remove-ADGroupMember"
```

### T1485 Data Destruction
Atomics: [T1485](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md)

Detection of SDelete (by display name) and execution of DD command on *nix operating systems. Alternatively, DV 3.0 with 4.4 Agents will support `TgtFileDeletionCount > "100"` query for detection of over 100 files deleted, which can be combined with *FileType* for filtering.

```
(AgentOS In ("linux","osx") AND TgtProcName = "dd" AND TgtProcCmdLine ContainsCIS "of=") OR TgtProcDisplayName = "Secure file delete"
```

### T1490 Inhibit System Recovery
Atomics: [T1490](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md)

Detects the use of vssadmin, wbadmin, bcdedit and powershell deletion of shadowcopy content and disabling of system recovery.

```
TgtProcCmdLine In Contains Anycase ("delete shadows","shadowcopy delete","delete catalog","recoveryenabled no") OR (TgtProcCmdLine ContainsCIS "Win32_ShadowCopy" AND TgtProcCmdLine ContainsCIS "Delete()") OR (SrcProcCmdScript ContainsCIS "Win32_ShadowCopy" AND SrcProcCmdScript ContainsCIS "Delete()")
```

### T1489 Service Stop
Atomics: [T1489](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md)

