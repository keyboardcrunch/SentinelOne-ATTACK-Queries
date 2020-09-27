## Lateral Movement

### T1550.002 Pass the Hash
Atomics: [T1550.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.002/T1550.002.md)


### T1550.003 Pass the Ticket
Atomics: [T1550.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.003/T1550.003.md)


### T1563.002 RDP Hijacking
Atomics: [T1563.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1563.002/T1563.002.md)

Detects RDS and RemoteApp session redirections for lateral movement.

```
SrcProcName = "tscon.exe" AND SrcProcCmdLine ContainsCIS "/dest:"
```

### T1021.001 Remote Desktop Protocol
Atomics: [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md)

Below query will catch both Atomic tests because it focuses on detecting the use of cmdkey for authenticating RDP sessions (often used for automated lateral movement).

```
TgtProcName = "cmdkey.exe" AND TgtProcCmdLine ContainsCIS "/generic:TERMSRV" AND TgtProcCmdLine ContainsCIS "/user:" AND TgtProcCmdLine ContainsCIS "/pass:"
```

### T1021.002 SMB/Windows Admin Shares
Atomics: [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md)


### T1021.006 Windows Remote Management
Atomics: [T1021.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.006/T1021.006.md)

