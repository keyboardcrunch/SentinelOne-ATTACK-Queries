# Windows Atomic Tests by ATT&CK Tactic & Technique
## Privilege Escalation

### T1053.002 AT Scheduled Task
Atomics: [T1053.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.002/T1053.002.md)

Detect interactive process execution scheduled by AT command.

```
TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive "
```

### T1546.008 Accessibility Features
Atomics: [T1546.008](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.008/T1546.008.md)

Detections addition of a debugger process to executables using Image File Execution Options.

```
(RegistryKeyPath ContainsCIS "CurrentVersion\Image File Execution Options" AND RegistryKeyPath ContainsCIS ".exe\Debugger") AND (EventType = "Registry Value Create" OR EventType = "Registry Key Create")
```


### T1546 Application Shimming
Atomics: [T1546.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.011/T1546.010.md) , 
[T1546.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.011/T1546.011.md)

Detects application shimming through sdbinst or registry modification.

```
(SrcProcName = "sdbinst.exe" and ProcessCmd ContainsCIS ".sdb") OR ((RegistryKeyPath ContainsCIS "AppInit_DLLs" OR RegistryPath  ContainsCIS "AppCompatFlags") AND (EventType = "Registry Value Create" OR EventType = "Registry Value Modified"))
```

### T1548.002 Bypass User Access Control
Atomics: [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md)

Detection of UAC bypass through tampering with Shell Open for .ms-settings or .msc file types.
`Noted issues with Sentinel Agent 4.3.2.86 detecting by registry key. All registry key paths wer ControlSet001\Service\bam\State\UserSettings\GUID\...`

```
SrcProcCmdLine ContainsCIS "ms-settings\shell\open\command" OR SrcProcCmdLine ContainsCIS "mscfile\shell\open\command"
```

### T1574.012 COR Profiler
Atomics: [T1574.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.012/T1574.012.md)

Detection of unmanaged COR profiler hooking of .NET CLR through registry or process command.

```
(SrcProcCmdScript Contains "COR_" AND SrcProcCmdScript Contains "\Environment") OR RegistryKeyPath Contains "COR_PROFILER_PATH" OR SrcProcCmdScript Contains "$env:COR_"
```

### T1546.001 Change Default File Association
Atomics: [1546.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.001/T1546.001.md)

Detection of file association changes. Detection by registry is noisy due to problem filtering on registry root, so install/uninstall apps create noise.

```
--- File assoc change by registry
RegistryKeyPath In Contains Anycase ( "\shell\open\command" , "\shell\print\command" , "\shell\printto\command" ) AND EventType In ( "Registry Value Create" , "Registry Value Modified" )
```

Recommended (for now)
```
--- File assoc change by assoc command
TgtProcCmdLine ContainsCIS "assoc" and TgtProcCmdLine RegExp ".*=.*"
```

###  T1574.001 DLL Search Order Hijacking
Atomics: [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md)

Detection of DLL search order hijack for AMSI bypass. Search order bypasses can target more than AMSI, so this can be expanded upon greatly by switching the `ContainsCIS` to `In Contains Anycase(dll list)`.

```
(FileFullName ContainsCIS "amsi.dll" AND FileFullName Does Not ContainCIS "System32") AND EventType = "File Creation"
```

### T1574.002 DLL Side-Loading of Notepad++ GUP.exe
Atomics: [T1574.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.002/T1574.002.md)

Detection for GUP.exe side-loading a dll, where executable has a display name of "WinGup for Notepad++" and has non-standard source process. Keep an eye on Cross Process events or add `AND EventType = "Open Remote Process Handle"` to the query to narrow down target (child) process.

```
TgtProcDisplayName ContainsCIS "WinGup" and SrcProcName Not In ("notepad++.exe","explorer.exe","lsass.exe","csrss.exe","svchost.exe","WerFault.exe")
```

### T1078.001 Enable Guest account with RDP and Admin
Atomics: [T1078.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.001/T1078.001.md)

Detects enabling of Guest account, adding Guest account to groups, as well as changing of Deny/Allow of Terminal Server connections through Registry changes.

```
(SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified"))
```

### T1546.012 Image File Execution Options Injection
Atomics: [T1546.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.012/T1546.012.md)

Detection of Image File Execution Options tampering for persistence through Registry monitoring.

```
RegistryKeyPath In Contains Anycase ("CurrentVersion\Image File Execution Options","CurrentVersion\SilentProcessExit") AND RegistryKeyPath In Contains Anycase ("GlobalFlag","ReportingMode","MonitorProcess")
```

### T1037.001 Logon Scripts (Windows)
Atomics: [T1037.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.001/T1037.001.md)

Detects addition of logon scripts through command line or registry methods.

```
SrcProcCmdLine ContainsCIS "UserInitMprLogonScript" OR (RegistryKeyPath ContainsCIS "UserInitMprLogonScript" AND EventType = "Registry Value Create")
```
