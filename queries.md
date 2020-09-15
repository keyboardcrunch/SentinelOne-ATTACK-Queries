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
--- T1546 Application Shimming
(SrcProcName = "sdbinst.exe" and ProcessCmd ContainsCIS ".sdb") OR ((RegistryKeyPath ContainsCIS "AppInit_DLLs" OR RegistryPath  ContainsCIS "AppCompatFlags") AND (EventType = "Registry Value Create" OR EventType = "Registry Value Modified"))
```

### T1548.002 Bypass User Access Control
Atomics: [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md)

Detection of UAC bypass through tampering with Shell Open for .ms-settings or .msc file types.
`Noted issues with Sentinel Agent 4.3.2.86 detecting by registry key. All registry key paths wer ControlSet001\Service\bam\State\UserSettings\GUID\...`

```
SrcProcCmdLine ContainsCIS "ms-settings\shell\open\command" OR SrcProcCmdLine ContainsCIS "mscfile\shell\open\command"
```
