## Execution

### T1053.002 AT Scheduled Task
Atomics: [T1053.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.002/T1053.002.md)

Detect interactive process execution scheduled by AT command.

```
TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive "
```

### T1559.002 Dynamic Data Exchange
Atomics: [T1559.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1559.002/T1559.002.md)

Latest Office 365 clients weren't executing DDE code but were providing warnings, so my simulations were unsucessful. The T1204.002 detection immediately below should cover processes spawned from Office applications.

### T1204.002 Malicious Documents
Atomics: [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md)

The tests for this technique overlap heavily with [T1566.001 Spearphishing Attachment](https://github.com/keyboardcrunch/SentinelOne-ATTACK-Queries/blob/master/InitialAccess.md#t1566001-spearphishing-attachment) due to similar download and macro detections, so here we're focusing on detecting Office applications launching processes. The below query will cover tests 1, 3 and 4 but test [#2](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md#atomic-test-2---ostap-payload-download) is standalone cscript execution and will be detected with other queries.

```
(SrcProcParentName In Contains ("WINWORD.EXE","EXCEL.EXE") AND SrcProcName In Contains Anycase ("cmd.exe","cscript.exe","wscript.exe","certutil.exe","powershell.exe","msbuild.exe","csc.exe")) OR IndicatorName = "SuspiciousDocument"
```

### T1106 Native API
Atomics: [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md)

There aren't any combination of available indicator types to query to find malicious uses of WinAPI for process execution, though this test can be detected through [T1027.004 Compile After Delivery](https://github.com/keyboardcrunch/SentinelOne-ATTACK-Queries/blob/master/Tactics/DefenseEvasion.md#t1027004-compile-after-delivery)

### T1059.001 PowerShell
Atomics: [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md)

Most of the Atomic Tests in this case are detected by their download cradles with [T1566.001 Test 1](https://github.com/keyboardcrunch/SentinelOne-ATTACK-Queries/blob/master/Tactics/InitialAccess.md#t1566001-spearphishing-attachment) or `IndicatorName = "ObfuscatedPSCommand"`, if not other LOLBAS detection methods for later portion of command execution.

### T1053.005 Scheduled Tasks
Atomics: [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md)

Our goal with this query is to detect any schtasks /create command as well as any use of the New-ScheduledTask* cmdlets from powershell, and to prevent noise from services and updates we'll exclude a list of system "trusted" SrcProcParentName executables.

```
(( TgtProcName = "schtasks.exe" AND TgtProcCmdLine ContainsCIS "/create" ) OR ( SrcProcCmdLine ContainsCIS "New-ScheduledTask" OR SrcProcCmdScript  ContainsCIS "New-ScheduledTask" )) AND SrcProcParentName Not In ("services.exe","OfficeClickToRun.exe")
```

**Optionally, leveraging the ScheduleTaskRegister Indicator object:**

```
IndicatorName = "ScheduleTaskRegister" AND SrcProcParentName Not In ("Integrator.exe","OfficeClickToRun.exe","services.exe","OneDriveSetup.exe","Ccm32BitLauncher.exe","WmiPrvSE.exe")
```

### T1569.002 Service Execution
Atomics: [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md)

The tests for this Atomic are lacking, so we'll go ahead and just detect sc.exe start or start-service. PSExec belongs in lateral movement detection, so I'll ignore Test 2.

```
(( SrcProcName = "sc.exe" AND SrcProcCmdLine ContainsCIS "create" ) OR SrcProcCmdLine ContainsCIS "Start-Service" ) AND SrcProcParentName != "services.exe"
```

### T1059.003 Windows Command Shell
Atomics: [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md)

Atomic test cases here simulate execution of batch files, so we're querying for bat files executed from temp directories where SrcProcParentName isn't an executable we want to filter. You can recycle the T1569.005 query directly below as a different method of detecting cmd.exe execution of bat files.

```
(SrcProcName = "cmd.exe" AND FileFullName ContainsCIS "\Temp" AND FileType = "bat") AND SrcProcParentName Not In ("msiexec.exe")
```

### T1059.005 Visual Basic
Atomics: [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md)

This Atomic is just execution of vbs files, but we'll narrow this down to execution of vbs files from any Temp\ directory to be more useful.

```
SrcProcName = "cscript.exe" AND SrcProcCmdLine RegExp "\bTemp\b.*\.(vbs)"
```

### T1047 Windows Management Instrumentation
Atomics: [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md)

The tests for this atomic are limited to execution of the wmic executable, so the below query has been limited to wmic.exe, and focuses on discovery and execution commandlines.

```
( SrcProcName = "WMIC.exe" AND SrcProcCmdLine In Contains Anycase ("useraccount get","process get","qfe get","service where","process call","call create") ) AND SrcProcParentName Not In ("msiexec.exe")
```