## Execution

### T1053.002 AT Scheduled Task
Atomics: [T1053.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.002/T1053.002.md)

Detect interactive process execution scheduled by AT command.

```
TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive "
```

### T1559.002 Dynamic Data Exchange
Atomics: [T1559.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1559.002/T1559.002.md)


### T1204.002 Malicious Documents
Atomics: [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md)

The tests for this technique overlap heavily with [T1566.001 Spearphishing Attachment](https://github.com/keyboardcrunch/SentinelOne-ATTACK-Queries/blob/a2fd4227666db3f1c5d6713ae3e3b21bf5343b79/InitialAccess.md#t1566001-spearphishing-attachment) due to similar download and macro detections, so here we're focusing on detecting Office applications launching processes. The below query will cover tests 1, 3 and 4 but test [#2](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md#atomic-test-2---ostap-payload-download) is standalone cscript execution and will be detected with other queries.

```
(SrcProcParentName In Contains ("WINWORD.EXE","EXCEL.EXE") AND SrcProcName In Contains Anycase ("cmd.exe","cscript.exe","wscript.exe","certutil.exe","powershell.exe","msbuild.exe","csc.exe")) OR IndicatorName = "SuspiciousDocument"
```

### T1106 Native API
Atomics: [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md)


### T1059.001 PowerShell
Atomics: [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md)


### T1053.005 Scheduled Task
Atomics: [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md)


### T1569.002 Service Execution
Atomics: [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md)


### T1059.005 Visual Basic
Atomics: [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md)


### T1059.003 Windows Command Shell
Atomics: [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md)


### T1047 Windows Management Instrumentation
Atomics: [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md)


