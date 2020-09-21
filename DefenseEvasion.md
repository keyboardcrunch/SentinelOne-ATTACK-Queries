## Defense Evasion

### T1055.004 Asynchronous Procedure Call
Atomics: [T1055.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.004/T1055.004.md)

SentinelOne isn't great at detecting all 5 injection methods, only 1 indicator of **RemoteInjection** is caught (Agent v. 4.3.2.86, Liberty SP2). In the future you could probably look for unsigned processes with some sort of combination of **Cross Process** event types > ##.

Reviewing process execution data for T1055.exe, I noted 4 child calc.exe processes and 2 notepad.exe child processes with their own calc.exe children; both notepad.exe instances had 2 **Process** events despite only having one child (most with **CrossProcess** entries in_storyline but only 1 storyline_child).

### T1197 BITS Jobs
Atomics: [T1197](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md)

The below query will find and remote content downloads from DesktopImgDownldr or BitsAdmin processes, Start-BitsTransfer cmdlet downloads, and excludes system processes and noise with SrcProcParentName Not In ().

```
(( TgtProcName In Contains Anycase ("bitsadmin.exe","desktopimgdownldr.exe") AND ( TgtProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)" OR TgtProcCmdLine ContainsCIS "/setnotifycmdline " ) ) OR ( TgtProcName = "powershell.exe" AND TgtProcCmdLine ContainsCIS "Start-BitsTransfer" ) ) AND SrcProcParentName Not In ("services.exe","smss.exe","wininit.exe")
```

### T1548.002 Bypass User Access Control
Atomics: [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md)

Detection of UAC bypass through tampering with Shell Open for .ms-settings or .msc file types.
`Noted issues with Sentinel Agent 4.3.2.86 detecting by registry key. All registry key paths wer ControlSet001\Service\bam\State\UserSettings\GUID\...`

```
SrcProcCmdLine ContainsCIS "ms-settings\shell\open\command" OR SrcProcCmdLine ContainsCIS "mscfile\shell\open\command"
```

### T1218.003 CMSTP
Atomics: [T1218.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.003/T1218.003.md)

CMSTP is rarely used within my environment, so the below detection has low false positives without filtering, though you may want to limit query to inf files located in personal/writeable directories.

```
SrcProcName = "cmstp.exe" AND SrcProcCmdLine RegExp "^.*\.(inf)"
```

### T1574.012 COR_PROFILER
Atomics: [T1574.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.012/T1574.012.md)

Detection of unmanaged COR profiler hooking of .NET CLR through registry or process command.

```
(SrcProcCmdScript Contains "COR_" AND SrcProcCmdScript Contains "\Environment") OR RegistryKeyPath Contains "COR_PROFILER_PATH" OR SrcProcCmdScript Contains "$env:COR_"
```

### T1070.001 Clear Windows Event Logs
Atomics: [T1070.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md)

Detects the clearing of EventLogs through wevtutil (concise) as well as Clear-EventLog through CommandLine and CommandScript objects. Powershell cmdlet detection returns a lot of noise for the CommandScripts object, so filtering out *SrcProcParentName* may be required.

```
(TgtProcName  = "wevtutil.exe" AND TgtProcCmdLine ContainsCIS "cl ") OR ((SrcProcCmdLine ContainsCIS "Clear-EventLog" OR SrcProcCmdScript ContainsCIS "Clear-EventLog") AND SrcProcParentName Not In ("WmiPrvSE.exe","PFERemediation.exe","svchost.exe"))
```

### T1027.004 Compile After Delivery
Atomics: [T1027.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.004/T1027.004.md)

Both Atomic tests for this technique leverage csc.exe for compilation of code. The below will detect specific compilation of executables as well as dynamic compilation through detection of csc.exe creating executable files (both dll and exe). Filter noise from later portion of query using *SrcProcParentName Not In ()*.

```
(TgtProcName = "csc.exe" AND SrcProcCmdLine Contains "/target:exe") OR (SrcProcName  = "csc.exe" AND TgtFileIsExecutable = "true" AND SrcProcParentName Not In ("svchost.exe"))
```

### T1218.001 Compiled HTML File
Atomics: [T1218.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md)

Breaking down the below query, the first section will detect Atomic Test 1 where a malicious chm file spawns a process, whereas the second half of the query detects hh.exe loading a remote payloads.

```
(SrcProcName = "hh.exe" AND EventType = "Open Remote Process Handle") OR (SrcProcName = "hh.exe" AND SrcProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)")
```

### T1218.002 Control Panel
Atomics: [T1218.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.002/T1218.002.md)

The below query will find all cpl files outside standard directories and all cpl files executed outside of Windows directories. First portion of query may need to be dropped if there's too much noise in your environment.

```
(TgtFileExtension = "cpl" AND TgtFilePath Does Not ContainCIS "C:\Windows" AND TgtFilePath Does Not ContainCIS "C:\Program Files" AND TgtFilePath Does Not ContainCIS "C:\$WINDOWS.~BT") OR (SrcProcName = "control.exe" AND SrcProcCmdLine ContainsCIS ".cpl" AND SrcProcCmdLine Does Not ContainCIS "C:\Windows")
```

In the future, when Process type counts are working, it may be more accurate to detect execution of cpl files where EventType **Open Remote Process Handle** or **Duplicate Process Handle** exists, though that can be added to above for filtering but would exclude Process type data.

```
SrcProcName = "rundll32.exe" AND SrcProcCmdLine ContainsCIS "Shell32.dll,Control_RunDLL" AND CrossProcOpenProcCount > 0
```

### T1574.001 DLL Search Order Hijacking
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

### T1140 Deobfuscate/Decode Files or Information
Atomics: [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md)

This Atomic tests detections of certutil encoding and decoding of executables, and the replication of certutil for bypassing detection of executable encoding. Our query below will detected renamed certutil through matching of DisplayName, as well as encoding or decoding of exe files.

```
(TgtProcName != "certutil.exe" AND TgtProcDisplayName = "CertUtil.exe") OR ( TgtProcDisplayName = "CertUtil.exe" AND (TgtProcCmdLine RegExp "^.*(-decode).*\.(exe)" OR TgtProcCmdLine RegExp "^.*(-encode).*\.(exe)") )
```

### T1562.002 Disable Windows Event Logging
Atomics: [T1562.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.002/T1562.002.md)

#### Atomic #1 - Disable IIS Logging

```
TgtProcName = "appcmd.exe" AND TgtProcCmdLine ContainsCIS "/dontLog:true" AND TgtProcCmdLine ContainsCIS "/section:httplogging"
```

#### Atomic #2 - Kill Eventlog Service Threads

Detection is specific to Invoke-Phant0m strings as the test uses it, and we're hoping to catch renamed and obfuscated versions by catching the TerminateThread call.

```
SrcProcCmdLine ContainsCIS "Invoke-Phant0m" OR SrcProcCmdScript ContainsCIS "$Kernel32::TerminateThread($getThread" OR SrcProcCmdScript ContainsCIS "Invoke-Phant0m"
```

### T1562.004 Disable or Modify System Firewall
Atomics: [T1562.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.004/T1562.004.md)

### T1562.001 Disable or Modify Tools
Atomics: [T1562.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md)

### T1564.001 Hidden Files and Directories
Atomics: [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md)

### T1564.003 Hidden Window
Atomics: [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md)

### T1070 Indicator Removal on Host
Atomics: [T1070](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.md)

### T1202 Indirect Command Execution
Atomics: [T1202](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1202/T1202.md)

### T1553.004 Install Root Certificate
Atomics: [T1553.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1553.004/T1553.004.md)

### T1218.004 InstallUtil
Atomics: [T1218.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md)

### T1127.001 MSBuild
Atomics: [T1127.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md)

### T1112 Modify Registry
Atomics: [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md)

### T1218.005 Mshta
Atomics: [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md)

SentinelOne happens to be pretty good at detecting MSHTA attacks, and *IndicatorName = "SuspiciousScript"* specifically picks out these javascript based attacks very well. The below query will detect mshta.exe spawning processes as well as URLs for remote payloads to be loaded by mshta.

```
(SrcProcName = "mshta.exe" and EventType = "Open Remote Process Handle") OR (SrcProcName = "mshta.exe" AND SrcProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)")
```

### T1218.007 Msiexec
Atomics: [T1218.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md)

The below query will accurately detect execution of remote msi files by msiexec.exe. The second half of the query aims to detect processes spawned by msi files instead of dll files in the CommandLine (as that is very noisy) and may return a bit of noise within for the CrossProcess Object as some auto-update processes may be collected by this query.

```
( SrcProcName = "msiexec.exe" AND SrcProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)" ) OR (SrcProcName RegExp "^.*\.(tmp)" AND EventType = "Open Remote Process Handle" AND SrcProcParentName = "msiexec.exe")
```

### T1564.004 NTFS File Attributes
Atomics: [T1564.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.004/T1564.004.md)

### T1070.005 Network Share Connection Removal
Atomics: [T1070.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.005/T1070.005.md)

### T1027 Obfuscated Files or Information
Atomics: [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md)

### T1218.008 Odbcconf
Atomics: [T1218.008](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.008/T1218.008.md)

### T1134.004 Parent PID Spoofing
Atomics: [T1134.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1134.004/T1134.004.md)

Detects parent PID spoofing through Cross Process indicators (SrcProcParentName limits scope heavily) as well as detecting the use of PPID-Spoof powershell script through Command Scripts indicators. Update the `TgtProcName` list to filter noise.

```
(TgtProcRelation = "not_in_storyline" AND EventType = "Open Remote Process Handle" AND SrcProcParentName In Contains Anycase ("userinit.exe","powershell.exe","cmd.exe") AND TgtProcName != "sihost.exe" And TgtProcIntegrityLevel  != "LOW" AND TgtProcName Not In ("SystemSettings.exe")) OR (SrcProcCmdScript ContainsCIS "PPID-Spoof" AND SrcProcCmdScript ContainsCIS "hSpoofParent = [Kernel32]::OpenProcess")
```

### T1550.002 Pass the Hash
Atomics: [T1550.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.002/T1550.002.md)

### T1550.003 Pass the Ticket
Atomics: [T1550.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.003/T1550.003.md)

### T1556.002 Password Filter DLL
Atomics: [T1556.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1556.002/T1556.002.md)

### T1574.009 Unquoted Service Path for program.exe
Atomics: [T1574.009](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.009/T1574.009.md)

Detects creation or modification of the file at `C:\program.exe` for exploiting unquoted services paths of Program Files folder.

```
(FileFullName = "C:\program.exe" AND EventType In ("File Creation","File Modification")) OR TgtProcImagePath = "C:\program.exe"
```

### T1055.012 Process Hollowing
Atomics: [T1055.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md)

Detect Process Hollowing using the Start-Hollow powershell script, through CommandLine and CommandScript indicators.

The `IndicatorCategory = "Injection"` has a lot of noise, but in the future a combination of `EventType = "Duplicate Process Handle" AND TgtProcRelation = "storyline_child"` joined with some `ChildProcCount` or `CrossProcCount` > 0 may help filter the noise.

```
--- Detect Start-Hollow.ps1 by command or content
(SrcProcCmdScript ContainsCIS "Start-Hollow" AND SrcProcCmdScript ContainsCIS "[Hollow]::NtQueryInformationProcess") OR TgtProcCmdLine ContainsCIS "Start-Hollow"
```

### T1055 Process Injection
Atomics: [T1055](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055/T1055.md)

Detects Process Injection through execution of MavInject, filtering out noisy/expected activity. `SrcProcParentName` filter narrows Cross Process items to HQ results.

```
(TgtProcName = "mavinject.exe" AND TgtProcCmdLine ContainsCIS "/injectrunning") AND (SrcProcName Not In ("AppVClient.exe") AND SrcProcParentName Not In ("smss.exe"))
```

### T1218.009 PubPrn
Atomics: [T1218.009](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1216.001/T1216.001.md)

### T1218.009 Regsvcs/Regasm
Atomics: [T1218.009](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md)

### T1218.010 Regsvr32
Atomics: [T1218.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md)

### T1036.003 Rename System Utilities
Atomics: [T1036.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.md)

### T1207 Rogue Domain Controller
Atomics: [T1207](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1207/T1207.md)

### T1014 Rootkit
Atomics: [T1014](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1014/T1014.md)

### T1218.011 Rundll32
Atomics: [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md)

### T1574.010 Services File Permissions Weakness
Atomics: [T1574.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.010/T1574.010.md)

### T1574.011 Services Registry Permissions Weakness
Atomics: [T1574.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.011/T1574.011.md)

### T1218 Signed Binary Proxy Execution
Atomics: [T1218](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md)

### T1216 Signed Script Proxy Execution
Atomics: [T1216](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1216/T1216.md)

### T1070.006 Timestomp
Atomics: [T1070.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md)

### T1222.001 Windows File and Directory Permissions Modification
Atomics: [T1222.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.001/T1222.001.md)

### T1220 XSL Script Processing
Atomics: [T1220](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1220/T1220.md)