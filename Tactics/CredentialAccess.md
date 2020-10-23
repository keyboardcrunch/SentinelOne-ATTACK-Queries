## Credential Access


### T1056.004 Credential API Hooking
Atomics: [T1056.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.004/T1056.004.md)

The weight of this test relies on injecting a dll with mavinject that hooks into powershell to do the TLS decryption, our detection for [T1055 Mavinject](https://github.com/keyboardcrunch/SentinelOne-ATTACK-Queries/blob/9da3392c991c2badcb88a715e791a55654c1c567/Tactics/DefenseEvasion.md#t1055-process-injection) would cover us for these tests.

### T1552.001 Credentials In Files
Atomics: [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md)

#### Test #1 - LaZagne
LaZagne happens to spawn 3 cmd shells to save security, system and sam RegKeys, and the standard compiled release from github will have the original name artifact of lazagne.exe.manifest within the %temp%\_MEI?????\lazagne.exe.manifest location.
`
TgtProcCmdline Contains "reg.exe save hklm\s" OR TgtFilePath Contains "lazagne.exe.manifest"
`

#### Test #3 - findstr password extraction
`
TgtProcCmdLine ContainsCIS "/si pass" OR TgtProcCmdLine ContainsCIS "-pattern password"
`

### T1555.003 Credentials from Web Browsers
Atomics: [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md)

#### Test #1 - Modified SysInternals AccessChk Chrome password collector

To focus on detection, we're looking for AccessChk.exe where the DisplayName does not match that of the original. There's 4X as many Cross_Process objects with this query but none detect the collection of the Chrome password db.

`
TgtProcName = "accesschk.exe" AND TgtProcDisplayName != "Reports effective permissions for securable objects"
`

### T1552.002 Registry Credential Enumeration
Atomics: [T1552.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.002/T1552.002.md)

This query detects enumeration and discovery of credentials within the Registry, including Putty sessions.

`
TgtProcCmdline ContainsCIS "query HKLM /f password /t REG_SZ /s" OR TgtProcCmdline ContainsCIS "query HKCU /f password /t REG_SZ /s" OR TgtProcCmdline ContainsCIS "query HKCU\Software\SimonTatham\PuTTY\Sessions /t REG_SZ /s"
`

### T1056.002 GUI Input Capture
Atomics: [T1056.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.002/T1056.002.md)

Focusing here on detecting the Powershell UI.PromptForCredential and GetNetworkCredential().Password in CmdScript or CmdLine.

`
(TgtProcCmdline ContainsCIS ".UI.PromptForCredential(" AND TgtProcCmdline ContainsCIS  ".GetNetworkCredential().Password") OR (SrcProcCmdScript ContainsCIS ".UI.PromptForCredential(" AND SrcProcCmdScript ContainsCIS  ".GetNetworkCredential().Password")
`

### T1552.006 Group Policy Preferences
Atomics: [T1552.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.006/T1552.006.md)

Detection focuses on sysvol GP Policy xml file enumeration, with findstr or Get-GPPPassword (Alias or CmdScript internal match).

`
TgtProcCmdline RegExp "^.*\/S cpassword.*\\sysvol\\.*.xml" OR TgtProcCmdline ContainsCIS "Get-GPPPassword" OR SrcProcCmdScript ContainsCIS "Get-ChildItem -Path \"\\$Server\SYSVOL\" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'"
`

### T1558.003 Kerberoasting
Atomics: [T1558.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md)


### T1056.001 Powershell Keylogging
Atomics: [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md)

I wasn't able to get either copy of the Get-Keystrokes.ps1 to work with powershell, but the below should reliably detect invocation by alias or CmdScript line matching.

`
TgtProcCmdline ContainsCIS "Get-Keystrokes" OR SrcProcCmdScript ContainsCIS "user32.dll GetAsyncKeyState" OR SrcProcCmdScript ContainsCIS "[Windows.Forms.Keys][Runtime.InteropServices.Marshal]::ReadInt32("
`

### T1003.004 LSA Secrets
Atomics: [T1003.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.004/T1003.004.md)

For simplicity, we're detecting a Cmdline used for both psexec (the test) as well as direct reg.exe LSA extraction.

`
TgtProcCmdLine ContainsCIS "save HKLM\security\policy\secrets"
`

### T1003.001 LSASS Memory Dumping
Atomics: [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md)

This one may look crazy but it's not. Detection of wce by hash, procdump, comsvc, dumpert, mimikatz, pypykatz, and werfault all in one query. 

`
TgtProcImageSha1 = "f0c52cea19c204f5cdbe952cc7cfc182e20d8d43" OR TgtProcCmdline ContainsCIS "-ma lsass.exe" OR TgtProcCmdline ContainsCIS "comsvcs.dll, MiniDump" OR TgtFilePath = "C:\Windows\Temp\dumpert.dmp" OR TgtFilePath RegExp "^.*lsass.*.DMP" OR (SrcProcCmdline ContainsCIS "sekurlsa::minidump" OR SrcProcCmdline ContainsCIS "sekurlsa::logonpasswords") OR SrcProcCmdline ContainsCIS "live lsa"
`

### T1003.003 NTDS
Atomics: [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md)


### T1040 Network Sniffing
Atomics: [T1040](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md)


### T1003 OS Credential Dumping
Atomics: [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md)


### T1110.002 Password Cracking
Atomics: [T1110.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.002/T1110.002.md)


### T1556.002 Password Filter DLL
Atomics: [T1556.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1556.002/T1556.002.md)


### T1110.001 Password Guessing
Atomics: [T1110.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.001/T1110.001.md)


### T1110.003 Password Spraying
Atomics: [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md)


### T1552.004 Private Keys
Atomics: [T1552.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md)


### T1003.002 Security Account Manager
Atomics: [T1003.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md)


