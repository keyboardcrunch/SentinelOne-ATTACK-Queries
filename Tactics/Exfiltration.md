## Exfiltration

There are a number of ways to use current supported indicators to detect data exfiltration, some with higher accuracy than others. Detection by command lines can have environmental noise, detection based on network connection indicators may require lost of custom filtering as well. Exfiltration queries need to be expanded, but for now I've limited them to the Atomic Red Team tests that can be detected.

### T1020 Automated Exfiltration
Atomics: [T1020](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1020/T1020.md)

Detection of powershell data POST and PUT with Invoke-WebRequest. 

```
SrcProcCmdLine ContainsCIS "Invoke-WebRequest" AND (SrcProcCmdLine ContainsCIS "-Method Put" OR SrcProcCmdLine ContainsCIS "-Method Post")
```
