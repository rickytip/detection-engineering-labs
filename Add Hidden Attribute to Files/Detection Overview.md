## Description
In the Windows operating system, file attributes are an important part of file metadata. The hidden attribute allows files to remain invisible in the default file explorer view. While this feature has legitimate uses in system administration and software development, it is often abused by malware to evade detection.

Windows offers several ways to set the hidden attribute, including the attrib command-line tool, PowerShell cmdlets, and programming interfaces. The most common method is using the attrib command with the +h flag, such as attrib +h filename.ext. Attackers often combine this with the system (+s) and read-only (+r) attributes to further reduce the chance that the file will be discovered or deleted.

During privilege escalation, attackers may place hidden files in system directories or protected locations, waiting for privileged processes to execute them. In command and control scenarios, hidden backdoor programs are commonly used to establish persistent access.

## Challenge Objective
Write detection rules to identify hidden files created using the attrib command.

## Data Sample
Data source: Sysmon,sample data:

{
  "IntegrityLevel": "High",
  "TerminalSessionId": "1",
  "RuleName": "-",
  "CommandLine": "\"C:\\Windows\\system32\\attrib.exe\" +h C:\\Windows\\System32\\apprun.ps1",
  "Product": "Microsoft? Windows? Operating System",
  "Company": "Microsoft Corporation",
  "OriginalFileName": "ATTRIB.EXE",
  "User": "WIN-87LD21GGNKN\\Administrator",
  "ParentProcessId": "4032",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "ProcessGuid": "{1e044158-80b1-687f-a801-000000000300}",
  "Computer": "WIN-87LD21GGNKN",
  "CurrentDirectory": "C:\\Users\\Administrator\\Desktop\\",
  "Hashes": "SHA256=B101350BCEEB773B7E77759613BB33C28FBF1D79A13C2CB783575A9D893D52E6",
  "UtcTime": "2025-07-22 12:14:41.595",
  "ParentCommandLine": "\"PowerShell.exe\" -noexit -command Set-Location -literalPath 'C:\\Users\\Administrator\\Desktop\\EvtxeCmd'",
  "SystemTime": "2025-07-22T12:14:41.596579900Z",
  "Description": "Attribute Utility",
  "ProcessId": "2368",
  "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)",
  "ParentProcessGuid": "{1e044158-4b1e-687f-e400-000000000300}",
  "LogonGuid": "{1e044158-49a4-687f-43b6-060000000000}",
  "Image": "C:\\Windows\\System32\\attrib.exe",
  "LogonId": "0x6b643",
  "EventId": 1,
  "ParentUser": "WIN-87LD21GGNKN\\Administrator",
  "timestamp": "2025-07-22T21:17:08.519724"
}
## References
https://ss64.com/nt/attrib.html
