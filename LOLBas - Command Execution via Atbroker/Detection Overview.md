## Description
LOLBAS is an open-source project initiated by the security community, focused on collecting and organizing binaries, scripts, and libraries that can be used for Living Off The Land techniques.

The project primarily collects built-in Windows binaries and scripts that can be abused. In real-world attack scenarios, attackers often leverage these legitimate components as part of their attack chain to bypass security defenses.

Atbroker.exe is an Assistive Technology (AT) program in Windows responsible for launching and managing assistive technology services registered on the system.

By modifying specific registry configurations, Atbroker can be used to execute arbitrary code, serving as a stealthy method within an attack chain. Detecting the abuse of such tools helps identify highly evasive threat activities in a timely manner.

## Challenge Objective
Write detection rules to identify command execution operations performed using Atbroker.
## Data Sample
Data source:Sysmon,Sample data:
{
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "CommandLine": "Atbroker.exe",
  "Company": "Microsoft Corporation",
  "Computer": "DESKTOP-XXX",
  "CurrentDirectory": "C:\\Users\\admin\\AppData\\Local\\Temp\\",
  "Description": "Windows Assistive Technology Manager",
  "EventId": "1",
  "EventRecordID": "12430",
  "FileVersion": "10.0.19041.1023 (WinBuild.160101.0800)",
  "Hashes": "MD5=30076E434A015BDF4C136E09351882CC,SHA256=AE7B1E298A6E38F0A3428151BFC5565EDE50A8D98DAFAA147B13CF89C61F2DDD,IMPHASH=468490D98938AAE93ECC62C54A775DC2",
  "Image": "C:\\Windows\\System32\\AtBroker.exe",
  "IntegrityLevel": "High",
  "Keywords": "0x8000000000000000",
  "Level": "4",
  "LogonGuid": "{769c9af7-1cf4-6853-8531-1c0000000000}",
  "LogonId": "0x1c3185",
  "Opcode": "0",
  "OriginalFileName": "ATBroker.exe",
  "ParentCommandLine": "\"C:\\WINDOWS\\system32\\cmd.exe\"    ",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "ParentProcessGuid": "{769c9af7-14c1-6859-8a14-000000000500}",
  "ParentProcessId": "5076",
  "ParentUser": "DESKTOP-XXX\\admin",
  "ProcessGuid": "{769c9af7-1582-6859-9514-000000000500}",
  "ProcessId": "4576",
  "Product": "Microsoft? Windows? Operating System",
  "ProviderGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
  "ProviderName": "Microsoft-Windows-Sysmon",
  "RuleName": "-",
  "Task": "1",
  "TerminalSessionId": "1",
  "ThreadId": "4000",
  "TimeCreated": "2025-06-23T08:51:14.3325910Z",
  "User": "DESKTOP-XXX\\admin",
  "UserId": "S-1-5-18",
  "UtcTime": "2025-06-23 08:51:14.330",
}
## References
https://lolbas-project.github.io/lolbas/Binaries/Atbroker/

## Results 
<img width="940" height="708" alt="Screenshot 2026-07-25 at 10 52 46 PM" src="https://github.com/user-attachments/assets/b621258c-efab-4997-9701-b7408536d821" />
