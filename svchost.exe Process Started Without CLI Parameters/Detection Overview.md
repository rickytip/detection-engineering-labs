## Description
In Windows, svchost.exe is a core process that hosts system services. It typically starts with parameters such as -k,-s, or -p, launched by services.exe to load a specified service group through the standard process. An svchost.exe instance without any command-line parameters does not conform to the normal service startup pattern and is generally considered highly suspicious in threat hunting, especially when used by malicious processes for memory injection or masquerading to evade detection.

Promptly identifying such abnormal startups is critical for uncovering potential malicious memory injection and persistent execution activities.

## Challenge Objective
Write a rule to detect the creation of svchost.exe processes that start without any command-line parameters.

## Data Sample
Data source: Sysmon; sample data:

{
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "CommandLine": "C:\\WINDOWS\\system32\\svchost.exe",
  "Company": "Microsoft Corporation",
  "Computer": "DESKTOP-9J6KYCS",
  "CurrentDirectory": "C:\\WINDOWS\\system32\\",
  "Description": "Host Process for Windows Services",
  "EventId": 1,
  "FileVersion": "10.0.19041.5794 (WinBuild.160101.0800)",
  "Hashes": "MD5=3D1034D6ED3DAED60816A25C561E8C83,SHA256=B0B36BFF7AE4057F687D839CD4B3D81159AB646F1EE1B22106A927E93DECBB61,IMPHASH=F9BBD96FAE53B7A31264A703CAFA0666",
  "Image": "C:\\Windows\\System32\\svchost.exe",
  "IntegrityLevel": "System",
  "LogonGuid": "{769c9af7-9b57-689e-e703-000000000000}",
  "LogonId": "0x3e7",
  "OriginalFileName": "svchost.exe",
  "ParentCommandLine": "C:\\WINDOWS\\system32\\services.exe",
  "ParentImage": "C:\\Windows\\System32\\services.exe",
  "ParentProcessGuid": "{769c9af7-9b57-689e-0b00-000000000e00}",
  "ParentProcessId": "656",
  "ParentUser": "NT AUTHORITY\\SYSTEM",
  "ProcessGuid": "{769c9af7-9f49-689e-3601-000000000e00}",
  "ProcessId": "9696",
  "Product": "Microsoft? Windows? Operating System",
  "RuleName": "-",
  "SystemTime": "2025-08-11T02:45:29.8255709Z",
  "TerminalSessionId": "0",
  "User": "NT AUTHORITY\\SYSTEM",
  "UtcTime": "2025-08-11 02:45:29.795",
}
## References
https://nasbench.medium.com/the-fragile-balance-assumptions-tuning-and-telemetry-limits-in-detection-engineering-a32ae6802995

## Results 
<img width="948" height="699" alt="Screenshot 2026-07-26 at 12 47 05 PM" src="https://github.com/user-attachments/assets/927f8deb-a98e-4947-a3db-4591e702745f" />
