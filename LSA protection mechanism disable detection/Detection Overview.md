## Description
The Local Security Authority (LSA) is a critical Windows component responsible for authentication and security policy. To prevent malware from extracting sensitive credentials from LSA memory, Microsoft introduced LSA Protection (RunAsPPL), which runs the LSA process as a Protected Process Light (PPL) to block code injection and unauthorized memory access.

When LSA Protection is enabled, even processes with administrative privileges cannot directly access the LSA process memory, effectively blocking common attack paths used by credential theft tools such as Mimikatz. However, threat actors can disable this protection by modifying the registry—typically by setting the RunAsPPL value to 0 or deleting it entirely under HKLM\SYSTEM\CurrentControlSet\Control\Lsa. Such changes typically occur during persistence and lateral movement after privilege escalation.

## Challenge Objective
Write detection rules to identify attempts to disable LSA Protection by modifying the registry.

## Data Sample
Data source: Sysmon; sample data:

{
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "CommandLine": "reg  add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v \"RunAsPPL\" /t REG_DWORD /d 0 /f",
  "Company": "Microsoft Corporation",
  "Computer": "WIN-87LD21GGNKN",
  "CurrentDirectory": "C:\\Users\\Administrator\\",
  "Description": "Registry Console Tool",
  "EventId": "1",
  "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)",
  "Hashes": "SHA256=19316D4266D0B776D9B2A05D5903D8CBC8F0EA1520E9C2A7E6D5960B6FA4DCAF",
  "Image": "C:\\Windows\\System32\\reg.exe",
  "IntegrityLevel": "High",
  "LogonGuid": "{1e044158-49a4-687f-43b6-060000000000}",
  "LogonId": "0x6b643",
  "OriginalFileName": "reg.exe",
  "ParentCommandLine": "\"C:\\Windows\\system32\\cmd.exe\"",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "ParentProcessGuid": "{1e044158-dece-6881-8d02-000000000300}",
  "ParentProcessId": "5708",
  "ParentUser": "WIN-87LD21GGNKN\\Administrator",
  "ProcessGuid": "{1e044158-547e-6894-f502-000000000300}",
  "ProcessId": "6332",
  "Product": "Microsoft? Windows? Operating System",
  "RuleName": "-",
  "SystemTime": "2025-08-07T07:23:42.370570400Z",
  "TerminalSessionId": "1",
  "User": "WIN-87LD21GGNKN\\Administrator",
  "UtcTime": "2025-08-07 07:23:42.369",
}
## References
https://www.atomicredteam.io/docs/atomics/T1685#atomic-test-1---windows-disable-lsa-protection

## Results 
<img width="938" height="700" alt="Screenshot 2026-07-26 at 12 36 34 PM" src="https://github.com/user-attachments/assets/8f8d25ef-85c0-4d19-b8ff-97b443f276e1" />
