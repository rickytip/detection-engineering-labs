## Description
PSExec.exe is a powerful utility in the Sysinternals (now Microsoft-owned) toolkit that allows administrators to execute commands and programs on remote computers without manually installing client software. As a legitimate system administration tool, it is widely used in enterprise environments for routine maintenance and management tasks.

However, due to its powerful remote execution capabilities and native trustworthiness, PSExec has become one of the most commonly exploited lateral movement tools by threat actors. To evade signature-based detection mechanisms, attackers typically employ tool renaming strategies, changing the original PSExec.exe file to other filenames while preserving its functional integrity. This simple yet effective evasion technique renders traditional filename-based detection methods ineffective.

## Challenge Objective
Using SIEM query statements to identify execution behavior of renamed PSExec.

## Data Sample
Data source: Sysmon, Sample data:

{
  "id": 0,
  "CommandLine": "C:\\Windows\\task.exe",
  "Company": "Sysinternals - www.sysinternals.com",
  "CurrentDirectory": "C:\\Users\\admin\\",
  "Description": "Execute processes remotely",
  "EventId": 1,
  "FileVersion": "2.43",
  "Hashes": "MD5=DB89EC570E6281934A5C5FCF7F4C8967,SHA256=EDFAE1A69522F87B12C6DAC3225D930E4848832E3C551EE1E7D31736BF4525EF,IMPHASH=8A589B59271D320348F6CDEC90A97E6C",
  "Image": "C:\\Windows\\task.exe",
  "IntegrityLevel": "Medium",
  "LogonGuid": "{769c9af7-71c8-6852-a0b6-a80000000000}",
  "LogonId": "0xa8b6a0",
  "OriginalFileName": "psexesvc.exe",
  "ParentCommandLine": "\"C:\\WINDOWS\\system32\\cmd.exe\" ",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "ParentProcessGuid": "{769c9af7-72f6-6852-2f06-000000000400}",
  "ParentProcessId": "2336",
  "ParentUser": "DESKTOP-PBEA012\\admin",
  "ProcessGuid": "{012b0ea2-739e-0012-2011-000000000400}",
  "ProcessId": "6852",
  "Product": "Sysinternals PsExec",
  "RuleName": "-",
  "TerminalSessionId": "1",
  "User": "DESKTOP-PBEA012\\admin",
  "UtcTime": "2025-06-18 08:06:54.614",
  "_X_ROW_KEY": "row_56"
}
## References
https://redcanary.com/threat-detection-report/techniques/rename-system-utilities/
https://www.elastic.co/guide/en/security/7.17/suspicious-process-execution-via-renamed-psexec-executable.html

## Results 
<img width="941" height="699" alt="Screenshot 2026-07-25 at 8 05 16 PM" src="https://github.com/user-attachments/assets/2c88c0bf-6911-4065-818e-d12ea8597341" />

