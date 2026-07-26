## Description
When attackers use the net user command to create accounts, adding a $ symbol at the end of the account name grants the account hidden attributes. This account cannot be identified through the net user command and will not appear in standard user management interfaces, yet it maintains full system access privileges.

This technique is commonly used for persistence, hiding backdoor accounts to evade detection and monitoring.

## Challenge Objective
Write detection rules to identify hidden account creation behavior through commands, focusing on command-line parameter structures.

## Data Sample
Data source: Sysmon; sample data:

{
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "CommandLine": "net  user test$ /add",
  "Company": "Microsoft Corporation",
  "Computer": "DESKTOP-CKIF9E6",
  "CurrentDirectory": "C:\\Windows\\system32\\",
  "Description": "Net Command",
  "EventId": 1,
  "FileVersion": "10.0.19041.1 (WinBuild.160101.0800)",
  "Hashes": "MD5=0BD94A338EEA5A4E1F2830AE326E6D19,SHA256=9F376759BCBCD705F726460FC4A7E2B07F310F52BAA73CAAAAA124FDDBDF993E,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07",
  "Image": "C:\\Windows\\System32\\net.exe",
  "IntegrityLevel": "High",
  "LogonGuid": "{95fc43c0-e0e6-68f1-d2f5-bb0000000000}",
  "LogonId": "0xbbf5d2",
  "OriginalFileName": "net.exe",
  "ParentCommandLine": "\"C:\\Windows\\system32\\cmd.exe\" ",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "ParentProcessGuid": "{95fc43c0-e062-68fa-5222-000000000800}",
  "ParentProcessId": "11532",
  "ParentUser": "DESKTOP-CKIF9E6\\admin",
  "ProcessGuid": "{95fc43c0-e40c-68fa-8f22-000000000800}",
  "User": "DESKTOP-CKIF9E6\\admin"
}
## References
https://borncity.com/blog/2021/05/11/windows-versteckte-benutzerkonten-anlegen-und-aufspren/

## Results
<img width="949" height="703" alt="Screenshot 2026-07-26 at 4 22 42 PM" src="https://github.com/user-attachments/assets/346b5428-e677-4ce5-839f-e16ce093b7a9" />
