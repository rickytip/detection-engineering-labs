## Description
After gaining initial access to a Windows system, attackers often need to create hidden backdoor accounts to maintain persistent access. Traditional account creation methods display the account in the system user list, making it easy for administrators to discover. However, by modifying specific registry keys, attackers can completely hide created accounts from the login screen and user management interfaces while retaining full access privileges.

This technique is widely used by APT groups and red teams during the persistence phase due to its high stealth, low technical barrier, and difficulty of detection through routine security checks. Detecting such registry modification activities is critical for identifying potential privilege maintenance operations.

## Challenge Objective
Write a detection rule to identify behaviors that hide accounts through registry key modifications.

## Data Sample
Data source: Sysmon; sample data:

{
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Computer": "DESKTOP-xxxx",
  "Details": "DWORD (0x00000000)",
  "EventId": 13,
  "EventType": "SetValue",
  "Image": "C:\\Windows\\system32\\reg.exe",
  "ProcessGuid": "{95fc43c0-634f-6904-e944-000000000800}",
  "ProcessId": "7772",
  "RuleName": "-",
  "SystemTime": "2025-10-31T07:20:47.7340320Z",
  "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\\xxxx",
  "User": "DESKTOP-CKIF9E6\\admin",
  "UtcTime": "2025-10-31 07:20:47.729",
}
## References
https://www.atomicredteam.io/docs/atomics/T1564.002#atomic-test-3---create-hidden-user-in-registry

## Results 
<img width="949" height="707" alt="Screenshot 2026-07-26 at 4 35 42 PM" src="https://github.com/user-attachments/assets/4d1d7c59-f9ff-4f44-b11f-610efb159101" />
