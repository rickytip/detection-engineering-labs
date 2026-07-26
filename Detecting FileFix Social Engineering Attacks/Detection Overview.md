## Description
The FileFix technique is a newly discovered social engineering attack by security researcher mr.d0x, designed to replace traditional ClickFix attack methods.

This method addresses the limitations of traditional ClickFix, which relies heavily on the Windows Run dialog, by providing a more covert attack path.

Attackers create fake file-sharing pages, claiming there are important files for the user to access. When the user clicks the “Open File Explorer” button, malicious code copies a PowerShell command to the clipboard and uses an HTML file input element to trigger the File Explorer window. Following on-screen instructions, the user pastes the supposed “file path” into the address bar, but actually executes a malicious command hidden after a comment symbol.

Since all related processes are spawned by the browser, this attack can bypass process-origin based security checks and behavior analysis systems. Detecting these attacks is crucial for effective security defense. The entire initial lure occurs within the browser, significantly reducing user awareness of the threat.

## Challenge Objective
Write detection rules to identify this new type of social engineering attack. Focus on suspicious child processes spawned by browser processes.

When writing your detection queries, ensure that the Computer field is included in the output for further validation.

## Data Sample
Data source: Sysmon. Sample data:

{
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -c ping example.com                                                                                                                # C:\\company\\internal-secure\\filedrive\\HRPolicy.docx",
  "Company": "Microsoft Corporation",
  "Computer": "DESKTOP-xxxx",
  "CurrentDirectory": "C:\\Users\\admin\\",
  "Description": "Windows PowerShell",
  "EventId": "1",
  "EventRecordID": "15889",
  "FileVersion": "10.0.19041.546 (WinBuild.160101.0800)",
  "Hashes": "MD5=04029E121A0CFA5991749937DD22A1D9,SHA256=9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F66CCD9F,IMPHASH=7C955A0ABC747F57CCC4324480737EF7",
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "IntegrityLevel": "Medium",
  "Keywords": "0x8000000000000000",
  "Level": "4",
  "LogonGuid": "{769c9af7-1cf4-6853-bc31-1c0000000000}",
  "LogonId": "0x1c31bc",
  "Opcode": "0",
  "OriginalFileName": "PowerShell.EXE",
  "ParentCommandLine": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=utility --utility-sub-type=chrome.mojom.UtilWin --lang=zh-CN --service-sandbox-type=none --message-loop-type-ui --metrics-shmem-handle=5516,i,4121256205318589965,8127675130075570963,524288 --field-trial-handle=1988,i,11783799437491543251,15239349582065691069,262144 --variations-seed-version=20250623-050040.903000 --mojo-platform-channel-handle=5524 /prefetch:8",
  "ParentImage": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "ParentProcessGuid": "{769c9af7-0766-685a-5c1a-000000000500}",
  "ParentProcessId": "10932",
  "ParentUser": "DESKTOP-xxxx\\admin",
  "ProcessGuid": "{769c9af7-076c-685a-621a-000000000500}",
  "ProcessId": "10600",
  "Product": "Microsoft? Windows? Operating System",
  "ProviderGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
  "ProviderName": "Microsoft-Windows-Sysmon",
  "RuleName": "-",
  "Task": "1",
  "TerminalSessionId": "1",
  "ThreadId": "4000",
  "TimeCreated": "2025-06-24T02:03:24.6630057Z",
  "User": "DESKTOP-xxxx\\admin",
  "UserId": "S-1-5-18",
  "UtcTime": "2025-06-24 02:03:24.661",
}
## References
https://mrd0x.com/filefix-clickfix-alternative/

## Results 
<img width="944" height="702" alt="Screenshot 2026-07-25 at 11 25 13 PM" src="https://github.com/user-attachments/assets/96d0725e-bdde-4d0e-9894-ae91a45bc6e0" />
