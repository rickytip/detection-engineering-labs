## Description
The Windows command interpreter (cmd.exe) supports “silent” execution via the start command with specific options. The /b option runs a program in the background without creating a new window, and /min starts a new window in a minimized state. Both can reduce or eliminate visible pop-ups, lowering user awareness.

Attackers often abuse this behavior to conceal malicious activity. Common examples include: macros in phishing documents silently launching a downloader, malware using a hidden window to unpack or deploy a second-stage payload, and creating scheduled tasks that run without noticeable windows to maintain persistence.

## Challenge Objective
Detect suspicious activity where cmd.exe uses the start command with window-hiding options. Focus on whether the command line contains flags that control window visibility.

## Data Sample
Data source: Sysmon; sample data:

{
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "CommandLine": "cmd.exe  /c start /B C:\\ProgramData\\emotet.bat",
  "Computer": "DESKTOP-TN5BM0V",
  "EventId": 1,
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "OriginalFileName": "Cmd.Exe",
  "ParentCommandLine": "\"C:\\Windows\\system32\\cmd.exe\" ",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "ParentUser": "DESKTOP-TN5BM0V\\admin",
  "ProcessId": "10164",
  "SystemTime": "2026-01-29T06:56:00.3270369Z",
}
## References
https://www.fortinet.com/blog/threat-research/ms-office-files-involved-in-emotet-trojan-campaign-pt-one

## Results 
<img width="949" height="702" alt="Screenshot 2026-07-26 at 6 02 19 PM" src="https://github.com/user-attachments/assets/20c771ce-87e7-4bf2-85f4-ec07a3c24846" />
