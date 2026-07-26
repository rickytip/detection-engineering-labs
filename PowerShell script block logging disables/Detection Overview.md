## Description
PowerShell ScriptBlock Logging is a crucial security auditing mechanism in Windows systems, recording all script content executed by PowerShell, including obfuscated, encoded, or dynamically generated code. This feature provides security teams with critical evidence to trace malicious activity, especially important in fileless attacks and memory execution scenarios.

In actual attack campaigns, disabling script block logging is a common anti-forensic technique used by attackers to achieve covert execution. By modifying specific keys in the Windows Registry, this auditing function can be disabled, preventing subsequent malicious PowerShell activity from being recorded. This behavior typically occurs early in the attack chain, followed by attackers performing privilege escalation, lateral movement, or data theft, activities that leave no trace in the script block log.

Detecting such disabling behavior is critical, as it is itself a strong indicator of attack intent. Normal system administration and enterprise IT operations rarely require disabling this security feature; any such operation should be treated as a high-priority security incident for investigation.

## Challenge Objective
Write detection rules to identify behaviors that disable PowerShell script block logging by modifying system configuration. Pay special attention to modifications made to paths in the Windows Registry related to PowerShell logging policies.

## Data Sample
Data source Sysmon, data sample:

{
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "CommandLine": "reg  add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f",
  "Company": "Microsoft Corporation",
  "Computer": "WIN-G9CK1G40D1P",
  "CurrentDirectory": "C:\\Users\\Administrator\\",
  "Description": "Registry Console Tool",
  "EventId": 1,
  "FileVersion": "10.0.17763.1 (WinBuild.160101.0800)",
  "Hashes": "MD5=8A93ACAC33151793F8D52000071C0B06,SHA256=19316D4266D0B776D9B2A05D5903D8CBC8F0EA1520E9C2A7E6D5960B6FA4DCAF,IMPHASH=BE482BE427FE212CFEF2CDA0E61F19AC",
  "Image": "C:\\Windows\\System32\\reg.exe",
  "IntegrityLevel": "High",
  "LogonGuid": "{ce9671a3-5e15-690c-a80b-060000000000}",
  "LogonId": "0x60ba8",
  "OriginalFileName": "reg.exe",
  "ParentCommandLine": "\"C:\\Windows\\system32\\cmd.exe\" ",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "ParentProcessGuid": "{ce9671a3-941c-690d-b000-000000000300}",
  "ParentProcessId": "4480",
  "ParentUser": "WIN-G9CK1G40D1P\\Administrator",
  "ProcessGuid": "{ce9671a3-9566-690d-cc00-000000000300}",
  "ProcessId": "4692",
  "Product": "Microsoft? Windows? Operating System",
  "RuleName": "-",
  "SystemTime": "2025-11-07T06:44:54.156713700Z",
}
## References
https://powershellcommands.com/turn-on-powershell-script-block-logging
https://www.seamlessintelligence.com.au/powershell_script_block_logging.html

## Results 
<img width="945" height="705" alt="Screenshot 2026-07-26 at 4 58 04 PM" src="https://github.com/user-attachments/assets/0875472b-d51d-43fe-8fc0-95c5420b861c" />
