## Description
Brute-force attacks use systematic attempts of numerous password combinations to gain access to target systems. These attacks rely on automated tools to quickly generate and test common passwords, dictionary-based guesses, or purely random combinations until the correct credentials are found.

Attackers typically use brute-force techniques to target remote desktop services, SSH, web application login portals, and more. In Windows environments, attackers often employ tools such as Hydra, Medusa, or custom scripts to perform password attacks against domain controllers, workstations, or servers. The primary advantage of this method is that it doesn’t require exploiting complex vulnerabilities—success depends solely on the presence of weak or default credentials. Once valid account access is gained, attackers can escalate privileges, move laterally, and steal data.

Prompt detection of brute-force activity is critical to prevent account compromise. By default, Windows systems log detailed authentication events, providing security teams with valuable data for attack detection.

## Challenge Objective
Develop detection rules to identify abnormal patterns of failed login attempts on Windows systems. Focus on clustering of failed authentication events within short time windows, considering factors such as failure count thresholds, timeframes, and relevant event types. The rules should effectively differentiate between occasional user mistakes and malicious, systematic password attacks.

When writing detection queries, ensure the IpAddress field is included in the output for further validation.

## Data Sample
Data source: Windows Security; sample data:
{
  "AuthenticationPackageName": "NTLM",
  "Channel": "Security",
  "Computer": "DESKTOP-OTKI0I3",
  "EventId": 4625,
  "FailureReason": "%%2313",
  "IpAddress": "172.26.81.196",
  "IpPort": "65100",
  "KeyLength": "0",
  "LmPackageName": "-",
  "LogonProcessName": "NtLmSsp ",
  "LogonType": "3",
  "ProcessId": "0x0",
  "ProcessName": "-",
  "Status": "0xc000006d",
  "SubStatus": "0xc000006a",
  "SubjectDomainName": "-",
  "SubjectLogonId": "0x0",
  "SubjectUserName": "-",
  "SubjectUserSid": "S-1-0-0",
  "SystemTime": "2025-07-02T08:08:25.0052826Z",
  "TargetDomainName": null,
  "TargetUserName": "alice",
  "TargetUserSid": "S-1-0-0",
  "TransmittedServices": "-",
  "WorkstationName": "\\\\172.26.81.196"
}
## References
https://www.imperva.com/learn/application-security/brute-force-attack/

## Results 
<img width="942" height="695" alt="Screenshot 2026-07-26 at 10 26 06 AM" src="https://github.com/user-attachments/assets/b0d0d5e0-785b-47bb-b612-e2c0eb3a5eb9" />
