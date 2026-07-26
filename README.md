# Detection Engineering Portfolio

A hands-on detection engineering portfolio built through SOC Labs challenges. This repo contains **40+ detection rules** covering Linux, Windows, and AWS attack techniques — mostly authored in **Sigma**, with additional **KQL** (Microsoft Sentinel) and **SPL** (Splunk) queries where the challenge called for SIEM-native logic.

Each rule folder includes detection logic plus a short overview of the technique, data source, and detection objective.

---

## Summary

| Metric | Count |
| --- | ---: |
| Challenge labs | 43 |
| Detection rules | 40 |
| Sigma | 26 |
| KQL (Microsoft Sentinel) | 7 |
| SPL (Splunk) | 7 |

### Coverage by platform

| Platform | Rules | Focus areas |
| --- | ---: | --- |
| **Linux** | 17 | Defense evasion, credential access, execution, persistence, discovery |
| **Windows** | 11 | LOLBins, credential protection, hidden accounts, lateral movement, initial access |
| **AWS** | 12 | CloudTrail/VPC/DNS log impairment, data exfiltration, IAM, SSM abuse |

---

## Skills demonstrated

- Sigma rule development and SIEM-ready detection logic
- Translating adversary TTPs into detections across **Sigma**, **KQL**, and **SPL**
- Linux (process/audit-style telemetry), Windows (Sysmon), and AWS (CloudTrail) detection
- MITRE ATT&CK–aligned technique analysis
- Detection tuning (true/false positive tradeoffs — see `Data Transfer Size Limits`)

---

## Repository structure

```text
detection-rules/
├── <Challenge Name>/
│   ├── Detection Rule.yml          # Sigma, KQL, or SPL detection logic
│   ├── Detection Overview.md       # Technique context + challenge objective
│   └── Detection Development.md    # Optional tuning notes / iterations
└── README.md
```

### Rule formats

| Format | When used | Example pattern |
| --- | --- | --- |
| **Sigma** | Majority of labs — portable, SIEM-agnostic detections | `title` / `logsource` / `detection` YAML |
| **KQL** | Sentinel-style challenges | `DetectionTable \| where ...` |
| **SPL** | Splunk-style challenges | `index=detectiontable ...` |

---

## Detection rules

### Linux (Sigma)

| Detection | Format |
| --- | --- |
| [Attempting to Disable the Syslog Service](./Attempting%20to%20Disable%20the%20Syslog%20Service) | Sigma |
| [AWK System Function for Executing Shell Commands](./AWK%20System%20Function%20for%20Executing%20Shell%20Commands) | Sigma |
| [Clearing Linux iptables Firewall Rules](./Clearing%20Linux%20iptables%20Firewall%20Rules) | Sigma |
| [Creating Hidden Files in Linux](./Creating%20Hidden%20Files%20in%20Linux) | Sigma |
| [Data Transfer Size Limits](./Data%20Transfer%20Size%20Limits) | Sigma |
| [Disable AppArmor Service](./Disable%20AppArmor%20Service) | Sigma |
| [Find Command Shell Code Execution Exploitation](./Find%20Command%20Shell%20Code%20Execution%20Exploitation) | Sigma |
| [Linux Credential File Access](./Linux%20Credential%20File%20Access) | Sigma |
| [Linux File Timestamp Modification](./Linux%20File%20Timestamp%20Modification) | Sigma |
| [Linux Find Command Special Permission File Reconnaissance](./Linux%20Find%20Command%20Special%20Permission%20File%20Reconnaissance) | Sigma |
| [Linux Shell History Clearing Detection](./Linux%20Shell%20History%20Clearing%20Detection) | Sigma |
| [Linux sudo Root Privilege Bypass Vulnerability Detection](./Linux%20sudo%20Root%20Privilege%20Bypass%20Vulnerability%20Detection) | Sigma |
| [Potential Linux Backdoor User Account Creation](./Potential%20Linux%20Backdoor%20User%20Account%20Creation) | Sigma |
| [Reverse Shell Connection](./Reverse%20Shell%20Connection) | Sigma |
| [SSH Port Forwarding](./SSH%20Port%20Forwarding) | Sigma |
| [Using chattr to Remove Immutable File Attributes](./Using%20chattr%20to%20Remove%20Immutable%20File%20Attributes) | Sigma |
| [Using DD to Overwrite Files in Linux](./Using%20DD%20to%20Overwrite%20Files%20in%20Linux) | Sigma |

### Windows (SPL + KQL)

| Detection | Format |
| --- | --- |
| [Add Hidden Attribute to Files](./Add%20Hidden%20Attribute%20to%20Files) | SPL |
| [CMD Hidden Window Execution](./CMD%20Hidden%20Window%20Execution) | SPL |
| [Creating Hidden Local Users on Windows](./Creating%20Hidden%20Local%20Users%20on%20Windows) | SPL |
| [Detecting FileFix Social Engineering Attacks](./Detecting%20FileFix%20Social%20Engineering%20Attacks) | KQL |
| [Hiding Local Accounts via SpecialAccounts Registry Key](./Hiding%20Local%20Accounts%20via%20SpecialAccounts%20Registry%20Key) | SPL |
| [Identifying Renamed PSExec Lateral Movement Behavior](./Identifying%20Renamed%20PSExec%20Lateral%20Movement%20Behavior) | KQL |
| [LOLBas - Command Execution via Atbroker](./LOLBas%20-%20Command%20Execution%20via%20Atbroker) | KQL |
| [LSA protection mechanism disable detection](./LSA%20protection%20mechanism%20disable%20detection) | SPL |
| [PowerShell script block logging disables](./PowerShell%20script%20block%20logging%20disables) | SPL |
| [svchost.exe Process Started Without CLI Parameters](./svchost.exe%20Process%20Started%20Without%20CLI%20Parameters) | SPL |
| [Windows Account Brute-Force Attack Attempts](./Windows%20Account%20Brute-Force%20Attack%20Attempts) | KQL |

### AWS (Sigma + KQL)

| Detection | Format |
| --- | --- |
| [AWS - CloudTrail Logs Impairment Through S3 Lifecycle Rule](./AWS%20-%20CloudTrail%20Logs%20Impairment%20Through%20S3%20Lifecycle%20Rule) | Sigma |
| [AWS - Data Theft via Shared AMI](./AWS%20-%20Data%20Theft%20via%20Shared%20AMI) | KQL |
| [AWS - Data Theft via Shared S3 Buckets](./AWS%20-%20Data%20Theft%20via%20Shared%20S3%20Buckets) | KQL |
| [AWS - Delete DNS query logs](./AWS%20-%20Delete%20DNS%20query%20logs) | Sigma |
| [AWS - Deletes a trail](./AWS%20-%20Deletes%20a%20trail) | Sigma |
| [AWS - EC2 Windows Instance Password Data Retrieval](./AWS%20-%20EC2%20Windows%20Instance%20Password%20Data%20Retrieval) | Sigma |
| [AWS - Enumerate SES Information Activities](./AWS%20-%20Enumerate%20SES%20Information%20Activities) | Sigma |
| [AWS - IAM User Logged into Console Without MFA](./AWS%20-%20IAM%20User%20Logged%20into%20Console%20Without%20MFA) | KQL |
| [AWS - Remove VPC Flow Logs](./AWS%20-%20Remove%20VPC%20Flow%20Logs) | Sigma |
| [AWS - Stop CloudTrail Trail](./AWS%20-%20Stop%20CloudTrail%20Trail) | Sigma |
| [Bulk Remote Sessions Across Multiple Instances via SSM StartSession](./Bulk%20Remote%20Sessions%20Across%20Multiple%20Instances%20via%20SSM%20StartSession) | Sigma |
| [Disabling Management Event Logging via Event Selector](./Disabling%20Management%20Event%20Logging%20via%20Event%20Selector) | Sigma |

### Technique overviews (detection logic pending)

| Lab | Platform |
| --- | --- |
| [AWS - EC2 Credential Exfiltration – EC2 Account Credentials Used by Another AWS Account](./AWS%20-%20EC2%20Credential%20Exfiltration%20–%20EC2%20Account%20Credentials%20Used%20by%20Another%20AWS%20Account) | AWS |
| [Linux Password Policy File Reconnaissance](./Linux%20Password%20Policy%20File%20Reconnaissance) | Linux |
| [Python Command Execution Call Chain](./Python%20Command%20Execution%20Call%20Chain) | Linux |

---

## Technique themes

Detections in this portfolio map to common ATT&CK-aligned themes, including:

- **Defense evasion** — clearing shell history, disabling logging (Syslog, AppArmor, CloudTrail, PowerShell ScriptBlock Logging), timestomping, hidden files/accounts
- **Credential access** — Linux credential file access, LSA protection disable, EC2 password data retrieval
- **Execution / LOLBins** — AWK, `find`, Atbroker, renamed PSExec, hidden `cmd.exe` windows
- **Persistence** — backdoor user creation, hidden local accounts
- **Exfiltration / C2** — reverse shells, SSH port forwarding, chunked file splits, shared AMI/S3 abuse
- **Discovery / recon** — special-permission file finds, SES enumeration
- **Initial access** — FileFix social engineering, console login without MFA, brute-force attempts

---

## Tooling

- [Sigma](https://github.com/SigmaHQ/sigma)
- KQL (Microsoft Sentinel / Azure Data Explorer style queries)
- SPL (Splunk)
- SOC Labs detection engineering challenges
- [MITRE ATT&CK](https://attack.mitre.org/)

---

## Disclaimer

These rules were developed in lab environments for learning and portfolio purposes. Before deploying in production, validate against your telemetry, tune for false positives, and align with your SIEM field mappings and environment baselines.

---

## Author

**Ricky Tip** — Detection Engineering / SOC  
Repository: [github.com/rickytip/detection-rules](https://github.com/rickytip/detection-rules)
