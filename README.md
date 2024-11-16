# Hypothesis-Driven_Threat_Detection
This GitHub project provides Threat Intelligence Analysts with a comprehensive framework to create, validate, and test hypotheses for identifying suspicious activities, vulnerabilities, and malicious actions within network environments. The repository emphasises real-world methodologies while maintaining a sector-agnostic approach, ensuring applicability across industries. By combining technical tools and best practices, the project aims to enable effective threat detection and actionable insights.

## Prioritised Threats

### Ransomware
Examples: Hypotheses targeting file encryption activities, malicious PowerShell execution, or network-wide lateral movement.
### Insider Threats
Examples: Hypotheses on abnormal login patterns or unauthorised data access.
### Zero-Day Attacks
Examples: Hypotheses centred around exploitation of unpatched software vulnerabilities.


### Kill Chain Focus
This documentation will be organised by the following stages, offering insights into potential attack vectors and hypotheses:

- Initial Access: Malicious email links, credential stuffing.
- Persistence: Registry modifications, scheduled tasks.
- Privilege Escalation: Exploiting vulnerabilities or weak configurations.
- Defence Evasion: Disabling antivirus, obfuscated scripts.
- Credential Access: Credential dumping, pass-the-hash attacks.
- Discovery: Network scanning, host enumeration.
- Lateral Movement: SMB exploits, compromised user accounts.
- Command and Control (C2): Suspicious beaconing patterns.
- Exfiltration: Unusual data transfer volumes.

# Hypothesis: Detection of Ransomware Activities via Unusual File Modifications and Encryption Patterns

## Overview
This hypothesis focuses on detecting early-stage ransomware activities by analysing unusual file modifications, rapid encryption of files, and abnormal processes associated with encryption tools.

## Objective
To identify suspicious patterns indicative of ransomware activity before widespread damage occurs.

## Key Indicators to Monitor
1. **File System Activity**:
   - High volume of file modifications in a short time.
   - File extensions being renamed to unusual or encrypted formats (e.g., `.lock`, `.encrypted`).

2. **Process Behaviour**:
   - Unknown or unauthorised processes rapidly accessing multiple files.
   - Processes using high CPU resources indicative of encryption.

3. **Network Activity**:
   - Outbound connections to known malicious IPs or domains (e.g., C2 servers).
   - Abnormal use of SMB or other protocols for lateral file encryption.

4. **Defence Evasion**:
   - Processes attempting to disable Microsoft Defender or other endpoint protections.
   - Tampering with event logs or deleting shadow copies.

## Hypothesis Statement
"If a process triggers a high volume of file modifications and shows signs of encryption activity, combined with defence evasion attempts and abnormal network connections, it is likely to be part of ransomware execution."


## Tools & Methodologies

### 1. **Log Analysis (Microsoft Sentinel)**  
- Query to identify rapid file modifications:
  
 ```
  kql
  FileEvents
  | where ActionType == "FileModified"
  | summarize Count = count() by FileName, Timestamp, User, DeviceId
  | where Count > 100 and Timestamp between (now(-1h) .. now())
```
- Query to detect defence evasion:
  
 ```kql
DeviceEvents
| where ActionType == "AntivirusDisabled" or ActionType == "SecurityToolTampered"
| summarize Count = count() by DeviceId, User, Timestamp
 ```

### 2. Endpoint Detection (Microsoft Defender for Endpoints)
Hunt for specific process names or hashes tied to ransomware campaigns.
Use built-in behaviour monitoring to flag encryption-related processes.
### 3. Data Parsing (CyberChef)
Extract file extension changes from logs or file metadata for anomaly detection.


### Expected Results
- Identification of processes with a high rate of file modifications.
- Detection of unauthorised defence evasion activities.
- Visibility into suspicious network traffic indicative of C2 communication.
### Mitigation Recommendations
- Enable file activity monitoring in Microsoft Sentinel.
- Apply Microsoft Defender's ransomware protection policies.
- Block known malicious IPs/domains and enforce network segmentation.
### Sharing Findings
Summarise:
- Timeline of detected activities.
- Indicators of compromise (IOCs) like file hashes, IPs, or domain names.
- Mitigation steps and their expected outcomes.

