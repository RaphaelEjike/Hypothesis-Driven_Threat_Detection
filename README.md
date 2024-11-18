# Hypothesis-Driven_Threat_Detection
This project provides Threat Intelligence Analysts with a comprehensive framework to create, validate, and test hypotheses for identifying suspicious activities, vulnerabilities, and malicious actions within network environments. The repository emphasises real-world methodologies while maintaining a sector-agnostic approach, ensuring applicability across industries. By combining technical tools and best practices, the project aims to enable effective threat detection and actionable insights.

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


## Expected Results
- Identification of processes with a high rate of file modifications.
- Detection of unauthorised defence evasion activities.
- Visibility into suspicious network traffic indicative of C2 communication.
## Mitigation Recommendations
- Enable file activity monitoring in Microsoft Sentinel.
- Apply Microsoft Defender's ransomware protection policies.
- Block known malicious IPs/domains and enforce network segmentation.
## Sharing Findings
Summarise:
- Timeline of detected activities.
- Indicators of compromise (IOCs) like file hashes, IPs, or domain names.
- Mitigation steps and their expected outcomes.

# Hypothesis: Detection of Suspicious Privileged Account Activity Indicative of Insider Threats

## Overview
This hypothesis addresses the possibility of a trusted insider (employee, contractor, or partner) abusing privileges to access sensitive data or exfiltrate information.

## Objective
To detect unusual or unauthorised activity by privileged accounts, focusing on abnormal access patterns, data downloads, and attempts to bypass security controls.

## Key Indicators to Monitor
1. **Authentication and Authorisation Events**:
   - Privileged account logins during unusual hours or from abnormal locations.
   - Use of shared credentials or simultaneous logins from different IPs.

2. **Data Access Patterns**:
   - Access to files, databases, or systems not related to the user's role.
   - Large-scale file downloads or unauthorised data transfers.

3. **System Changes**:
   - Modifications to security configurations (e.g., disabling logging).
   - Creation of backdoor accounts or changes to Active Directory group memberships.

4. **Defence Evasion**:
   - Deletion of logs or tampering with monitoring tools.
   - Use of anonymisation tools (e.g., VPNs or Tor) by internal accounts.

---

## Hypothesis Statement
"If a privileged account demonstrates unusual access patterns or unauthorised actions such as accessing sensitive data, transferring files, or disabling security measures, it is likely being misused as part of an insider threat."

---

## Tools & Methodologies

### 1. **Log Analysis (Microsoft Sentinel)**  
- Query for unusual login times:
  
```
  kql
  SigninLogs
  | where UserPrincipalName contains "@"
  | where TimeGenerated between (now(-7d) .. now())
  | summarize Count = count() by UserPrincipalName, bin(TimeGenerated, 1h)
  | where Count > 1 and hour(TimeGenerated) < 6
```
- Query for large data transfers:
```
FileEvents
| where ActionType == "FileDownloaded"
| summarize DataTransferred = sum(FileSizeInBytes) by UserPrincipalName, DeviceName, Timestamp
| where DataTransferred > 1e9
```
### 2. Endpoint Monitoring (Microsoft Defender for Endpoints)
- Track changes to critical system files or audit logs: Example Tampering with EventLog or registry values related to monitoring tools.
- Use behaviour analytics to detect role violations.

### 3. Data Parsing (CyberChef)
- Extract and normalise timestamps from logs to visualise trends in data access.


## Expected Results
- Detection of login patterns outside of normal business hours or from suspicious geolocations.
- Identification of large data transfers or access to sensitive resources unrelated to the user’s role.
- Alerts on tampering with monitoring tools or logs.
## Mitigation Recommendations
1. Implement conditional access policies to block abnormal login locations or times.
2. Monitor privileged account activity using Microsoft Sentinel.
3. Enforce least privilege access and role-based access controls (RBAC).
## Sharing Findings
Use the reporting_template.md in the workflows/ folder to summarise:
-Timeline of detected activities.
-Indicators of compromise (IOCs) like user IDs, access logs, or IP addresses.
-Mitigation strategies implemented or recommended.



# Hypothesis: Detection of Zero-Day Exploitation through Behavioural Anomalies and Indicators of Compromise (IOCs)

## Overview
This hypothesis focuses on identifying potential zero-day exploit activity by analysing abnormal behaviours, suspicious network traffic, and indicators of exploitation, even when no specific vulnerability signature exists.

## Objective
To detect early signs of zero-day attacks by observing anomalous activity patterns, including privilege escalation, process injection, and unusual outbound communication.

## Key Indicators to Monitor
1. **Endpoint Behaviour**:
   - Processes behaving unusually, such as spawning unexpected child processes.
   - Use of legitimate tools for malicious purposes (e.g., PowerShell, WMI).

2. **Privilege Escalation**:
   - Creation of new privileged user accounts or modification of existing accounts.
   - Exploitation attempts targeting kernel or system-level access.

3. **Network Traffic**:
   - Outbound connections to new, previously unseen IP addresses.
   - Use of non-standard ports or encrypted traffic patterns.

4. **Persistence Mechanisms**:
   - Registry changes or new entries indicating persistence.
   - Dropping of payloads or scripts in startup directories.
  





---

## Hypothesis Statement
"If a previously unseen exploit is being used in an attack, it will exhibit anomalous behaviours such as unusual process activity, privilege escalation attempts, and connections to external infrastructure, which can be identified by behavioural analysis and traffic monitoring."

---

## Tools & Methodologies

### 1. **Log Analysis (Microsoft Sentinel)**  
- Query for unexpected child processes:

```
kql
  ProcessEvents
  | where ParentProcessName == "explorer.exe" and ProcessName != "explorer.exe"
  | summarize Count = count() by ProcessName, ParentProcessName, DeviceName, Timestamp
```
- Query for privilege escalation:

```
kql
SecurityEvent
| where EventID in (4672, 4688)
| summarize Count = count() by Account, DeviceName, EventID, Timestamp
```

### 2. Network Monitoring (Microsoft Defender for Endpoints)
- Hunt for anomalous outbound traffic: Monitor connections to new IP addresses using:

```
kql
NetworkConnectionEvents
| where DestinationIP !in (known_safe_IPs)
| summarize Count = count() by DestinationIP, DeviceName, Timestamp

```

### 3. Data Parsing (CyberChef)
- Decode or analyse payloads captured during the traffic monitoring stage.

## Expected Results
- Identification of anomalous process behaviours that do not align with expected patterns.
- Detection of unusual or suspicious privilege escalation events.
- Visibility into outbound connections to unknown IPs or domains, indicating C2 communication.
  
## Mitigation Recommendations
1. Implement behaviour-based threat detection systems (e.g., Defender ATP).
2. Apply strict egress firewall rules to block unknown IPs and domains.
3.  Enable advanced logging to capture detailed endpoint and network telemetry.

## Sharing Findings
- Timeline of detected activities.
- Indicators of compromise (IOCs) like process names, IP addresses, or file hashes.
- Suggested mitigation strategies for securing vulnerable systems.


## Resources 
 
- <a href="https://github.com/RaphaelEjike/ThreatHunting ">My KQL threat hunting workflows (Private)</a>
- <a href="https://www.kqlsearch.com/">www.kqlsearch.com</a>
- <a href="https://learn.microsoft.com/en-us/kusto/query/tutorials/learn-common-operators?view=azure-data-explorer&preserve-view=true&pivots=azuredataexplorer">Kusto query tutorials</a>
- <a href="https://kqlquery.com/">https://kqlquery.com/</a>
- <a href="https://kqlquery.com/posts/kql_sources/">https://kqlquery.com/posts/kql_sources/</a>
- <a href="https://github.com/marcusbakker/KQL/blob/master/kql_cheat_sheet_dark.pdf">https://github.com/marcusbakker/KQL/blob/master/kql_cheat_sheet_dark.pdf</a>



