# Internet-Exposed-Device

## Scenario:
During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources. Internal shared services device (e.g., a domain controller) is mistakenly exposed to the internet due to misconfiguration.

## Table:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceInfo|
| **Info**| [Microsoft Defender Info](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)|
| **Purpose**| The DeviceInfo table in the advanced hunting schema contains information about devices in the organization, including OS version, active users, and computer name.|

### Device Discovery ###
As part of the investigation, we discovered that a workstation identified as Windows-target-1 was unintentionally exposed to the public internet. Its external IP remained reachable for several days, potentially allowing unauthorized access attempts. This device is part of the shared services cluster and should not be accessible from outside the internal network.
- Last Internet facing time: `2025-04-12T19:15:05.9710276Z`

![image](https://github.com/user-attachments/assets/3820ca30-6ed0-466e-bb4b-69a786ae588a)

### Brute Force Attempts Detected
Several bad actors have been discovered attempting to log into the target machine.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
![image](https://github.com/user-attachments/assets/52fa4a1d-fcfa-4155-bc0d-4e4d49429bcf)

- The top 7 IP addresses with the highest number of failed login attempts were unsuccessful in gaining access to the VM.

```kql
let RemoteIPsInQuestion = dynamic(["92.255.85.172","185.42.12.59", "147.45.112.27", "196.251.84.131", "147.45.112.29", "88.214.25.73", "91.238.181.40"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
- No query results

- All 10 successful remote or network logins for the 'labuser' account over the past 30 days were autorized and legitimate.

![image](https://github.com/user-attachments/assets/68779b9c-efe3-4abe-a9f3-bf493d4b6061)

- No failed logon attempts were recorded for the 'labuser' account, suggesting that no brute-force activity occurred. This also makes the possibility of a one-time successful password guess highly unlikely.

![image](https://github.com/user-attachments/assets/96d3f1b5-683b-4c8e-9e68-2bee21c1b997)

- All successful login IP addresses for the 'labuser' account were reviewed for anomalies or unusual geolocations. No suspicious or unexpected activity was identified — all logins originated from expected locations.

![image](https://github.com/user-attachments/assets/09eb8e75-974e-441e-b1f4-3f60e1867b91)

Although the device was exposed to the internet and clear brute-force attempts were observed, there is no indication of a successful compromise or unauthorized access using the legitimate 'labuser' account.

The table below outlines the relevant MITRE ATT&CK techniques (TTPs) observed in this incident, highlighting their role in the detection and investigation process.

## 🛡️ MITRE ATT&CK TTPs for Incident Detection

| **TTP ID** | **TTP Name**                     | **Description**                                                                                          | **Detection Relevance**                                                         |
|------------|-----------------------------------|----------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| T1071      | Application Layer Protocol        | Observing network traffic and identifying misconfigurations (e.g., device exposed to the internet).       | Helps detect exposed devices via application protocols, identifying misconfigurations. |
| T1075      | Pass the Hash                     | Failed login attempts suggesting brute-force or password spraying attempts.                               | Identifies failed login attempts from external sources, indicative of password spraying.  |
| T1110      | Brute Force                       | Multiple failed login attempts from external sources trying to gain unauthorized access.                 | Identifies brute-force login attempts and suspicious login behavior.            |
| T1046      | Network Service Scanning          | Exposure of internal services to the internet, potentially scanned by attackers.                         | Indicates potential reconnaissance and scanning by external actors.            |
| T1021      | Remote Services                   | Remote logins via network/interactive login types showing external interaction attempts.                   | Identifies legitimate and malicious remote service logins to an exposed device.  |
| T1070      | Indicator Removal on Host         | No indicators of success in the attempted brute-force attacks, showing system defenses were effective.     | Confirms the lack of successful attacks due to effective defense measures.      |
| T1213      | Data from Information Repositories| Device exposed publicly, indicating potential reconnaissance activities.                                  | Exposes possible adversary reconnaissance when a device is publicly accessible.  |
| T1078      | Valid Accounts                    | Successful logins from the legitimate account ('labuser') were normal and monitored.                      | Monitors legitimate access and excludes unauthorized access attempts.           |

## Response Actions Taken:
- Conducted a full audit, malware scan, and vulnerability assessment
- Hardened the NSG on windows-target-1 to restrict RDP access to approved IPs only (no public exposure)
- Enforced account lockout policies and enabled MFA
- Awaiting further instructions for follow-up remediation or closure

---










