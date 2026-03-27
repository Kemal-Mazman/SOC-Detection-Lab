# Detection: Encoded PowerShell Execution

## MITRE ATT&CK Mapping
- T1059.001 – Command and Scripting Interpreter: PowerShell  
- T1027 – Obfuscated Files or Information  

---

## Description

This detection identifies PowerShell processes executed with encoded commands using the `-EncodedCommand` or `-enc` flags.

Attackers commonly use this technique to obfuscate malicious commands, making it harder for defenders to understand the true intent of execution without decoding the payload.

---

## Lab Environment

- Kali Linux (Attacker)
- Windows 10 with Sysmon (Endpoint)
- Ubuntu Server with Splunk Enterprise (SIEM)

---

## Attack Simulation

The following command was executed on the Windows endpoint:

```powershell
powershell.exe -EncodedCommand ZQBjAGgAbwAgAGgAZQBsAGwAbwA=

The Base64 payload decodes to:
echo hello
This was used as a safe test to validate detection logic.

Data Source
Sysmon Event ID 1 (Process Creation)

Splunk Detection Query

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "Name='User'>(?<User>[^<]+)"
| search powershell.exe "-EncodedCommand"
| table _time host Image CommandLine User


Investigation Steps
Identify the process execution (powershell.exe)
Review the full command line for encoded content
Extract and decode the Base64 string
Analyse the decoded command for malicious intent
Check parent process and user context
Review related events (network connections, file creation)


False Positives
Legitimate administrative scripts using encoded PowerShell
Automation tools or software deployment scripts
Severity

Medium–High

Encoded PowerShell is not always malicious, but it is commonly used in attack scenarios and should be investigated.

Lab Notes

During testing, the detection did not initially appear in Splunk due to a time synchronization issue on the Windows VM.

The system was not synced with an NTP server, causing logs to be indexed with incorrect timestamps.

After fixing time synchronization, the detection worked as expected.

Screenshots
<img width="1899" height="382" alt="Splunk" src="https://github.com/user-attachments/assets/ec27b40d-1946-4c1c-bc82-3bd2ce7000c8" />

<img width="643" height="121" alt="Powershell" src="https://github.com/user-attachments/assets/98355aa0-f0b6-4118-af0b-3ba8938b4586" />

