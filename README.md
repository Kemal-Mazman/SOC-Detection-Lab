# SOC Detection Lab

## SOC Detection Lab Architecture

![SOC Detection Lab Architecture](architecture/Soc%20detection%20lab%20architecture.png)

## Overview

This repository documents the development of my personal SOC detection engineering lab.

The goal of this lab is to understand how modern security operations teams collect telemetry, analyse logs, build detections, investigate suspicious activity, and document findings.

The lab is designed to simulate a simplified enterprise-style SOC environment where attacker behaviour can be generated, forwarded into a SIEM, analysed, and converted into practical detection logic.

## Current Portfolio Status

* **Detections built so far:** 7
* **Latest detection:** Local Account Admin + RDP Attack Chain
* **Primary tools:** Splunk Enterprise, Sysmon, Windows Security Logs, Splunk Universal Forwarder
* **Lab focus:** Detection engineering, attack simulation, log analysis, and SOC-style investigation workflows

## Lab Architecture

The lab is built using:

* **Proxmox VE** for virtualization
* **Windows 10 VM** for endpoint telemetry and log generation
* **Ubuntu Server VM** running Splunk Enterprise
* **Splunk Universal Forwarder** for log forwarding
* **Sysmon** for detailed Windows process and system telemetry
* **Kali Linux VM** for controlled attack simulation

## Data Flow

1. Attack or test activity is generated against the Windows endpoint.
2. Windows Security logs and Sysmon logs are generated.
3. The Splunk Universal Forwarder sends logs to Splunk Enterprise.
4. Splunk is used for searching, detection development, validation, and investigation.
5. Detection logic and screenshots are documented in GitHub.

## Detection Coverage

| Detection                                                                                                         | MITRE ATT&CK                                                          | Status   |
| ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | -------- |
| [Encoded PowerShell Execution](detections/powershell_encoded_command_detection.md)                                | T1059.001, T1027                                                      | Complete |
| [Multiple Failed Windows Logins](detections/failed_logon_detection.md)                                            | T1110                                                                 | Complete |
| [Scheduled Task Creation](detections/T1053.005_Scheduled_Task_Creation.md)                                        | T1053.005                                                             | Complete |
| [Registry Run Key Modification](detections/registry_run_key_detection.md)                                         | T1547.001                                                             | Complete |
| [Windows Discovery Command Sequence](detections/discovery_command_sequence_detection.md)                          | T1033, T1082, T1016, T1087, T1069                                     | Complete |
| [Local Account Creation and Admin Group Modification](detections/local_account_creation_admin_group_detection.md) | T1136.001, T1098, T1078                                               | Complete |
| [Local Account Admin + RDP Attack Chain](detections/local_account_admin_rdp_attack_chain_detection.md)            | T1033, T1082, T1016, T1087, T1069, T1136.001, T1098, T1078, T1021.001 | Complete |

## Latest Detection: Local Account Admin + RDP Attack Chain

The latest detection moves beyond single-event alerting and correlates a sequence of suspicious Windows activity:

1. Discovery commands executed on the endpoint
2. New local account created
3. Account added to the local Administrators group
4. Successful RDP logon using the newly created account

This produces an analyst-friendly attack-chain timeline instead of separate isolated events.

The detection uses:

* **Sysmon Event ID 1** for process creation and discovery commands
* **Windows Security Event ID 4720** for local account creation
* **Windows Security Event ID 4732** for local administrator group modification
* **Windows Security Event ID 4624 with Logon Type 10** for successful RDP logon

## Current Focus Areas

* Windows authentication logging and event analysis
* Sysmon process creation analysis
* Splunk SPL detection query development
* Log ingestion and parsing
* Alert logic tuning and false-positive reduction
* Attack-chain correlation
* Basic incident investigation workflows
* Technical documentation of findings and validation steps

## Example Learning Scenarios

This lab currently covers scenarios such as:

* Simulating failed authentication activity and analysing related Windows Security events
* Detecting encoded PowerShell execution using Sysmon process creation logs
* Detecting scheduled task persistence
* Detecting registry Run Key persistence
* Identifying Windows discovery command sequences
* Detecting local account creation and administrator group modification
* Correlating account abuse with successful RDP logon activity

## Repository Structure

```text
SOC-Detection-Lab/
├── architecture/
│   └── SOC lab architecture diagrams
├── detections/
│   └── Detection documentation and SPL queries
├── investigations/
│   └── Investigation notes and analysis summaries
├── logs/
│   └── Sample log notes or exported analysis artifacts
├── screenshots/
│   └── Splunk validation screenshots and lab evidence
└── README.md
```

## Methodology

Each detection is documented with:

* Detection overview
* Scenario description
* MITRE ATT&CK mapping
* Data sources
* Attack simulation steps
* Splunk SPL query
* Validation screenshots
* Investigation steps
* False-positive considerations
* Cleanup steps where required

## Objective

The objective of this lab is to build a strong foundation in security operations and detection engineering by:

* Understanding how attacker behaviour appears in logs
* Learning how to design effective detection logic
* Building detections mapped to MITRE ATT&CK
* Practicing structured investigation thinking
* Improving Splunk SPL skills
* Documenting technical work clearly for portfolio review

## Notes

This is a controlled home lab environment used for learning and portfolio development. All attack simulations are performed against systems I own and manage.
