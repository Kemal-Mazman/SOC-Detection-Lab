# SOC Detection Lab

## SOC Detection Lab Architecture

![SOC Detection Lab Architecture](architecture/Soc%20detection%20lab%20architecture.png)

> ### Featured case study — [From Lab-Brittle to Production-Ready: Tuning a Noisy Detection](investigations/lab-brittle-to-production.md)
>
> Took an attack-chain detection from brittle and untested to correlated, time-bound, and noise-aware — then **measured** it against a realistic benign baseline.
>
> **Before:** every legitimate account provisioning flagged as an attack — 0% precision, all noise.
>
> **After:** benign automation triaged to Low, the one real attack isolated as the only High — no hardcoded exclusions, no lost coverage.
>
> The half of detection engineering that matters isn't detecting the technique — it's telling malicious from busy. [Read the write-up →](investigations/lab-brittle-to-production.md)

## Overview

This repository documents the development of my personal SOC detection engineering lab.

The goal of this lab is to understand how modern security operations teams collect telemetry, analyse logs, build detections, investigate suspicious activity, and document findings.

The lab is designed to simulate a simplified enterprise-style SOC environment where attacker behaviour can be generated, forwarded into a SIEM, analysed, and converted into practical detection logic.

## Current Portfolio Status

* **Completed detections:** 10
* **Flagship work:** Benign-baseline generation and behavioural false-positive tuning
* **Latest detection:** Defender Exclusion Added → Execution From Excluded Path (KQL, with automated suppression testing)
* **Detection engineering improvement:** Generalised local-account extraction with no hardcoded usernames
* **Primary tools:** Splunk Enterprise, Azure Data Explorer (KQL), Sysmon, Windows Security Logs, Microsoft Defender operational logs, Splunk Universal Forwarder
* **Lab focus:** Detection engineering, attack simulation, log analysis, false-positive tuning, detection validation, and attack-chain correlation

## Lab Architecture

The lab is built using:

* **Proxmox VE** for virtualization
* **Windows 10 VM** for endpoint telemetry and log generation
* **Ubuntu Server VM** running Splunk Enterprise
* **Splunk Universal Forwarder** for log forwarding
* **Sysmon** for detailed Windows process and system telemetry
* **Kali Linux VM** for controlled attack simulation
* **Azure Data Explorer** as a KQL analytics substrate for detections written in KQL

## Data Flow

1. Attack or test activity is generated against the Windows endpoint.
2. Windows Security logs, Sysmon logs and Microsoft Defender operational logs are generated.
3. The Splunk Universal Forwarder sends logs to Splunk Enterprise; selected telemetry is also ingested into Azure Data Explorer for KQL detection development.
4. Splunk or Azure Data Explorer is used for searching, detection development, validation, and investigation.
5. Detection logic, validation results and screenshots are documented in GitHub.

## Detection Coverage

| Detection                                                                                                         | MITRE ATT&CK                                                          | Platform   | Status   |
| ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ---------- | -------- |
| [Encoded PowerShell Execution](detections/powershell_encoded_command_detection.md)                                | T1059.001, T1027                                                      | Splunk SPL | Complete |
| [Multiple Failed Windows Logins](detections/failed_logon_detection.md)                                            | T1110                                                                 | Splunk SPL | Complete |
| [Scheduled Task Creation](detections/T1053.005_Scheduled_Task_Creation.md)                                        | T1053.005                                                             | Splunk SPL | Complete |
| [Registry Run Key Modification](detections/registry_run_key_detection.md)                                         | T1547.001                                                             | Splunk SPL | Complete |
| [Windows Discovery Command Sequence](detections/discovery_command_sequence_detection.md)                          | T1033, T1082, T1016, T1087, T1069                                     | Splunk SPL | Complete |
| [Local Account Creation and Admin Group Modification](detections/local_account_creation_admin_group_detection.md) | T1136.001, T1098, T1078                                               | Splunk SPL | Complete |
| [Local Account Admin + RDP Attack Chain](detections/local_account_admin_rdp_attack_chain_detection.md)            | T1033, T1082, T1016, T1087, T1069, T1136.001, T1098, T1078, T1021.001 | Splunk SPL | Complete |
| [ClickFix PowerShell — Run Dialog and Windows Terminal](detections/clickfix_powershell_lineage_detection.md)      | T1204.004, T1059.001                                                  | Splunk SPL | Complete |
| [RunMRU Interpreter Abuse](detections/runmru_interpreter_abuse_detection.md)                                      | T1204.004                                                             | Splunk SPL | Complete |
| [Defender Exclusion Added → Execution From Excluded Path](detections/defender_exclusion_then_execution_detection.md) | T1562.001, T1204.002                                              | KQL        | Complete |

## Latest Detection: Defender Exclusion Added → Execution From Excluded Path

This is the first detection in the repository written in KQL rather than Splunk SPL, and the first to ship with an automated suppression test suite.

It correlates two events that are individually unremarkable and jointly high-signal:

1. A Microsoft Defender path exclusion being added (Event ID 5007)
2. A process executing from inside that excluded path (Sysmon Event ID 1), on the same host, within 10 minutes

Neither event alone justifies an alert — administrators and installers add exclusions routinely. The detection targets the sequence: an attacker carving out a blind spot and then immediately using it.

**Stateful sequence matching.** Correlation uses the KQL `scan` operator with a per-entity partition key rather than a join. A join produces a cross product of every exclusion against every execution and then filters it, which does not express "the next execution after this exclusion".

**Adversarial self-testing.** The detection ships with an automated validation matrix of eight scenarios, six of which assert that it stays *silent* — wrong host, wrong event order, outside the correlation window, path-boundary near-miss, and each event occurring alone. Scenario `08_multi_exclusion` was written to attack the detection's own state model, and it failed on the first attempt: partitioning on host alone meant a second exclusion overwrote the first in `scan` state, so an attacker adding two exclusions and executing from the first was missed. The partition key was changed to host + path as a result.

The test payload is a copy of a signed Microsoft binary (`whoami.exe`), so the detection is demonstrably firing on the sequence rather than on any property of the executable.

Runnable queries: [detection](detections/kql/defender_exclusion_then_execution_detection.kql) · [validation matrix](detections/kql/defender_exclusion_validation_matrix.kql) · [normalization tests](detections/kql/defender_exclusion_path_normalization_tests.kql)

Full write-up, including known limitations: [detections/defender_exclusion_then_execution_detection.md](detections/defender_exclusion_then_execution_detection.md)

## ClickFix PowerShell and RunMRU Evidence

These two detections provide complementary coverage for ClickFix and fake-CAPTCHA paste-and-run activity.

### ClickFix PowerShell Execution

The [ClickFix PowerShell detection](detections/clickfix_powershell_lineage_detection.md) identifies suspicious PowerShell execution delivered through:

* The classic Windows Run dialog
* The Windows Terminal delivery variant
* Encoded commands, hidden execution, and common download or decoding activity
* Process ancestry rather than relying only on the immediate parent process

The detection uses Sysmon Event ID 1 and follows the process tree through `ProcessGuid` and `ParentProcessGuid`.

This allows the detection to identify both the classic Run-dialog path and the Windows Terminal variant, where the suspicious PowerShell process may not have `explorer.exe` as its immediate parent.

### RunMRU Registry Evidence

The [RunMRU Interpreter Abuse detection](detections/runmru_interpreter_abuse_detection.md) identifies registry evidence that a command interpreter was entered through the Windows Run dialog.

It uses Sysmon Event ID 13 to inspect registry value writes under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

The detection looks for commands beginning with interpreters such as PowerShell, CMD, MSHTA, WScript, CScript, Rundll32, or Regsvr32 while excluding the `MRUList` ordering value.

The RunMRU detection complements the ClickFix process-lineage detection:

1. RunMRU provides evidence of the command entered through the Run dialog.
2. Process telemetry provides evidence of the resulting PowerShell execution and its ancestry.

Together, they provide visibility across both the user-action and execution stages of the activity.

## Featured Correlation Detection: Local Account Admin + RDP Attack Chain

This detection moves beyond single-event alerting and correlates a sequence of suspicious Windows activity:

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

The detection was later rebuilt to remove hardcoded test-account values, correlate account-creation and group-modification activity using the account SID, enforce a time window, and risk-score activity based on the identity that performed it.

The resulting logic separates legitimate automated provisioning from manually performed attack activity without filtering out account names.

## Detection Engineering Improvements

### Generalising Local Account Creation Detection

The [local account creation improvement](detections/T1136.001-local-account-creation.md) documents how a brittle, username-specific rule was rebuilt to detect the underlying behaviour.

The original logic depended on a hardcoded account name from the initial simulation.

Windows Security Event ID 4720 includes both:

* The account that performed the creation
* The new account that was created

The revised extraction anchors itself to the `New Account` section of the event and isolates the created account without depending on a specific username.

Validation across a 30-day window produced:

* **Account-creation events tested:** 3
* **Correct field extractions:** 3/3
* **Different account names:** 3
* **Hardcoded account values:** 0

This improvement demonstrates detection validation and generalisation rather than adding a separate detection.

## Current Focus Areas

* Windows authentication logging and event analysis
* Sysmon process creation analysis
* Detection query development in Splunk SPL and KQL
* Log ingestion, parsing and field normalization
* Alert logic tuning and false-positive reduction
* Attack-chain and stateful sequence correlation
* Automated detection validation and suppression testing
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
* Detecting ClickFix-style PowerShell execution through the Run dialog
* Detecting the Windows Terminal ClickFix delivery variant through process ancestry
* Detecting RunMRU registry evidence of command-interpreter use
* Correlating Defender configuration changes with subsequent process execution
* Generating benign activity to measure false positives
* Tuning detection severity using behavioural context rather than hardcoded exclusions
* Writing automated test matrices that assert where a detection should *not* fire

## Repository Structure

```text
SOC-Detection-Lab/
├── architecture/
│   └── SOC lab architecture diagrams
├── detections/
│   ├── Detection documentation and SPL queries
│   └── kql/
│       └── Standalone, runnable KQL detection and validation queries
├── investigations/
│   └── Investigation notes and analysis summaries
├── logs/
│   └── Sample log notes or exported analysis artifacts
├── screenshots/
│   └── Splunk and KQL validation screenshots and lab evidence
├── tools/
│   └── Benign activity generation and lab automation scripts
└── README.md
```

## Methodology

Each detection is documented with:

* Detection overview
* Scenario description
* MITRE ATT&CK mapping
* Data sources
* Lab environment and software versions
* Attack simulation steps
* Detection query (Splunk SPL or KQL)
* Automated validation matrix asserting both firing and suppression behaviour, where applicable
* Validation screenshots
* Investigation steps
* False-positive considerations
* Known limitations and detection scope boundaries
* Cleanup steps where required

## Objective

The objective of this lab is to build a strong foundation in security operations and detection engineering by:

* Understanding how attacker behaviour appears in logs
* Learning how to design effective detection logic
* Building detections mapped to MITRE ATT&CK
* Practicing structured investigation thinking
* Improving Splunk SPL and KQL query skills
* Testing detections against the conditions where they should *not* fire
* Documenting technical work clearly for portfolio review

## Notes

This is a controlled home lab environment used for learning and portfolio development. All attack simulations are performed against systems I own and manage.
