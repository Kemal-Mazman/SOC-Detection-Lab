# Detections

| Detection                                                                                              | MITRE ATT&CK                                                          | Platform   | Status   |
| ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- | ---------- | -------- |
| [Encoded PowerShell Execution](powershell_encoded_command_detection.md)                                | T1059.001, T1027                                                      | Splunk SPL | Complete |
| [Multiple Failed Windows Logins](failed_logon_detection.md)                                            | T1110                                                                 | Splunk SPL | Complete |
| [Scheduled Task Creation](T1053.005_Scheduled_Task_Creation.md)                                        | T1053.005                                                             | Splunk SPL | Complete |
| [Registry Run Key Modification](registry_run_key_detection.md)                                         | T1547.001                                                             | Splunk SPL | Complete |
| [Windows Discovery Command Sequence](discovery_command_sequence_detection.md)                          | T1033, T1082, T1016, T1087, T1069                                     | Splunk SPL | Complete |
| [Local Account Creation and Admin Group Modification](local_account_creation_admin_group_detection.md) | T1136.001, T1098, T1078                                               | Splunk SPL | Complete |
| [Local Account Admin + RDP Attack Chain](local_account_admin_rdp_attack_chain_detection.md)            | T1033, T1082, T1016, T1087, T1069, T1136.001, T1098, T1078, T1021.001 | Splunk SPL | Complete |
| [ClickFix PowerShell (Run Dialog + Windows Terminal Variant)](clickfix_powershell_lineage_detection.md) | T1204.004, T1059.001                                                  | Splunk SPL | Complete |
| [RunMRU Interpreter Abuse](runmru_interpreter_abuse_detection.md)                                      | T1204.004                                                             | Splunk SPL | Complete |
| [Defender Exclusion Added → Execution From Excluded Path](defender_exclusion_then_execution_detection.md) | T1562.001, T1204.002                                                | KQL        | Complete |
| [Entra ID Password Spray Followed by Successful Sign-In](entra-password-spray-success/README.md) | T1110.003, T1078.004 | KQL | Complete |