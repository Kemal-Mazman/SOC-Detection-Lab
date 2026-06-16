# Detection: Suspicious Windows Discovery Command Sequence

## Status

Complete

## Objective

Detect a sequence of Windows discovery commands executed by the same user on the same host within a short time window.

This detection focuses on identifying post-compromise discovery behaviour where an attacker attempts to understand the local system, user context, network configuration, local accounts, and local groups.

## Scenario

After gaining access to a Windows endpoint, an attacker commonly runs basic discovery commands to understand the environment before continuing with privilege escalation, persistence, or lateral movement.

In this lab, the following commands were executed on the Windows 10 endpoint:

```cmd
whoami
hostname
ipconfig
net user
net localgroup administrators
```

## MITRE ATT&CK Mapping

| Technique | Description                            |
| --------- | -------------------------------------- |
| T1033     | System Owner/User Discovery            |
| T1082     | System Information Discovery           |
| T1016     | System Network Configuration Discovery |
| T1087     | Account Discovery                      |
| T1069     | Permission Groups Discovery            |

## Data Source

| Source | Event                        |
| ------ | ---------------------------- |
| Sysmon | Event ID 1: Process Creation |

## Detection Logic

The detection looks for multiple discovery-related commands executed within a short time window and groups them into an alert-style summary.

## Splunk SPL

```spl
index=main host="DESKTOP-5BL4PPV" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" _index_earliest=-20m
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "Name='User'>(?<User>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]+)"
| where EventID="1"
| eval cmd=lower(CommandLine)
| where match(cmd,"whoami|hostname|ipconfig|net1?\s+user|net1?\s+localgroup")
| eval Discovery_Command=case(
    match(cmd,"whoami"),"User Discovery",
    match(cmd,"hostname"),"System Name Discovery",
    match(cmd,"ipconfig"),"Network Configuration Discovery",
    match(cmd,"net1?\s+user"),"Account Discovery",
    match(cmd,"net1?\s+localgroup"),"Group Discovery",
    true(),"Other Discovery"
)
| stats earliest(_time) as first_seen latest(_time) as last_seen count dc(Discovery_Command) as unique_discovery_types values(Discovery_Command) as discovery_types values(CommandLine) as command_lines values(ParentImage) as parent_processes by host User
| where unique_discovery_types >= 3
| convert ctime(first_seen) ctime(last_seen)
| table first_seen last_seen host User count unique_discovery_types discovery_types command_lines parent_processes
```

## Lab Result

The detection successfully grouped multiple discovery commands into one alert-style result.

Observed discovery categories:

* User Discovery
* System Name Discovery
* Network Configuration Discovery
* Account Discovery
* Group Discovery

## Screenshot

![Discovery Alert Summary](../screenshots/Discovery%20alert%20summary.png)

## Investigation Notes

An analyst should review:

* Which user executed the commands
* Whether the commands were run interactively
* The parent process
* Whether the same user later performed privilege escalation, account creation, or persistence activity
* Whether similar discovery occurred across multiple hosts

## False Positives

Possible legitimate activity includes:

* System administrators troubleshooting an endpoint
* Helpdesk staff collecting system information
* Software inventory or audit scripts
* User support sessions

This detection becomes higher confidence when discovery commands are followed by suspicious account activity, persistence, or remote logon behaviour.

## Severity

Medium

## Key Lesson

Simple commands are not necessarily malicious by themselves. The detection value comes from identifying the sequence, timing, user context, and follow-on behaviour.
