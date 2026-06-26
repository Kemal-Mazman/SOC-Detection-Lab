# Logs

This folder is reserved for lab log notes, exported examples, and references used during detection validation.

The purpose of this folder is to support the detection engineering workflow by keeping notes about important event IDs, sourcetypes, and log sources used in the SOC Detection Lab.

## Log Sources Used

Current lab telemetry includes:

* Windows Security logs
* Windows System logs
* Windows Application logs
* Sysmon Operational logs
* Splunk Universal Forwarder ingestion data

## Key Windows Security Events

| Event ID | Description                            |
| -------: | -------------------------------------- |
|     4624 | Successful logon                       |
|     4625 | Failed logon                           |
|     4720 | Local user account created             |
|     4722 | User account enabled                   |
|     4724 | Password set or reset attempt          |
|     4732 | Member added to a local security group |
|     4738 | User account changed                   |

## Key Sysmon Events

| Event ID | Description        |
| -------: | ------------------ |
|        1 | Process creation   |
|        3 | Network connection |
|       11 | File creation      |
|       13 | Registry value set |
|       22 | DNS query          |

## Current Splunk Sourcetypes

Examples used in this lab:

```spl
WinEventLog:Security
WinEventLog:System
WinEventLog:Application
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

## Notes

This folder does not store sensitive production logs. Any log examples used here should be from the controlled home lab environment only.
