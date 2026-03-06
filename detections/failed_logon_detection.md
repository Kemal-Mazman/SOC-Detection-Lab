# Detection: Multiple Failed Windows Logins

## MITRE ATT&CK
T1110 – Brute Force

## Description
This detection identifies multiple failed login attempts on a Windows host.  
Repeated authentication failures may indicate password guessing or brute-force activity.

## Data Source
Windows Security Event Log

Event ID:
4625 – Failed Logon

## Splunk Detection Query

index=main EventCode=4625
| stats count by Account_Name, host
| sort -count


## Investigation Steps

1. Identify the affected account
2. Determine the source host generating failures
3. Check if attempts are sequential or automated
4. Review other authentication logs for successful login after failures
5. Investigate potential brute force attempts

## False Positives

Possible legitimate causes include:

- User forgetting password
- Expired credentials
- Misconfigured service accounts
- Automated scripts with outdated credentials

## Severity
Medium

## Lab Validation

This detection was tested in my SOC Detection Lab by generating multiple failed login attempts on a Windows 10 endpoint.

Logs were ingested into Splunk using the Splunk Universal Forwarder.

## Screenshots

See `/screenshots/failed_logon_detection.png`
