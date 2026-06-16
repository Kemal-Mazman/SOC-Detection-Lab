# Detection: Suspicious Local Account Creation and Administrator Group Modification

## Status

Complete

## Objective

Detect suspicious local account creation followed by administrator group modification on a Windows endpoint.

This detection focuses on identifying account abuse activity where a new local user is created and then added to the local Administrators group.

## Scenario

After initial access, an attacker may create a new local account to maintain access to a compromised system. If that account is added to the local Administrators group, it can provide elevated privileges and support persistence or future interactive access.

In this lab, a controlled account abuse scenario was simulated on a Windows 10 endpoint.

Commands used:

```cmd
net user lab_svc_01 /add /random
net localgroup administrators lab_svc_01 /add
```

## MITRE ATT&CK Mapping

| Technique | Description                   |
| --------- | ----------------------------- |
| T1136.001 | Create Account: Local Account |
| T1098     | Account Manipulation          |
| T1078     | Valid Accounts                |

## Data Source

| Source               | Event ID | Description                                          |
| -------------------- | -------: | ---------------------------------------------------- |
| Windows Security Log |     4720 | A user account was created                           |
| Windows Security Log |     4722 | A user account was enabled                           |
| Windows Security Log |     4724 | An attempt was made to reset an account's password   |
| Windows Security Log |     4732 | A member was added to a security-enabled local group |
| Windows Security Log |     4738 | A user account was changed                           |

## Detection Logic

The detection looks for Windows Security account-management events related to local account creation and group membership changes.

The most important events in this scenario are:

* Event ID 4720: local user account created
* Event ID 4732: user added to local Administrators group

Additional supporting events such as 4722, 4724 and 4738 provide context around account enablement, password activity and account modification.

## Splunk SPL

```spl
index=main sourcetype="WinEventLog:Security" _index_earliest=-20m
(EventCode=4720 OR EventCode=4722 OR EventCode=4724 OR EventCode=4732 OR EventCode=4738)
| eval Activity=case(
    EventCode=4720,"Local User Account Created",
    EventCode=4722,"Local User Account Enabled",
    EventCode=4724,"Password Set or Reset Attempt",
    EventCode=4732 AND Group_Name="Administrators","User Added to Administrators",
    EventCode=4732,"User Added to Local Group",
    EventCode=4738,"User Account Changed",
    true(),"Other Account Management Event"
)
| stats earliest(_time) as first_seen latest(_time) as last_seen values(EventCode) as event_codes values(Activity) as activities values(Account_Name) as account_names values(Target_Account_Name) as target_accounts values(Group_Name) as groups by host
| convert ctime(first_seen) ctime(last_seen)
| table first_seen last_seen host event_codes activities account_names target_accounts groups
```

## Lab Result

The detection successfully identified a sequence of account-management events related to the test account.

Observed events:

* 4720: Local User Account Created
* 4722: Local User Account Enabled
* 4724: Password Set or Reset Attempt
* 4732: User Added to Administrators
* 4738: User Account Changed

The key high-risk behaviour was the addition of the newly created local account to the Administrators group.

## Screenshot

![Account Creation Admin Summary](../screenshots/Account%20creationadmin%20summary.png)

## Investigation Notes

An analyst should investigate:

* Which user created the local account
* Whether the account name follows normal naming standards
* Whether the account was added to Administrators
* Whether the account was later used for interactive logon
* Whether the account appears on other hosts
* Whether discovery or persistence activity occurred before or after the account creation
* Whether the change was approved by IT or part of normal administration

## False Positives

Possible legitimate activity includes:

* Helpdesk account creation
* Local administrator maintenance
* Lab or testing activity
* Approved onboarding or troubleshooting
* Temporary administrative access granted by IT

This detection becomes higher confidence when the account creation is followed by administrator group modification, remote logon activity, persistence creation or unusual discovery commands.

## Severity

High

## Key Lesson

Windows Security logs are the authoritative source for local account creation and group membership changes. Sysmon can provide useful command-line context, but Security events confirm that the account-management change actually occurred.
