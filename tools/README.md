# Tools — Benign Activity & Lab Automation

Scripts used to generate **benign activity** in the lab so detections can be tested against
realistic noise, not just their own attacks. This is what makes false-positive measurement
and behavioural tuning possible — see the
[featured case study](../investigations/lab-brittle-to-production.md) for how these were used
to tune the attack-chain detection.

All scripts run on the **Windows endpoint** in an **elevated** PowerShell session.

## Scripts

| Script | What it does |
| --- | --- |
| `batch-provisioning.ps1` | Generates a full benign baseline in one run — creates ~60 local accounts with **randomised names**, assigns a realistic minority to privileged groups, paces the activity so it doesn't look like a burst, and prunes down to a small live set. This is the main generator. |
| `register-noise-task.ps1` | Registers a Windows Scheduled Task that runs the generator under the **SYSTEM** account, so benign activity is attributed to automation (a machine account) rather than an interactive user. |
| `reset-and-repoint.ps1` | Cleans up previously generated accounts, clears the log, and re-points the scheduled task at the batch generator. Used to reset to a clean baseline. |

## Design principle — randomised, not fixed

Every account is created with a **randomised name**. This is deliberate: if benign activity
always used one fixed account name, a detection could be "tuned" simply by excluding that
name — which is just a hardcoded rule in disguise. Random names force tuning to be
**behavioural** (based on *who* performs the action, not *what it's called*), which is the
whole point of the exercise.

## Typical workflow

```powershell
# 1. (First time) register the scheduled task so the generator runs as SYSTEM
powershell -ExecutionPolicy Bypass -File .\register-noise-task.ps1

# 2. Reset to a clean baseline and point the task at the batch generator
powershell -ExecutionPolicy Bypass -File .\reset-and-repoint.ps1

# 3. Generate the benign baseline as SYSTEM (runs the task on demand)
Start-ScheduledTask -TaskName 'HelpdeskProvisioning'
```

Attacks are always run **manually, as an interactive user** — never scheduled — so that
benign automation and simulated attacks are performed by different identities. That identity
difference is the signal the tuned detection keys on.

## Note

These scripts create and delete local accounts on a system I own and manage, in an isolated
home lab, for detection-testing purposes only.
