# LinkedIn post — draft

*(GitHub-first: commit the `detections/` folder, then post this with the repo link. Suggested
first comment holds the link so it doesn't suppress reach.)*

---

A while ago someone in the Perth security community gave me a piece of advice that stuck: stop
writing detections against abstract MITRE techniques, and start writing them against how a
*real, currently-active adversary* actually behaves.

So I did. This weekend I built two detections in my home SOC lab modelled on **Lumma Stealer's
ClickFix delivery** — the fake-CAPTCHA trick that convinces a user to paste a command into the
Run dialog themselves — including the **Windows Terminal delivery variant Microsoft disclosed in
March 2026**.

The interesting part wasn't writing the rule. It was watching the "obvious" rule fail.

The naive detection keys on PowerShell spawned by `explorer.exe` (the Run-dialog case). But when
I generated the Terminal variant and actually *read* the telemetry instead of assuming it, the
lineage was:

```
explorer.exe → WindowsTerminal.exe → powershell.exe → (pasted command)
```

The malicious PowerShell's immediate parent is `powershell.exe`, not `explorer.exe` — so the
parent-only rule is structurally blind to it. WindowsTerminal sits at the *grandparent* level,
only reachable by walking the process tree via ProcessGuid.

What I measured, on my own lab telemetry (both variants carrying the same encoded-command signal,
so the only difference is lineage):

- **Coverage:** naive explorer-parent rule = 50% (1 of 2 variants). Tuned rule that alerts on a
  strong command-line signal AND (explorer-parent OR WindowsTerminal-in-ancestry) = **100%**.
- **False positives:** I deliberately generated benign PowerShell noise to stress it. A flag-only
  rule would have fired on ~30 benign events; gating on a *strong* signal (encoded command /
  hidden window / download cradle) instead of weak flags like `-NoProfile` dropped that to **zero**,
  while keeping every true positive. The benign automation contributes entirely to noise and
  nothing to real alerts — which is the whole point of weighting the signals.

Second detection, and a lesson I didn't plan for: I wanted to catch the *forensic evidence* a
user typed an interpreter into Run (the `RunMRU` registry key). It returned nothing. Turned out
my Sysmon config wasn't collecting RunMRU at all — the artifact was sitting in the registry, but
Sysmon's include list didn't cover that path. Confirming the gap, closing it in the config, and
re-validating with a fresh write was honestly the most useful part of the whole exercise. You
can't detect what you're not collecting, and you don't find that out until you go looking.

Both detections, the before/after logic, the FP methodology, and the Sysmon fix are documented in
the repo. Feedback from detection engineers very welcome — especially on the ancestry-walk
approach vs. a data-model-based one at scale.

#DetectionEngineering #BlueTeam #SOC #Splunk #Sysmon #ThreatDetection #MITREATTACK #CyberSecurity

---

*First comment:*
Repo: github.com/Kemal-Mazman/SOC-Detection-Lab → `/detections`
