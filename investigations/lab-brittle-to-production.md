# From Lab-Brittle to Production-Ready: Tuning a Noisy Detection

**A detection is only half-built until it can tell an attacker from a busy administrator.**
This is the story of taking one attack-chain detection from *brittle and blind* to
*correlated, time-bound, and noise-aware* — measured against realistic benign activity,
with a before-and-after that proves it still catches the attacker.

---

## The one-line result

| | Before | After |
|---|---|---|
| **What the rule did** | Fired on every account created and made an admin | Same — fires on every chain |
| **Against benign activity** | Every hit was a false positive | Benign automation triaged to **Low** |
| **A real attacker** | Buried among the noise | Isolated as the **only High** |
| **Precision** | **0%** | Attack cleanly separated from noise |
| **How** | — | Behavioural risk scoring — **no hardcoded names, no lost coverage** |

The rule never stopped detecting. It learned to *rank* what it detects — which is the
difference between a detection that pages a human at 2am for nothing and one a SOC can
actually run.

---

## The detection

The rule watches for a classic privilege-escalation chain on a Windows host:

1. A local account is **created** (Event ID 4720)
2. That same account is **added to a privileged group** — Administrators or Remote Desktop Users (Event ID 4732)
3. …within a short **time window**, so unrelated events days apart don't falsely chain

Correlation is done on the account's **Security Identifier (SID)** — not its name. That
choice turned out to be non-optional (see below), and it's the core of what makes the rule
robust.

> Full logic and tuning history: [`detections/local_account_admin_rdp_attack_chain_detection.md`](../detections/local_account_admin_rdp_attack_chain_detection.md)

---

## Where it started: brittle and untested

The original version had two problems that are invisible in a sterile lab and fatal in
production:

- **It keyed on a hardcoded account name** from my own testing. It only worked because I
  happened to name my test account a certain way — it would have missed a real attacker
  entirely.
- **It claimed to correlate by SID but didn't.** The correlation was faked with a static
  string. The rule *looked* finished and wasn't.

I only found this because I built the attacks manually and read the raw telemetry myself —
which is exactly how you catch a rule that passes its own test for the wrong reason.

---

## Making the lab noisy (the part most home labs skip)

A detection tested only against its own attack proves nothing about false positives,
because there's no legitimate activity to confuse it. So before tuning, I built the
**benign twin** of the attack: a generator that simulates a helpdesk automation account
provisioning real users — creating accounts with **randomised names**, assigning a
realistic **minority to privileged groups**, all performed by the machine's **automation
account**, not by me.

The randomisation matters. If every benign account had the same name, I could have "tuned"
the rule by excluding that name — which is just the original hardcoded bug wearing a
disguise. Random names force the tuning to be **behavioural**, which is the whole point.

---

## The "before" number

Run against this benign baseline, the rule flagged **every legitimate provisioning as a
possible attack** — a create-and-elevate chain looks identical whether it's an attacker or
the helpdesk doing its job. Precision: **0%**. Every alert was noise.

That's not a failure — it's the honest starting metric. You can't tune what you haven't
measured.

![Before tuning: every create-and-elevate chain flagged identically as ALERT, attacker and automation indistinguishable](../screenshots/before-baseline.png)

*Every row reads `ALERT` — the attacker (`hacked-svc`, run by an interactive user) is flagged identically to legitimate automated provisioning. The rule detects, but cannot triage.*

---

## The tuning decision

The tempting fixes are all traps:

- **Exclude the benign account by name** → reintroduces the hardcoded bug; blind to any
  attacker who picks that name.
- **Tune on speed** → backwards. The *automation* is the fast one (sub-second); a human
  attacker fumbling through commands is *slower*. Speed would flag the wrong side.

The reliable signal is **who performed the action**. Every event records a *Subject* — the
identity that did it. Legitimate provisioning runs as the **automation / machine account**;
an attacker runs as a compromised **interactive user**. So instead of *excluding* benign
activity, I **risk-scored** it:

- Chain performed by the automation account → **Low** (informational, no page)
- Chain performed by any interactive user → **High** (investigate now)

Crucially, the rule still fires on **every** chain. Nothing is filtered out; the benign
noise is simply ranked down. Zero detection coverage lost.

---

## The "after": proving it still bites

A tuned rule is worthless if it's gone quiet on real attacks too. So the final test:
I manually ran the exact attack chain — create an account, elevate it to Administrators —
**as an interactive user**, the way an intruder would.

Result:

- The attack chain scored **High** — the single high-risk row.
- Every benign automated chain stayed **Low**.
- One rule, one alarm worth a human's attention, the noise correctly suppressed.

![After tuning: the attack scored High and isolated at the top, all benign automated chains scored Low](../screenshots/after-attack-isolated.png)

*Same rule, now risk-scored. The single attack (`hacked-svc`, performed by an interactive user) is the only High; sixteen legitimate automated provisions are correctly triaged Low. No accounts filtered out — coverage is intact.*

A detail worth noting: my manual attack took about **5 minutes** end-to-end, versus
sub-second for the automation — yet it still scored High. Because the discriminator is
*who*, not *how fast*, a slow and clumsy attacker is caught just as reliably as a fast one.

---

## What the telemetry taught me

The insight that justified the whole SID-correlation approach came straight from the raw
logs: when an account is added to a group, Windows records the member **by SID only** — the
account *name* field is blank. So correlating this chain by name is impossible; the SID is
the only thread that ties "account created" to "account made admin." The original rule's
faked SID correlation wasn't just brittle — it was papering over a field that genuinely
isn't there.

---

## Honest limitations

- **The counts aren't identical between runs** (the baseline and tuned datasets were
  generated as separate batches, and the generator prunes accounts). The metric that
  matters isn't a raw count — it's the shift from *0% precision* to *benign suppressed,
  attack isolated*.
- **The behavioural discriminator has a known blind spot:** an attacker who first escalates
  to the automation/SYSTEM context would score Low. That's a real gap — the honest next
  step is to layer a second signal (e.g. logon-session lineage) rather than trust the
  Subject alone. Naming the limit is part of the engineering.
- **The lab is single-host and intermittent**, so benign activity is generated on demand
  rather than accrued continuously. The tuning logic is unaffected; the volume is
  representative, not longitudinal.

---

## What this demonstrates

- Detecting a technique is the easy half; **distinguishing malicious from benign** is the
  half that matters — and it's measured here, not asserted.
- Tuning was done on **behaviour**, not brittle exclusions, with **no loss of coverage**.
- The work includes its own **validation** (the attack still fires) and an honest account
  of its **limits** — the difference between an engineered detection and a tutorial.

*Prepared as part of an ongoing SOC detection-engineering portfolio.*
