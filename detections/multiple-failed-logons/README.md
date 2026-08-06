# Detection 1 — Multiple Failed Logons (burst)

Dual-SIEM detection: the same logic implemented in Splunk SPL and Microsoft KQL,
mapped to the same ATT&CK technique and validated against the same test data.
This is the **workflow-proving** detection — it establishes the repository format,
the field-mapping process, and the ADX test harness before the ClickFix case study.

---

## Detection objective

Flag any single account that accumulates **≥ 10 failed logons within a 5-minute
window**, indicating interactive/service-account password guessing or brute force
against one target — as distinct from a slow "low-and-slow" attempt that stays
under the per-window threshold.

## Data source

| | |
|---|---|
| Event | Windows Security **Event ID 4625** (An account failed to log on) |
| Splunk | `WinEventLog:Security` via the Splunk Add-on for Microsoft Windows |
| Sentinel | `SecurityEvent` table (Windows Security Events connector, AMA) |
| Test substrate | ADX free-cluster mirror table (see `test-data/adx-setup.kql`) |

## MITRE ATT&CK mapping

| Technique | ID | Notes |
|---|---|---|
| Brute Force: Password Guessing | **T1110.001** | Primary — many attempts against one account |
| Brute Force: Password Spraying | T1110.003 | *Adjacent* — invert the detection to `summarize dcount(Account) by IpAddress, bin(...)` to catch one password across many accounts |

## SPL query

See [`detection.spl`](./detection.spl).

## KQL query

See [`detection.kql`](./detection.kql). Runs unchanged in Sentinel and in the
ADX mirror table.

## Field mapping

See [`field-mapping.md`](./field-mapping.md) for the full Splunk → Sentinel → ADX
column crosswalk and the schema-on-read vs schema-on-write notes.

## Testing method

The dataset in `test-data/sample-4625-events.csv` contains 30 synthetic 4625
events across three accounts, designed so exactly one should fire:

| Account | Pattern | Design intent |
|---|---|---|
| `svc_backup` | 12 failures inside 02:00–02:05 | **Should fire** (burst over threshold) |
| `jsmith` | 3 failures | Should not fire (below threshold) |
| `admin` | 15 failures spread over 20 min (≤4 per window) | Should **not** fire — proves the 5-minute windowing suppresses a slow drip that a raw total-count rule would wrongly flag |

**KQL path:** run `test-data/adx-setup.kql` in the ADX free cluster to create the
`SecurityEvent` mirror table and ingest the sample, then run `detection.kql`.
**SPL path:** ingest the same CSV into a test index (or generate live 4625s on the
lab endpoint) and run `detection.spl`.

## Results

Verified against the sample data:

| Account | 5-min window | Failures | SPL | KQL (ADX) | Expected |
|---|---|---|---|---|---|
| `svc_backup` | 02:00 | 12 | Fires | Fires | **Fires** |
| `admin` | any single window | ≤ 4 | Suppressed | Suppressed | Suppressed |
| `jsmith` | 02:00 | 3 | Suppressed | Suppressed | Suppressed |

Both implementations return the identical single result row (`svc_backup`,
`failures = 12`), confirming logic equivalence across the two schemas.

## False positives

- **Service / batch accounts** with expired cached credentials can generate
  bursts of 4625 (LogonType 3/5) — tune by excluding known service accounts or
  raising the threshold for them specifically.
- **Password rotation events** (a user updating a password across mapped drives,
  mobile clients, saved sessions) can briefly spike.
- **Vulnerability scanners / NAC health checks** authenticating on a schedule.

## Limitations

- Threshold/window are static; a patient attacker pacing under 10/5-min evades it.
  Pair with a longer-window low-volume companion rule for full coverage.
- 4625 alone does not confirm compromise — a **subsequent 4624 (success)** for the
  same account is the escalation signal and should be a follow-on correlation.
- LogonType is captured but not yet used to prioritise (Type 10 RDP vs Type 3
  network should score differently).

## Tested vs schema-validated status

| Implementation | Status |
|---|---|
| SPL (`detection.spl`) | **Tested** against sample 4625 events |
| KQL (`detection.kql`) | **Tested** in Azure Data Explorer using an `Event`-compatible `SecurityEvent` mirror table populated with the sample events. Production Sentinel table mapping validated separately from Microsoft's documented `SecurityEvent` schema. |

*Screenshots of both firing go in `screenshots/`.*
