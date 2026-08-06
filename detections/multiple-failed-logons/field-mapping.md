# Field Mapping — Multiple Failed Logons (Event ID 4625)

The same detection concept, resolved across each platform's schema. This is the
artefact that proves the port preserved *meaning*, not just syntax.

| Detection concept | Splunk (`WinEventLog:Security`, CIM/TA-normalised) | Sentinel `SecurityEvent` | ADX test table |
|---|---|---|---|
| Event selector | `EventCode=4625` | `EventID == 4625` | `EventID == 4625` |
| Target account | `user`  *(raw: `Account_Name`)* | `Account`  *(also `TargetUserName`)* | `Account` |
| Host | `host` | `Computer` | `Computer` |
| Source IP | `src_ip`  *(raw: `Source_Network_Address`)* | `IpAddress` | `IpAddress` |
| Logon type | `Logon_Type` | `LogonType` | `LogonType` |
| Timestamp | `_time` | `TimeGenerated` | `TimeGenerated` |

## Notes on the differences

- **Schema-on-read vs schema-on-write.** In Splunk the fields above only exist
  if the Windows TA (or CIM) extracts them; a raw forwarder gives you
  `Account_Name` twice (Subject and Target) and you must disambiguate. In
  Sentinel/ADX the columns are fixed and typed — no extraction step, but no
  flexibility either.
- **Account format.** `SecurityEvent.Account` is usually `DOMAIN\user`; the SPL
  `user` may be the bare username depending on normalisation. If you correlate
  across platforms, normalise case and strip the domain first
  (`Account` is compared case-sensitively in KQL — use `tolower()` if joining).
- **The ADX column set is deliberately a subset of `SecurityEvent`** — only the
  columns this detection needs. That is why the query is labelled
  *tested on an Event-compatible schema*, not *tested in production Sentinel*.
