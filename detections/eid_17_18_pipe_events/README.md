# Sysmon Event IDs 17 / 18 — Named Pipe Events

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **17 rules**

Named pipe creation (17) and connection (18). Default pipe names are a reliable fingerprint for C2 frameworks and privilege-escalation tooling.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🔴 critical 7 · 🟠 high 3 · 🟡 medium 7 |
| Status | experimental 17 |
| ATT&CK techniques | 14 distinct |
| Provenance | 17 Sigma-derived, 0 written for this repo |
| Event IDs queried | `17` (17), `18` (17) |

## Onboarding

Enable `PipeEvent` in the Sysmon config. Both event IDs are needed — a rule that only watches creation misses the client side.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 17 |
| `data_win_eventdata_pipeName` | 16 |
| `data_win_eventdata_image` | 5 |

## Top ATT&CK techniques

[`T1055`](https://attack.mitre.org/techniques/T1055/) (6) · [`T1569.002`](https://attack.mitre.org/techniques/T1569/002/) (4) · [`T1021.002`](https://attack.mitre.org/techniques/T1021/002/) (2) · [`T1005`](https://attack.mitre.org/techniques/T1005/) (1) · [`T1059.001`](https://attack.mitre.org/techniques/T1059/001/) (1) · [`T1003.001`](https://attack.mitre.org/techniques/T1003/001/) (1) · [`T1003.002`](https://attack.mitre.org/techniques/T1003/002/) (1) · [`T1003.004`](https://attack.mitre.org/techniques/T1003/004/) (1)

## Rules (17)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| CobaltStrike Named Pipe | 🔴 critical | 90 | `T1055` | [`cobaltstrike_named_pipe.yaml`](./cobaltstrike_named_pipe.yaml) |
| HackTool - Credential Dumping Tools Named Pipe Created | 🔴 critical | 90 | `T1003.001`, `T1003.002`, `T1003.004`… | [`hacktool_credential_dumping_tools_named_pipe_created.yaml`](./hacktool_credential_dumping_tools_named_pipe_created.yaml) |
| HackTool - DiagTrackEoP Default Named Pipe | 🔴 critical | 90 | — | [`hacktool_diagtrackeop_default_named_pipe.yaml`](./hacktool_diagtrackeop_default_named_pipe.yaml) |
| HackTool - Koh Default Named Pipe | 🔴 critical | 90 | `T1528`, `T1134.001` | [`hacktool_koh_default_named_pipe.yaml`](./hacktool_koh_default_named_pipe.yaml) |
| Malicious Named Pipe Created | 🔴 critical | 90 | `T1055` | [`malicious_named_pipe_created.yaml`](./malicious_named_pipe_created.yaml) |
| RedSun - Named Pipe Created | 🔴 critical | 90 | `T1055`, `T1685` | [`redsun_named_pipe_created.yaml`](./redsun_named_pipe_created.yaml) |
| Turla Group Named Pipes | 🔴 critical | 90 | `T1106` | [`turla_group_named_pipes.yaml`](./turla_group_named_pipes.yaml) |
| CobaltStrike Named Pipe Patterns | 🟠 high | 75 | `T1055` | [`cobaltstrike_named_pipe_patterns.yaml`](./cobaltstrike_named_pipe_patterns.yaml) |
| HackTool - CoercedPotato Named Pipe Creation | 🟠 high | 75 | `T1055` | [`hacktool_coercedpotato_named_pipe_creation.yaml`](./hacktool_coercedpotato_named_pipe_creation.yaml) |
| HackTool - EfsPotato Named Pipe Creation | 🟠 high | 75 | `T1055` | [`hacktool_efspotato_named_pipe_creation.yaml`](./hacktool_efspotato_named_pipe_creation.yaml) |
| ADFS Database Named Pipe Connection By Uncommon Tool | 🟡 medium | 50 | `T1005` | [`adfs_database_named_pipe_connection_by_uncommon_tool.yaml`](./adfs_database_named_pipe_connection_by_uncommon_tool.yaml) |
| Alternate PowerShell Hosts Pipe | 🟡 medium | 50 | `T1059.001` | [`alternate_powershell_hosts_pipe.yaml`](./alternate_powershell_hosts_pipe.yaml) |
| PsExec Tool Execution From Suspicious Locations - PipeName | 🟡 medium | 50 | `T1569.002` | [`psexec_tool_execution_from_suspicious_locations_pipename.yaml`](./psexec_tool_execution_from_suspicious_locations_pipename.yaml) |
| PUA - CSExec Default Named Pipe | 🟡 medium | 50 | `T1021.002`, `T1569.002` | [`pua_csexec_default_named_pipe.yaml`](./pua_csexec_default_named_pipe.yaml) |
| PUA - PAExec Default Named Pipe | 🟡 medium | 50 | `T1569.002` | [`pua_paexec_default_named_pipe.yaml`](./pua_paexec_default_named_pipe.yaml) |
| PUA - RemCom Default Named Pipe | 🟡 medium | 50 | `T1021.002`, `T1569.002` | [`pua_remcom_default_named_pipe.yaml`](./pua_remcom_default_named_pipe.yaml) |
| WMI Event Consumer Created Named Pipe | 🟡 medium | 50 | `T1047` | [`wmi_event_consumer_created_named_pipe.yaml`](./wmi_event_consumer_created_named_pipe.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
