# Sysmon Event ID 8 — CreateRemoteThread

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **12 rules**

A thread created in another process — a direct signal of classic code injection.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 9 · 🟡 medium 3 |
| Status | experimental 11, production 1 |
| ATT&CK techniques | 12 distinct |
| Provenance | 12 Sigma-derived, 0 written for this repo |
| Event IDs queried | `8` (12) |

## Onboarding

Enable `CreateRemoteThread` in the Sysmon config. Low volume once common Windows sources are excluded.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 12 |
| `data_win_eventdata_targetImage` | 10 |
| `data_win_eventdata_sourceImage` | 9 |
| `data_win_eventdata_startAddress` | 1 |
| `data_win_eventdata_startModule` | 1 |
| `data_win_eventdata_targetParentProcessId` | 1 |
| `data_win_eventdata_sourceParentImage` | 1 |
| `data_win_eventdata_sourceCommandLine` | 1 |
| `data_win_eventdata_startFunction` | 1 |

## Top ATT&CK techniques

[`T1003.001`](https://attack.mitre.org/techniques/T1003/001/) (2) · [`T1218.011`](https://attack.mitre.org/techniques/T1218/011/) (2) · [`T1059.001`](https://attack.mitre.org/techniques/T1059/001/) (2) · [`T1055`](https://attack.mitre.org/techniques/T1055/) (2) · [`T1055.012`](https://attack.mitre.org/techniques/T1055/012/) (1) · [`T1059.005`](https://attack.mitre.org/techniques/T1059/005/) (1) · [`T1059.007`](https://attack.mitre.org/techniques/T1059/007/) (1) · [`T1218.005`](https://attack.mitre.org/techniques/T1218/005/) (1)

## Rules (12)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| HackTool - CACTUSTORCH Remote Thread Creation | 🟠 high | 75 | `T1055.012`, `T1059.005`, `T1059.007`… | [`hacktool_cactustorch_remote_thread_creation.yaml`](./hacktool_cactustorch_remote_thread_creation.yaml) |
| HackTool - Potential CobaltStrike Process Injection | 🟠 high | 75 | `T1055.001` | [`hacktool_potential_cobaltstrike_process_injection.yaml`](./hacktool_potential_cobaltstrike_process_injection.yaml) |
| Password Dumper Remote Thread in LSASS | 🟠 high | 75 | `T1003.001` | [`password_dumper_remote_thread_in_lsass.yaml`](./password_dumper_remote_thread_in_lsass.yaml) |
| Potential Bumblebee Remote Thread Creation | 🟠 high | 75 | `T1218.011`, `T1059.001` | [`potential_bumblebee_remote_thread_creation.yaml`](./potential_bumblebee_remote_thread_creation.yaml) |
| Potential Credential Dumping Attempt Via PowerShell Remote Thread | 🟠 high | 75 | `T1003.001` | [`potential_credential_dumping_attempt_via_powershell_remote_thread.yaml`](./potential_credential_dumping_attempt_via_powershell_remote_thread.yaml) |
| Rare Remote Thread Creation By Uncommon Source Image | 🟠 high | 75 | `T1055` | [`rare_remote_thread_creation_by_uncommon_source_image.yaml`](./rare_remote_thread_creation_by_uncommon_source_image.yaml) |
| Remote Thread Created In KeePass.EXE | 🟠 high | 75 | `T1555.005` | [`remote_thread_created_in_keepass_exe.yaml`](./remote_thread_created_in_keepass_exe.yaml) |
| Remote Thread Creation In Mstsc.Exe From Suspicious Location | 🟠 high | 75 | — | [`remote_thread_creation_in_mstsc_exe_from_suspicious_location.yaml`](./remote_thread_creation_in_mstsc_exe_from_suspicious_location.yaml) |
| Remote Thread Creation Ttdinject.exe Proxy | 🟠 high | 75 | `T1127` | [`remote_thread_creation_ttdinject_exe_proxy.yaml`](./remote_thread_creation_ttdinject_exe_proxy.yaml) |
| Remote Thread Creation By Uncommon Source Image | 🟡 medium | 50 | `T1055` | [`remote_thread_creation_by_uncommon_source_image.yaml`](./remote_thread_creation_by_uncommon_source_image.yaml) |
| Remote Thread Creation In Uncommon Target Image | 🟡 medium | 50 | `T1055.003` | [`remote_thread_creation_in_uncommon_target_image.yaml`](./remote_thread_creation_in_uncommon_target_image.yaml) |
| Remote Thread Creation Via PowerShell In Uncommon Target | 🟡 medium | 50 | `T1218.011`, `T1059.001` | [`remote_thread_creation_via_powershell_in_uncommon_target.yaml`](./remote_thread_creation_via_powershell_in_uncommon_target.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
