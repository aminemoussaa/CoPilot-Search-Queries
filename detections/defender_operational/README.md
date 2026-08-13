# Microsoft Defender Operational Log

**Platform** `Windows` · **Log source** Defender `Microsoft-Windows-Windows Defender/Operational` · **15 rules**

Defender's own telemetry: malware detections and remediation outcomes, exclusion changes, and real-time protection being disabled.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🔴 critical 1 · 🟠 high 12 · 🟡 medium 2 |
| Status | production 10, experimental 5 |
| ATT&CK techniques | 7 distinct |
| Provenance | 15 Sigma-derived, 0 written for this repo |
| Event IDs queried | `1006` (1), `1009` (1), `1116` (2), `1119` (1), `1121` (2), `3002` (1), `3007` (1), `5001` (1), `5007` (3), `5010` (1), `5013` (1), `5101` (1) — and 3 more |

## Onboarding

Collected by default where Defender is enabled. Exclusion-change events (5007) are a key tamper signal — collect them even if you forward nothing else.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 15 |
| `data_win_eventdata_processName` | 3 |
| `data_win_eventdata_newValue` | 3 |
| `data_win_eventdata_path` | 2 |
| `data_win_eventdata_sourceName` | 2 |
| `data_win_eventdata_value` | 1 |
| `data_win_eventdata_threatName` | 1 |
| `data_win_eventdata_oldValue` | 1 |
| `data_win_eventdata_reason` | 1 |
| `data_win_eventdata_feature_Name` | 1 |

## Top ATT&CK techniques

[`T1685`](https://attack.mitre.org/techniques/T1685/) (11) · [`T1059`](https://attack.mitre.org/techniques/T1059/) (2) · [`T1003.001`](https://attack.mitre.org/techniques/T1003/001/) (1) · [`T1047`](https://attack.mitre.org/techniques/T1047/) (1) · [`T1569.002`](https://attack.mitre.org/techniques/T1569/002/) (1) · [`T1036.005`](https://attack.mitre.org/techniques/T1036/005/) (1) · [`T1055`](https://attack.mitre.org/techniques/T1055/) (1)

## Rules (15)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| RedSun - TieringEngineService.exe Detected as EICAR Test File | 🔴 critical | 90 | `T1036.005`, `T1685`, `T1055` | [`redsun_tieringengineservice_exe_detected_as_eicar_test_file.yaml`](./redsun_tieringengineservice_exe_detected_as_eicar_test_file.yaml) |
| LSASS Access Detected via Attack Surface Reduction | 🟠 high | 75 | `T1003.001` | [`lsass_access_detected_via_attack_surface_reduction.yaml`](./lsass_access_detected_via_attack_surface_reduction.yaml) |
| Microsoft Defender Tamper Protection Trigger | 🟠 high | 75 | `T1685` | [`microsoft_defender_tamper_protection_trigger.yaml`](./microsoft_defender_tamper_protection_trigger.yaml) |
| PSExec and WMI Process Creations Block | 🟠 high | 75 | `T1047`, `T1569.002` | [`psexec_and_wmi_process_creations_block.yaml`](./psexec_and_wmi_process_creations_block.yaml) |
| Win Defender Restored Quarantine File | 🟠 high | 75 | `T1685` | [`win_defender_restored_quarantine_file.yaml`](./win_defender_restored_quarantine_file.yaml) |
| Windows Defender AMSI Trigger Detected | 🟠 high | 75 | `T1059` | [`windows_defender_amsi_trigger_detected.yaml`](./windows_defender_amsi_trigger_detected.yaml) |
| Windows Defender Configuration Changes | 🟠 high | 75 | `T1685` | [`windows_defender_configuration_changes.yaml`](./windows_defender_configuration_changes.yaml) |
| Windows Defender Exploit Guard Tamper | 🟠 high | 75 | `T1685` | [`windows_defender_exploit_guard_tamper.yaml`](./windows_defender_exploit_guard_tamper.yaml) |
| Windows Defender Grace Period Expired | 🟠 high | 75 | `T1685` | [`windows_defender_grace_period_expired.yaml`](./windows_defender_grace_period_expired.yaml) |
| Windows Defender Malware And PUA Scanning Disabled | 🟠 high | 75 | `T1685` | [`windows_defender_malware_and_pua_scanning_disabled.yaml`](./windows_defender_malware_and_pua_scanning_disabled.yaml) |
| Windows Defender Real-time Protection Disabled | 🟠 high | 75 | `T1685` | [`windows_defender_real_time_protection_disabled.yaml`](./windows_defender_real_time_protection_disabled.yaml) |
| Windows Defender Threat Detected | 🟠 high | 75 | `T1059` | [`windows_defender_threat_detected.yaml`](./windows_defender_threat_detected.yaml) |
| Windows Defender Virus Scanning Feature Disabled | 🟠 high | 75 | `T1685` | [`windows_defender_virus_scanning_feature_disabled.yaml`](./windows_defender_virus_scanning_feature_disabled.yaml) |
| Windows Defender Exclusions Added | 🟡 medium | 50 | `T1685` | [`windows_defender_exclusions_added.yaml`](./windows_defender_exclusions_added.yaml) |
| Windows Defender Real-Time Protection Failure/Restart | 🟡 medium | 50 | `T1685` | [`windows_defender_real_time_protection_failure_restart.yaml`](./windows_defender_real_time_protection_failure_restart.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
