# Sysmon — Multi-Event Rules

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **2 rules**

Rules whose query spans more than one Sysmon event ID without matching one of the canonical event families above.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 1 · 🟡 medium 1 |
| Status | production 2 |
| ATT&CK techniques | 4 distinct |
| Provenance | 0 Sigma-derived, 2 written for this repo |
| Event IDs queried | `1` (2), `3` (1), `13` (1) |

## Onboarding

Check each rule's `data_source` for the specific event IDs it needs.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 2 |
| `data_win_eventdata_targetObject` | 1 |
| `data_win_eventdata_commandLine` | 1 |
| `data_win_eventdata_initiatingProcessImageFileName` | 1 |
| `data_win_eventdata_originalFileName` | 1 |
| `data_win_eventdata_image` | 1 |
| `data_win_eventdata_product` | 1 |

## Top ATT&CK techniques

[`T1546`](https://attack.mitre.org/techniques/T1546/) (1) · [`T1053.005`](https://attack.mitre.org/techniques/T1053/005/) (1) · [`T1176`](https://attack.mitre.org/techniques/T1176/) (1) · [`T1518`](https://attack.mitre.org/techniques/T1518/) (1)

## Rules (2)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Windows Compatibility Telemetry Tampering Through Registry | 🟠 high | 72 | `T1546`, `T1053.005` | [`windows_compatibility_telemetry_tampering_through_registry.yaml`](./windows_compatibility_telemetry_tampering_through_registry.yaml) |
| Windows WaveBrowser PUP Detection | 🟡 medium | 50 | `T1176`, `T1518` | [`windows_wavebrowser_pup_detection.yaml`](./windows_wavebrowser_pup_detection.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
