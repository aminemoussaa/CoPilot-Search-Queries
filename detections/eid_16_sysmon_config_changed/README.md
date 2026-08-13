# Sysmon Event ID 16 — Sysmon Configuration Changed

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **1 rule**

Sysmon's own configuration being changed — tampering with the sensor itself.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟡 medium 1 |
| Status | experimental 1 |
| ATT&CK techniques | 0 distinct |
| Provenance | 1 Sigma-derived, 0 written for this repo |
| Event IDs queried | `16` (1) |

## Onboarding

Produced automatically by Sysmon; no configuration needed. Always collect it.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 1 |

## Rules (1)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Sysmon Configuration Change | 🟡 medium | 50 | — | [`sysmon_configuration_change.yaml`](./sysmon_configuration_change.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
