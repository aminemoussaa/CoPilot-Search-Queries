# Sysmon Event IDs 19 / 20 / 21 — WMI Events

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **4 rules**

WMI permanent event filters (19), consumers (20) and filter-to-consumer bindings (21) — the classic fileless persistence triad.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 3 · 🟡 medium 1 |
| Status | experimental 3, production 1 |
| ATT&CK techniques | 3 distinct |
| Provenance | 3 Sigma-derived, 1 written for this repo |
| Event IDs queried | `19` (4), `20` (4), `21` (4) |

## Onboarding

Enable `WmiEvent` in the Sysmon config. All three IDs matter: a subscription is only armed once the binding exists.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 4 |
| `data_win_eventdata_destination` | 2 |

## Top ATT&CK techniques

[`T1546.003`](https://attack.mitre.org/techniques/T1546/003/) (3) · [`T1047`](https://attack.mitre.org/techniques/T1047/) (1) · [`T1059.005`](https://attack.mitre.org/techniques/T1059/005/) (1)

## Rules (4)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Suspicious Encoded Scripts in a WMI Consumer | 🟠 high | 75 | `T1047`, `T1546.003` | [`suspicious_encoded_scripts_in_a_wmi_consumer.yaml`](./suspicious_encoded_scripts_in_a_wmi_consumer.yaml) |
| Suspicious Scripting in a WMI Consumer | 🟠 high | 75 | `T1059.005` | [`suspicious_scripting_in_a_wmi_consumer.yaml`](./suspicious_scripting_in_a_wmi_consumer.yaml) |
| Windows WMI Permanent Event Subscription | 🟠 high | 72 | `T1546.003` | [`wmi_permanent_event_subscription_sysmon.yaml`](./wmi_permanent_event_subscription_sysmon.yaml) |
| WMI Event Subscription | 🟡 medium | 50 | `T1546.003` | [`wmi_event_subscription.yaml`](./wmi_event_subscription.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
