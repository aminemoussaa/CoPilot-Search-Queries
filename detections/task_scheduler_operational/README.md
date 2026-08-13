# Windows Task Scheduler Operational Log

**Platform** `Windows` · **Log source** Task Scheduler `Microsoft-Windows-TaskScheduler/Operational` · **4 rules**

Scheduled task registration and execution, complementary to Security 4698 and Sysmon process creation.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 2 · 🟡 medium 2 |
| Status | experimental 4 |
| ATT&CK techniques | 2 distinct |
| Provenance | 4 Sigma-derived, 0 written for this repo |
| Event IDs queried | `129` (3), `140` (1), `141` (2), `142` (1) |

## Onboarding

The TaskScheduler Operational channel is **disabled by default** — enable it in Event Viewer or via `wevtutil sl` before these rules will fire.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 4 |
| `data_win_eventdata_taskName` | 2 |
| `data_win_eventdata_path` | 2 |
| `data_win_eventdata_userName` | 1 |

## Top ATT&CK techniques

[`T1053.005`](https://attack.mitre.org/techniques/T1053/005/) (2) · [`T1489`](https://attack.mitre.org/techniques/T1489/) (1)

## Rules (4)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Important Scheduled Task Deleted or Disabled | 🟠 high | 75 | `T1489` | [`important_scheduled_task_deleted_or_disabled.yaml`](./important_scheduled_task_deleted_or_disabled.yaml) |
| Scheduled Tasks Names Used By SVR For GraphicalProton Backdoor - Task Scheduler | 🟠 high | 75 | — | [`scheduled_tasks_names_used_by_svr_for_graphicalproton_backdoor_task_scheduler.yaml`](./scheduled_tasks_names_used_by_svr_for_graphicalproton_backdoor_task_scheduler.yaml) |
| Scheduled Task Executed From A Suspicious Location | 🟡 medium | 50 | `T1053.005` | [`scheduled_task_executed_from_a_suspicious_location.yaml`](./scheduled_task_executed_from_a_suspicious_location.yaml) |
| Scheduled Task Executed Uncommon LOLBIN | 🟡 medium | 50 | `T1053.005` | [`scheduled_task_executed_uncommon_lolbin.yaml`](./scheduled_task_executed_uncommon_lolbin.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
