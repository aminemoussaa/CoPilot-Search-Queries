# task scheduler operational

Windows **TaskScheduler Operational** channel — scheduled task registration and execution.

**4 rules** — high 2, medium 2

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| Important Scheduled Task Deleted or Disabled | high | T1489 | [important_scheduled_task_deleted_or_disabled.yaml](./important_scheduled_task_deleted_or_disabled.yaml) |
| Scheduled Tasks Names Used By SVR For GraphicalProton Backdoor - Task Scheduler | high | — | [scheduled_tasks_names_used_by_svr_for_graphicalproton_backdoor_task_scheduler.yaml](./scheduled_tasks_names_used_by_svr_for_graphicalproton_backdoor_task_scheduler.yaml) |
| Scheduled Task Executed From A Suspicious Location | medium | T1053.005 | [scheduled_task_executed_from_a_suspicious_location.yaml](./scheduled_task_executed_from_a_suspicious_location.yaml) |
| Scheduled Task Executed Uncommon LOLBIN | medium | T1053.005 | [scheduled_task_executed_uncommon_lolbin.yaml](./scheduled_task_executed_uncommon_lolbin.yaml) |
