# Sysmon Event IDs 23 / 26 — File Delete

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **11 rules**

File deletion with archiving (23) and deletion detected without archiving (26) — anti-forensics and ransomware cleanup.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 4 · 🟡 medium 7 |
| Status | experimental 11 |
| ATT&CK techniques | 5 distinct |
| Provenance | 11 Sigma-derived, 0 written for this repo |
| Event IDs queried | `23` (11), `26` (11) |

## Onboarding

Enable `FileDelete` (archives the file) or `FileDeleteDetected` (log only) in the Sysmon config. Archiving consumes disk on the endpoint.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_eventdata_targetFilename` | 11 |
| `data_win_system_eventID` | 11 |
| `data_win_eventdata_image` | 5 |
| `data_win_eventdata_user` | 1 |

## Top ATT&CK techniques

[`T1070`](https://attack.mitre.org/techniques/T1070/) (5) · [`T1070.004`](https://attack.mitre.org/techniques/T1070/004/) (3) · [`T1490`](https://attack.mitre.org/techniques/T1490/) (1) · [`T1574`](https://attack.mitre.org/techniques/T1574/) (1) · [`T1133`](https://attack.mitre.org/techniques/T1133/) (1)

## Rules (11)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Exchange PowerShell Cmdlet History Deleted | 🟠 high | 75 | `T1070` | [`exchange_powershell_cmdlet_history_deleted.yaml`](./exchange_powershell_cmdlet_history_deleted.yaml) |
| Potential PrintNightmare Exploitation Attempt | 🟠 high | 75 | `T1574` | [`potential_printnightmare_exploitation_attempt.yaml`](./potential_printnightmare_exploitation_attempt.yaml) |
| Prefetch File Deleted | 🟠 high | 75 | `T1070.004` | [`prefetch_file_deleted.yaml`](./prefetch_file_deleted.yaml) |
| Unusual File Deletion by Dns.exe | 🟠 high | 75 | `T1133` | [`unusual_file_deletion_by_dns_exe.yaml`](./unusual_file_deletion_by_dns_exe.yaml) |
| ADS Zone.Identifier Deleted By Uncommon Application | 🟡 medium | 50 | `T1070.004` | [`ads_zone_identifier_deleted_by_uncommon_application.yaml`](./ads_zone_identifier_deleted_by_uncommon_application.yaml) |
| Backup Files Deleted | 🟡 medium | 50 | `T1490` | [`backup_files_deleted.yaml`](./backup_files_deleted.yaml) |
| EventLog EVTX File Deleted | 🟡 medium | 50 | `T1070` | [`eventlog_evtx_file_deleted.yaml`](./eventlog_evtx_file_deleted.yaml) |
| File Deleted Via Sysinternals SDelete | 🟡 medium | 50 | `T1070.004` | [`file_deleted_via_sysinternals_sdelete.yaml`](./file_deleted_via_sysinternals_sdelete.yaml) |
| IIS WebServer Access Logs Deleted | 🟡 medium | 50 | `T1070` | [`iis_webserver_access_logs_deleted.yaml`](./iis_webserver_access_logs_deleted.yaml) |
| PowerShell Console History Logs Deleted | 🟡 medium | 50 | `T1070` | [`powershell_console_history_logs_deleted.yaml`](./powershell_console_history_logs_deleted.yaml) |
| Tomcat WebServer Logs Deleted | 🟡 medium | 50 | `T1070` | [`tomcat_webserver_logs_deleted.yaml`](./tomcat_webserver_logs_deleted.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
