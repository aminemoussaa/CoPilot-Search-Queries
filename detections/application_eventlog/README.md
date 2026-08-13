# Windows Application Event Log

**Platform** `Windows` · **Log source** Windows `Application` · **25 rules**

Application-provider records: MsiInstaller, ESENT, Application Error crash events, Windows Backup, software restriction policies and MSSQL auditing.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🔴 critical 1 · 🟠 high 16 · 🟡 medium 8 |
| Status | experimental 25 |
| ATT&CK techniques | 19 distinct |
| Provenance | 25 Sigma-derived, 0 written for this repo |
| Event IDs queried | `1` (1), `325` (2), `524` (1), `1000` (5), `1001` (1), `1033` (2), `1040` (2), `1042` (2), `2027` (1), `7053` (1), `8128` (1), `33205` (5) — and 10 more |

## Onboarding

Collected by default. MSSQL audit rules additionally require SQL Server auditing to be configured and writing to the Windows Application log.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_providerName` | 25 |
| `data_win_system_eventID` | 25 |
| `data_win_eventdata_data` | 16 |
| `data_win_eventdata_appName` | 3 |
| `data_win_eventdata_message` | 2 |
| `data_win_eventdata_exceptionCode` | 2 |
| `data_win_eventdata_appVersion` | 1 |
| `data_win_eventdata_moduleName` | 1 |
| `data_win_system_level` | 1 |

## Top ATT&CK techniques

[`T1211`](https://attack.mitre.org/techniques/T1211/) (3) · [`T1203`](https://attack.mitre.org/techniques/T1203/) (2) · [`T1499`](https://attack.mitre.org/techniques/T1499/) (2) · [`T1190`](https://attack.mitre.org/techniques/T1190/) (2) · [`T1685`](https://attack.mitre.org/techniques/T1685/) (2) · [`T1219.002`](https://attack.mitre.org/techniques/T1219/002/) (1) · [`T1068`](https://attack.mitre.org/techniques/T1068/) (1) · [`T1212`](https://attack.mitre.org/techniques/T1212/) (1)

## Rules (25)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Audit CVE Event | 🔴 critical | 90 | `T1203`, `T1068`, `T1211`… | [`audit_cve_event.yaml`](./audit_cve_event.yaml) |
| Atera Agent Installation | 🟠 high | 75 | `T1219.002` | [`atera_agent_installation.yaml`](./atera_agent_installation.yaml) |
| CVE-2024-49113 Exploitation Attempt - LDAP Nightmare | 🟠 high | 75 | `T1499` | [`cve_2024_49113_exploitation_attempt_ldap_nightmare.yaml`](./cve_2024_49113_exploitation_attempt_ldap_nightmare.yaml) |
| Exploitation Activity of CVE-2025-59287 - WSUS Deserialization | 🟠 high | 75 | `T1190`, `T1203` | [`exploitation_activity_of_cve_2025_59287_wsus_deserialization.yaml`](./exploitation_activity_of_cve_2025_59287_wsus_deserialization.yaml) |
| LPE InstallerFileTakeOver PoC CVE-2021-41379 | 🟠 high | 75 | `T1190` | [`lpe_installerfiletakeover_poc_cve_2021_41379.yaml`](./lpe_installerfiletakeover_poc_cve_2021_41379.yaml) |
| LSASS Crash Via Netlogon Stack Buffer Overflow - CVE-2026-41089 | 🟠 high | 75 | `T1499` | [`lsass_crash_via_netlogon_stack_buffer_overflow_cve_2026_41089.yaml`](./lsass_crash_via_netlogon_stack_buffer_overflow_cve_2026_41089.yaml) |
| LSASS Process Crashed - Application | 🟠 high | 75 | `T1003.001` | [`lsass_process_crashed_application.yaml`](./lsass_process_crashed_application.yaml) |
| Microsoft Malware Protection Engine Crash | 🟠 high | 75 | `T1211`, `T1685` | [`microsoft_malware_protection_engine_crash.yaml`](./microsoft_malware_protection_engine_crash.yaml) |
| Microsoft Malware Protection Engine Crash - WER | 🟠 high | 75 | `T1211`, `T1685` | [`microsoft_malware_protection_engine_crash_wer.yaml`](./microsoft_malware_protection_engine_crash_wer.yaml) |
| MSMQ Corrupted Packet Encountered | 🟠 high | 75 | — | [`msmq_corrupted_packet_encountered.yaml`](./msmq_corrupted_packet_encountered.yaml) |
| MSSQL Add Account To Sysadmin Role | 🟠 high | 75 | — | [`mssql_add_account_to_sysadmin_role.yaml`](./mssql_add_account_to_sysadmin_role.yaml) |
| MSSQL Disable Audit Settings | 🟠 high | 75 | — | [`mssql_disable_audit_settings.yaml`](./mssql_disable_audit_settings.yaml) |
| MSSQL Extended Stored Procedure Backdoor Maggie | 🟠 high | 75 | `T1546` | [`mssql_extended_stored_procedure_backdoor_maggie.yaml`](./mssql_extended_stored_procedure_backdoor_maggie.yaml) |
| MSSQL SPProcoption Set | 🟠 high | 75 | — | [`mssql_spprocoption_set.yaml`](./mssql_spprocoption_set.yaml) |
| MSSQL XPCmdshell Option Change | 🟠 high | 75 | — | [`mssql_xpcmdshell_option_change.yaml`](./mssql_xpcmdshell_option_change.yaml) |
| MSSQL XPCmdshell Suspicious Execution | 🟠 high | 75 | — | [`mssql_xpcmdshell_suspicious_execution.yaml`](./mssql_xpcmdshell_suspicious_execution.yaml) |
| Restricted Software Access By SRP | 🟠 high | 75 | `T1072` | [`restricted_software_access_by_srp.yaml`](./restricted_software_access_by_srp.yaml) |
| Backup Catalog Deleted | 🟡 medium | 50 | `T1070.004` | [`backup_catalog_deleted.yaml`](./backup_catalog_deleted.yaml) |
| CVE-2023-40477 Potential Exploitation - WinRAR Application Crash | 🟡 medium | 50 | — | [`cve_2023_40477_potential_exploitation_winrar_application_crash.yaml`](./cve_2023_40477_potential_exploitation_winrar_application_crash.yaml) |
| Dump Ntds.dit To Suspicious Location | 🟡 medium | 50 | — | [`dump_ntds_dit_to_suspicious_location.yaml`](./dump_ntds_dit_to_suspicious_location.yaml) |
| MSI Installation From Suspicious Locations | 🟡 medium | 50 | — | [`msi_installation_from_suspicious_locations.yaml`](./msi_installation_from_suspicious_locations.yaml) |
| MSI Installation From Web | 🟡 medium | 50 | `T1218`, `T1218.007` | [`msi_installation_from_web.yaml`](./msi_installation_from_web.yaml) |
| MSSQL Destructive Query | 🟡 medium | 50 | `T1485` | [`mssql_destructive_query.yaml`](./mssql_destructive_query.yaml) |
| MSSQL Server Failed Logon From External Network | 🟡 medium | 50 | `T1110` | [`mssql_server_failed_logon_from_external_network.yaml`](./mssql_server_failed_logon_from_external_network.yaml) |
| Ntdsutil Abuse | 🟡 medium | 50 | `T1003.003` | [`ntdsutil_abuse.yaml`](./ntdsutil_abuse.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
