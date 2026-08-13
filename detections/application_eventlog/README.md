# application eventlog

Windows **Application** channel — MsiInstaller, ESENT, Application Error, MSSQL and other application providers.

**25 rules** — critical 1, high 16, medium 8

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| Audit CVE Event | critical | T1203, T1068, T1211, T1212… | [audit_cve_event.yaml](./audit_cve_event.yaml) |
| Atera Agent Installation | high | T1219.002 | [atera_agent_installation.yaml](./atera_agent_installation.yaml) |
| CVE-2024-49113 Exploitation Attempt - LDAP Nightmare | high | T1499 | [cve_2024_49113_exploitation_attempt_ldap_nightmare.yaml](./cve_2024_49113_exploitation_attempt_ldap_nightmare.yaml) |
| Exploitation Activity of CVE-2025-59287 - WSUS Deserialization | high | T1190, T1203 | [exploitation_activity_of_cve_2025_59287_wsus_deserialization.yaml](./exploitation_activity_of_cve_2025_59287_wsus_deserialization.yaml) |
| LPE InstallerFileTakeOver PoC CVE-2021-41379 | high | T1190 | [lpe_installerfiletakeover_poc_cve_2021_41379.yaml](./lpe_installerfiletakeover_poc_cve_2021_41379.yaml) |
| LSASS Crash Via Netlogon Stack Buffer Overflow - CVE-2026-41089 | high | T1499 | [lsass_crash_via_netlogon_stack_buffer_overflow_cve_2026_41089.yaml](./lsass_crash_via_netlogon_stack_buffer_overflow_cve_2026_41089.yaml) |
| LSASS Process Crashed - Application | high | T1003.001 | [lsass_process_crashed_application.yaml](./lsass_process_crashed_application.yaml) |
| Microsoft Malware Protection Engine Crash | high | T1211, T1685 | [microsoft_malware_protection_engine_crash.yaml](./microsoft_malware_protection_engine_crash.yaml) |
| Microsoft Malware Protection Engine Crash - WER | high | T1211, T1685 | [microsoft_malware_protection_engine_crash_wer.yaml](./microsoft_malware_protection_engine_crash_wer.yaml) |
| MSMQ Corrupted Packet Encountered | high | — | [msmq_corrupted_packet_encountered.yaml](./msmq_corrupted_packet_encountered.yaml) |
| MSSQL Add Account To Sysadmin Role | high | — | [mssql_add_account_to_sysadmin_role.yaml](./mssql_add_account_to_sysadmin_role.yaml) |
| MSSQL Disable Audit Settings | high | — | [mssql_disable_audit_settings.yaml](./mssql_disable_audit_settings.yaml) |
| MSSQL Extended Stored Procedure Backdoor Maggie | high | T1546 | [mssql_extended_stored_procedure_backdoor_maggie.yaml](./mssql_extended_stored_procedure_backdoor_maggie.yaml) |
| MSSQL SPProcoption Set | high | — | [mssql_spprocoption_set.yaml](./mssql_spprocoption_set.yaml) |
| MSSQL XPCmdshell Option Change | high | — | [mssql_xpcmdshell_option_change.yaml](./mssql_xpcmdshell_option_change.yaml) |
| MSSQL XPCmdshell Suspicious Execution | high | — | [mssql_xpcmdshell_suspicious_execution.yaml](./mssql_xpcmdshell_suspicious_execution.yaml) |
| Restricted Software Access By SRP | high | T1072 | [restricted_software_access_by_srp.yaml](./restricted_software_access_by_srp.yaml) |
| Backup Catalog Deleted | medium | T1070.004 | [backup_catalog_deleted.yaml](./backup_catalog_deleted.yaml) |
| CVE-2023-40477 Potential Exploitation - WinRAR Application Crash | medium | — | [cve_2023_40477_potential_exploitation_winrar_application_crash.yaml](./cve_2023_40477_potential_exploitation_winrar_application_crash.yaml) |
| Dump Ntds.dit To Suspicious Location | medium | — | [dump_ntds_dit_to_suspicious_location.yaml](./dump_ntds_dit_to_suspicious_location.yaml) |
| MSI Installation From Suspicious Locations | medium | — | [msi_installation_from_suspicious_locations.yaml](./msi_installation_from_suspicious_locations.yaml) |
| MSI Installation From Web | medium | T1218, T1218.007 | [msi_installation_from_web.yaml](./msi_installation_from_web.yaml) |
| MSSQL Destructive Query | medium | T1485 | [mssql_destructive_query.yaml](./mssql_destructive_query.yaml) |
| MSSQL Server Failed Logon From External Network | medium | T1110 | [mssql_server_failed_logon_from_external_network.yaml](./mssql_server_failed_logon_from_external_network.yaml) |
| Ntdsutil Abuse | medium | T1003.003 | [ntdsutil_abuse.yaml](./ntdsutil_abuse.yaml) |
