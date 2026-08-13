# Windows Security Event Log

**Platform** `Windows` · **Log source** Windows `Security` · **141 rules**

Native Windows audit records: logon and account activity, account and group management, object access, directory service changes, privilege use and audit policy changes.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🔴 critical 11 · 🟠 high 79 · 🟡 medium 51 |
| Status | experimental 132, production 9 |
| ATT&CK techniques | 78 distinct |
| Provenance | 137 Sigma-derived, 4 written for this repo |
| Event IDs queried | `4624` (9), `4625` (4), `4656` (14), `4657` (5), `4662` (7), `4663` (17), `4697` (21), `4698` (5), `4720` (5), `4776` (3), `5136` (10), `5145` (19) — and 43 more |

## Onboarding

Configure the relevant Advanced Audit Policy subcategories — most of these events are **not** logged by default. Object access rules additionally need SACLs on the target objects.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 140 |
| `data_win_eventdata_objectName` | 27 |
| `data_win_eventdata_objectType` | 20 |
| `data_win_eventdata_relativeTargetName` | 18 |
| `data_win_eventdata_serviceFileName` | 18 |
| `data_win_eventdata_accessMask` | 15 |
| `data_win_eventdata_processName` | 14 |
| `data_win_eventdata_shareName` | 14 |
| `data_win_eventdata_subjectUserName` | 12 |
| `data_win_eventdata_targetUserName` | 12 |

## Top ATT&CK techniques

[`T1027`](https://attack.mitre.org/techniques/T1027/) (15) · [`T1021.002`](https://attack.mitre.org/techniques/T1021/002/) (12) · [`T1059.001`](https://attack.mitre.org/techniques/T1059/001/) (12) · [`T1053.005`](https://attack.mitre.org/techniques/T1053/005/) (8) · [`T1685`](https://attack.mitre.org/techniques/T1685/) (8) · [`T1098`](https://attack.mitre.org/techniques/T1098/) (7) · [`T1569.002`](https://attack.mitre.org/techniques/T1569/002/) (6) · [`T1012`](https://attack.mitre.org/techniques/T1012/) (5)

## Rules (141)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Active Directory Replication from Non Machine Account | 🔴 critical | 90 | `T1003.006` | [`active_directory_replication_from_non_machine_account.yaml`](./active_directory_replication_from_non_machine_account.yaml) |
| AD Object WriteDAC Access | 🔴 critical | 90 | `T1222.001` | [`ad_object_writedac_access.yaml`](./ad_object_writedac_access.yaml) |
| CosmicDuke Service Installation | 🔴 critical | 90 | `T1543.003`, `T1569.002` | [`cosmicduke_service_installation.yaml`](./cosmicduke_service_installation.yaml) |
| CVE-2021-1675 Print Spooler Exploitation IPC Access | 🔴 critical | 90 | `T1569` | [`cve_2021_1675_print_spooler_exploitation_ipc_access.yaml`](./cve_2021_1675_print_spooler_exploitation_ipc_access.yaml) |
| CVE-2023-23397 Exploitation Attempt | 🔴 critical | 90 | — | [`cve_2023_23397_exploitation_attempt.yaml`](./cve_2023_23397_exploitation_attempt.yaml) |
| CVE-2024-1708 - ScreenConnect Path Traversal Exploitation - Security | 🔴 critical | 90 | — | [`cve_2024_1708_screenconnect_path_traversal_exploitation_security.yaml`](./cve_2024_1708_screenconnect_path_traversal_exploitation_security.yaml) |
| DiagTrackEoP Default Login Username | 🔴 critical | 90 | — | [`diagtrackeop_default_login_username.yaml`](./diagtrackeop_default_login_username.yaml) |
| Diamond Sleet APT Scheduled Task Creation | 🔴 critical | 90 | `T1053.005` | [`diamond_sleet_apt_scheduled_task_creation.yaml`](./diamond_sleet_apt_scheduled_task_creation.yaml) |
| OilRig APT Schedule Task Persistence - Security | 🔴 critical | 90 | `T1053.005`, `T1543.003`, `T1112`… | [`oilrig_apt_schedule_task_persistence_security.yaml`](./oilrig_apt_schedule_task_persistence_security.yaml) |
| WCE wceaux.dll Access | 🔴 critical | 90 | `T1003` | [`wce_wceaux_dll_access.yaml`](./wce_wceaux_dll_access.yaml) |
| Win Susp Computer Name Containing Samtheadmin | 🔴 critical | 90 | `T1078` | [`win_susp_computer_name_containing_samtheadmin.yaml`](./win_susp_computer_name_containing_samtheadmin.yaml) |
| Active Directory User Backdoors | 🟠 high | 75 | `T1098` | [`active_directory_user_backdoors.yaml`](./active_directory_user_backdoors.yaml) |
| AD Privileged Users or Groups Reconnaissance | 🟠 high | 75 | `T1087.002` | [`ad_privileged_users_or_groups_reconnaissance.yaml`](./ad_privileged_users_or_groups_reconnaissance.yaml) |
| ADCS Certificate Template Configuration Vulnerability with Risky EKU | 🟠 high | 75 | — | [`adcs_certificate_template_configuration_vulnerability_with_risky_eku.yaml`](./adcs_certificate_template_configuration_vulnerability_with_risky_eku.yaml) |
| BlueSky Ransomware Artefacts | 🟠 high | 75 | `T1486` | [`bluesky_ransomware_artefacts.yaml`](./bluesky_ransomware_artefacts.yaml) |
| CobaltStrike Service Installations - Security | 🟠 high | 75 | `T1021.002`, `T1543.003`, `T1569.002` | [`cobaltstrike_service_installations_security.yaml`](./cobaltstrike_service_installations_security.yaml) |
| Credential Dumping Tools Service Execution - Security | 🟠 high | 75 | `T1003.001`, `T1003.002`, `T1003.004`… | [`credential_dumping_tools_service_execution_security.yaml`](./credential_dumping_tools_service_execution_security.yaml) |
| DCOM InternetExplorer.Application Iertutil DLL Hijack - Security | 🟠 high | 75 | `T1021.002`, `T1021.003` | [`dcom_internetexplorer_application_iertutil_dll_hijack_security.yaml`](./dcom_internetexplorer_application_iertutil_dll_hijack_security.yaml) |
| DPAPI Domain Backup Key Extraction | 🟠 high | 75 | `T1003.004` | [`dpapi_domain_backup_key_extraction.yaml`](./dpapi_domain_backup_key_extraction.yaml) |
| Enabled User Right in AD to Control User Objects | 🟠 high | 75 | `T1098` | [`enabled_user_right_in_ad_to_control_user_objects.yaml`](./enabled_user_right_in_ad_to_control_user_objects.yaml) |
| ETW Logging Disabled In .NET Processes - Registry | 🟠 high | 75 | `T1112`, `T1685` | [`etw_logging_disabled_in_net_processes_registry.yaml`](./etw_logging_disabled_in_net_processes_registry.yaml) |
| First Time Seen Remote Named Pipe | 🟠 high | 75 | `T1021.002` | [`first_time_seen_remote_named_pipe.yaml`](./first_time_seen_remote_named_pipe.yaml) |
| HackTool - EDRSilencer Execution - Filter Added | 🟠 high | 75 | `T1685` | [`hacktool_edrsilencer_execution_filter_added.yaml`](./hacktool_edrsilencer_execution_filter_added.yaml) |
| HackTool - NoFilter Execution | 🟠 high | 75 | `T1134`, `T1134.001` | [`hacktool_nofilter_execution.yaml`](./hacktool_nofilter_execution.yaml) |
| Hacktool Ruler | 🟠 high | 75 | `T1087`, `T1114`, `T1059`… | [`hacktool_ruler.yaml`](./hacktool_ruler.yaml) |
| Hidden Local User Creation | 🟠 high | 75 | `T1136.001` | [`hidden_local_user_creation.yaml`](./hidden_local_user_creation.yaml) |
| HybridConnectionManager Service Installation | 🟠 high | 75 | `T1554` | [`hybridconnectionmanager_service_installation.yaml`](./hybridconnectionmanager_service_installation.yaml) |
| Impacket PsExec Execution | 🟠 high | 75 | `T1021.002` | [`impacket_psexec_execution.yaml`](./impacket_psexec_execution.yaml) |
| Important Scheduled Task Deleted/Disabled | 🟠 high | 75 | `T1053.005` | [`important_scheduled_task_deleted_disabled.yaml`](./important_scheduled_task_deleted_disabled.yaml) |
| Important Windows Event Auditing Disabled | 🟠 high | 75 | `T1685.001` | [`important_windows_event_auditing_disabled.yaml`](./important_windows_event_auditing_disabled.yaml) |
| Invoke-Obfuscation CLIP+ Launcher - Security | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_clip_launcher_security.yaml`](./invoke_obfuscation_clip_launcher_security.yaml) |
| Invoke-Obfuscation Obfuscated IEX Invocation - Security | 🟠 high | 75 | `T1027` | [`invoke_obfuscation_obfuscated_iex_invocation_security.yaml`](./invoke_obfuscation_obfuscated_iex_invocation_security.yaml) |
| Invoke-Obfuscation STDIN+ Launcher - Security | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_stdin_launcher_security.yaml`](./invoke_obfuscation_stdin_launcher_security.yaml) |
| Invoke-Obfuscation VAR+ Launcher - Security | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_var_launcher_security.yaml`](./invoke_obfuscation_var_launcher_security.yaml) |
| Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - Security | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_var_launcher_obfuscation_security.yaml`](./invoke_obfuscation_var_launcher_obfuscation_security.yaml) |
| Invoke-Obfuscation Via Stdin - Security | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_via_stdin_security.yaml`](./invoke_obfuscation_via_stdin_security.yaml) |
| Invoke-Obfuscation Via Use Clip - Security | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_via_use_clip_security.yaml`](./invoke_obfuscation_via_use_clip_security.yaml) |
| Invoke-Obfuscation Via Use MSHTA - Security | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_via_use_mshta_security.yaml`](./invoke_obfuscation_via_use_mshta_security.yaml) |
| Invoke-Obfuscation Via Use Rundll32 - Security | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_via_use_rundll32_security.yaml`](./invoke_obfuscation_via_use_rundll32_security.yaml) |
| Kapeka Backdoor Scheduled Task Creation | 🟠 high | 75 | `T1053.005` | [`kapeka_backdoor_scheduled_task_creation.yaml`](./kapeka_backdoor_scheduled_task_creation.yaml) |
| Kerberos Manipulation | 🟠 high | 75 | `T1212` | [`kerberos_manipulation.yaml`](./kerberos_manipulation.yaml) |
| Metasploit Or Impacket Service Installation Via SMB PsExec | 🟠 high | 75 | `T1021.002`, `T1570`, `T1569.002` | [`metasploit_or_impacket_service_installation_via_smb_psexec.yaml`](./metasploit_or_impacket_service_installation_via_smb_psexec.yaml) |
| Metasploit SMB Authentication | 🟠 high | 75 | `T1021.002` | [`metasploit_smb_authentication.yaml`](./metasploit_smb_authentication.yaml) |
| Meterpreter or Cobalt Strike Getsystem Service Installation - Security | 🟠 high | 75 | `T1134.001`, `T1134.002` | [`meterpreter_or_cobalt_strike_getsystem_service_installation_security.yaml`](./meterpreter_or_cobalt_strike_getsystem_service_installation_security.yaml) |
| Mimikatz DC Sync | 🟠 high | 75 | `T1003.006` | [`mimikatz_dc_sync.yaml`](./mimikatz_dc_sync.yaml) |
| NetNTLM Downgrade Attack | 🟠 high | 75 | `T1685`, `T1112` | [`netntlm_downgrade_attack.yaml`](./netntlm_downgrade_attack.yaml) |
| Operation Wocao Activity - Security | 🟠 high | 75 | `T1012`, `T1036.004`, `T1027`… | [`operation_wocao_activity_security.yaml`](./operation_wocao_activity_security.yaml) |
| Password Change on Directory Service Restore Mode (DSRM) Account | 🟠 high | 75 | `T1098` | [`password_change_on_directory_service_restore_mode_dsrm_account.yaml`](./password_change_on_directory_service_restore_mode_dsrm_account.yaml) |
| Password Dumper Activity on LSASS | 🟠 high | 75 | `T1003.001` | [`password_dumper_activity_on_lsass.yaml`](./password_dumper_activity_on_lsass.yaml) |
| Password Protected ZIP File Opened (Email Attachment) | 🟠 high | 75 | `T1027`, `T1566.001` | [`password_protected_zip_file_opened_email_attachment.yaml`](./password_protected_zip_file_opened_email_attachment.yaml) |
| Password Protected ZIP File Opened (Suspicious Filenames) | 🟠 high | 75 | `T1027`, `T1105`, `T1036` | [`password_protected_zip_file_opened_suspicious_filenames.yaml`](./password_protected_zip_file_opened_suspicious_filenames.yaml) |
| Persistence and Execution at Scale via GPO Scheduled Task | 🟠 high | 75 | `T1053.005` | [`persistence_and_execution_at_scale_via_gpo_scheduled_task.yaml`](./persistence_and_execution_at_scale_via_gpo_scheduled_task.yaml) |
| PetitPotam Suspicious Kerberos TGT Request | 🟠 high | 75 | `T1187` | [`petitpotam_suspicious_kerberos_tgt_request.yaml`](./petitpotam_suspicious_kerberos_tgt_request.yaml) |
| Possible Impacket SecretDump Remote Activity | 🟠 high | 75 | `T1003.002`, `T1003.004`, `T1003.003` | [`possible_impacket_secretdump_remote_activity.yaml`](./possible_impacket_secretdump_remote_activity.yaml) |
| Possible PetitPotam Coerce Authentication Attempt | 🟠 high | 75 | `T1187` | [`possible_petitpotam_coerce_authentication_attempt.yaml`](./possible_petitpotam_coerce_authentication_attempt.yaml) |
| Possible Shadow Credentials Added | 🟠 high | 75 | `T1556` | [`possible_shadow_credentials_added.yaml`](./possible_shadow_credentials_added.yaml) |
| Potential CVE-2023-36884 Exploitation - Share Access | 🟠 high | 75 | — | [`potential_cve_2023_36884_exploitation_share_access.yaml`](./potential_cve_2023_36884_exploitation_share_access.yaml) |
| Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation | 🟠 high | 75 | `T1557.003` | [`potential_kerberos_coercion_by_spoofing_spns_via_dns_manipulation.yaml`](./potential_kerberos_coercion_by_spoofing_spns_via_dns_manipulation.yaml) |
| Potential Privilege Escalation via Local Kerberos Relay over LDAP | 🟠 high | 75 | `T1548` | [`potential_privilege_escalation_via_local_kerberos_relay_over_ldap.yaml`](./potential_privilege_escalation_via_local_kerberos_relay_over_ldap.yaml) |
| PowerShell Scripts Installed as Services - Security | 🟠 high | 75 | `T1569.002` | [`powershell_scripts_installed_as_services_security.yaml`](./powershell_scripts_installed_as_services_security.yaml) |
| Powerview Add-DomainObjectAcl DCSync AD Extend Right | 🟠 high | 75 | `T1098` | [`powerview_add_domainobjectacl_dcsync_ad_extend_right.yaml`](./powerview_add_domainobjectacl_dcsync_ad_extend_right.yaml) |
| Protected Storage Service Access | 🟠 high | 75 | `T1021.002` | [`protected_storage_service_access.yaml`](./protected_storage_service_access.yaml) |
| RDP Login from Localhost | 🟠 high | 75 | `T1021.001` | [`rdp_login_from_localhost.yaml`](./rdp_login_from_localhost.yaml) |
| RDP over Reverse SSH Tunnel WFP | 🟠 high | 75 | `T1090.001`, `T1090.002`, `T1021.001` | [`rdp_over_reverse_ssh_tunnel_wfp.yaml`](./rdp_over_reverse_ssh_tunnel_wfp.yaml) |
| Reconnaissance Activity | 🟠 high | 75 | `T1087.002`, `T1069.002` | [`reconnaissance_activity.yaml`](./reconnaissance_activity.yaml) |
| Register new Logon Process by Rubeus | 🟠 high | 75 | `T1558.003` | [`register_new_logon_process_by_rubeus.yaml`](./register_new_logon_process_by_rubeus.yaml) |
| Remote PowerShell Sessions Network Connections (WinRM) | 🟠 high | 75 | `T1059.001` | [`remote_powershell_sessions_network_connections_winrm.yaml`](./remote_powershell_sessions_network_connections_winrm.yaml) |
| Replay Attack Detected | 🟠 high | 75 | `T1558` | [`replay_attack_detected.yaml`](./replay_attack_detected.yaml) |
| RottenPotato Like Attack Pattern | 🟠 high | 75 | `T1557.001` | [`rottenpotato_like_attack_pattern.yaml`](./rottenpotato_like_attack_pattern.yaml) |
| SAM Registry Hive Handle Request | 🟠 high | 75 | `T1012`, `T1552.002` | [`sam_registry_hive_handle_request.yaml`](./sam_registry_hive_handle_request.yaml) |
| Scanner PoC for CVE-2019-0708 RDP RCE Vuln | 🟠 high | 75 | `T1210` | [`scanner_poc_for_cve_2019_0708_rdp_rce_vuln.yaml`](./scanner_poc_for_cve_2019_0708_rdp_rce_vuln.yaml) |
| Scheduled Tasks Names Used By SVR For GraphicalProton Backdoor | 🟠 high | 75 | — | [`scheduled_tasks_names_used_by_svr_for_graphicalproton_backdoor.yaml`](./scheduled_tasks_names_used_by_svr_for_graphicalproton_backdoor.yaml) |
| Security Eventlog Cleared | 🟠 high | 75 | `T1685.005` | [`security_eventlog_cleared.yaml`](./security_eventlog_cleared.yaml) |
| Service Installed By Unusual Client - Security | 🟠 high | 75 | `T1543` | [`service_installed_by_unusual_client_security.yaml`](./service_installed_by_unusual_client_security.yaml) |
| SMB Create Remote File Admin Share | 🟠 high | 75 | `T1021.002` | [`smb_create_remote_file_admin_share.yaml`](./smb_create_remote_file_admin_share.yaml) |
| Successful Overpass the Hash Attempt | 🟠 high | 75 | `T1550.002` | [`successful_overpass_the_hash_attempt.yaml`](./successful_overpass_the_hash_attempt.yaml) |
| Suspicious Computer Account Name Change CVE-2021-42287 | 🟠 high | 75 | `T1036`, `T1098` | [`suspicious_computer_account_name_change_cve_2021_42287.yaml`](./suspicious_computer_account_name_change_cve_2021_42287.yaml) |
| Suspicious LDAP-Attributes Used | 🟠 high | 75 | `T1001.003` | [`suspicious_ldap_attributes_used.yaml`](./suspicious_ldap_attributes_used.yaml) |
| Suspicious PsExec Execution | 🟠 high | 75 | `T1021.002` | [`suspicious_psexec_execution.yaml`](./suspicious_psexec_execution.yaml) |
| Suspicious Scheduled Task Creation | 🟠 high | 75 | `T1053.005` | [`suspicious_scheduled_task_creation.yaml`](./suspicious_scheduled_task_creation.yaml) |
| Suspicious Scheduled Task Update | 🟠 high | 75 | `T1053.005` | [`suspicious_scheduled_task_update.yaml`](./suspicious_scheduled_task_update.yaml) |
| Suspicious Teams Application Related ObjectAcess Event | 🟠 high | 75 | `T1528` | [`suspicious_teams_application_related_objectacess_event.yaml`](./suspicious_teams_application_related_objectacess_event.yaml) |
| Suspicious Windows ANONYMOUS LOGON Local Account Created | 🟠 high | 75 | `T1136.001`, `T1136.002` | [`suspicious_windows_anonymous_logon_local_account_created.yaml`](./suspicious_windows_anonymous_logon_local_account_created.yaml) |
| SysKey Registry Keys Access | 🟠 high | 75 | `T1012` | [`syskey_registry_keys_access.yaml`](./syskey_registry_keys_access.yaml) |
| Sysmon Channel Reference Deletion | 🟠 high | 75 | `T1112` | [`sysmon_channel_reference_deletion.yaml`](./sysmon_channel_reference_deletion.yaml) |
| T1047 Wmiprvse Wbemcomn DLL Hijack | 🟠 high | 75 | `T1047`, `T1021.002` | [`t1047_wmiprvse_wbemcomn_dll_hijack.yaml`](./t1047_wmiprvse_wbemcomn_dll_hijack.yaml) |
| User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess' | 🟠 high | 75 | `T1558.003` | [`user_couldn_t_call_a_privileged_service_lsaregisterlogonprocess.yaml`](./user_couldn_t_call_a_privileged_service_lsaregisterlogonprocess.yaml) |
| Weak Encryption Enabled and Kerberoast | 🟠 high | 75 | `T1685` | [`weak_encryption_enabled_and_kerberoast.yaml`](./weak_encryption_enabled_and_kerberoast.yaml) |
| Windows Filtering Platform Blocked Connection From EDR Agent Binary | 🟠 high | 75 | `T1685` | [`windows_filtering_platform_blocked_connection_from_edr_agent_binary.yaml`](./windows_filtering_platform_blocked_connection_from_edr_agent_binary.yaml) |
| Windows User Account Created | 🟠 high | 60 | `T1136.001` | [`windows_user_account_created.yaml`](./windows_user_account_created.yaml) |
| A New Trust Was Created To A Domain | 🟡 medium | 50 | `T1098` | [`a_new_trust_was_created_to_a_domain.yaml`](./a_new_trust_was_created_to_a_domain.yaml) |
| Account Tampering - Suspicious Failed Logon Reasons | 🟡 medium | 50 | `T1078` | [`account_tampering_suspicious_failed_logon_reasons.yaml`](./account_tampering_suspicious_failed_logon_reasons.yaml) |
| Addition of SID History to Active Directory Object | 🟡 medium | 50 | `T1134.005` | [`addition_of_sid_history_to_active_directory_object.yaml`](./addition_of_sid_history_to_active_directory_object.yaml) |
| Azure AD Health Monitoring Agent Registry Keys Access | 🟡 medium | 50 | `T1012` | [`azure_ad_health_monitoring_agent_registry_keys_access.yaml`](./azure_ad_health_monitoring_agent_registry_keys_access.yaml) |
| Azure AD Health Service Agents Registry Keys Access | 🟡 medium | 50 | `T1012` | [`azure_ad_health_service_agents_registry_keys_access.yaml`](./azure_ad_health_service_agents_registry_keys_access.yaml) |
| DCERPC SMB Spoolss Named Pipe | 🟡 medium | 50 | `T1021.002` | [`dcerpc_smb_spoolss_named_pipe.yaml`](./dcerpc_smb_spoolss_named_pipe.yaml) |
| Defrag Deactivation - Security | 🟡 medium | 50 | `T1053` | [`defrag_deactivation_security.yaml`](./defrag_deactivation_security.yaml) |
| Denied Access To Remote Desktop | 🟡 medium | 50 | `T1021.001` | [`denied_access_to_remote_desktop.yaml`](./denied_access_to_remote_desktop.yaml) |
| Device Installation Blocked | 🟡 medium | 50 | `T1200` | [`device_installation_blocked.yaml`](./device_installation_blocked.yaml) |
| DPAPI Domain Master Key Backup Attempt | 🟡 medium | 50 | `T1003.004` | [`dpapi_domain_master_key_backup_attempt.yaml`](./dpapi_domain_master_key_backup_attempt.yaml) |
| File Access Of Signal Desktop Sensitive Data | 🟡 medium | 50 | `T1003` | [`file_access_of_signal_desktop_sensitive_data.yaml`](./file_access_of_signal_desktop_sensitive_data.yaml) |
| Group Policy Abuse for Privilege Addition | 🟡 medium | 50 | `T1484.001` | [`group_policy_abuse_for_privilege_addition.yaml`](./group_policy_abuse_for_privilege_addition.yaml) |
| Invoke-Obfuscation COMPRESS OBFUSCATION - Security | 🟡 medium | 50 | `T1027`, `T1059.001` | [`invoke_obfuscation_compress_obfuscation_security.yaml`](./invoke_obfuscation_compress_obfuscation_security.yaml) |
| Invoke-Obfuscation RUNDLL LAUNCHER - Security | 🟡 medium | 50 | `T1027`, `T1059.001` | [`invoke_obfuscation_rundll_launcher_security.yaml`](./invoke_obfuscation_rundll_launcher_security.yaml) |
| ISO Image Mounted | 🟡 medium | 50 | `T1566.001` | [`iso_image_mounted.yaml`](./iso_image_mounted.yaml) |
| Kerberoasting Activity - Initial Query | 🟡 medium | 50 | `T1558.003` | [`kerberoasting_activity_initial_query.yaml`](./kerberoasting_activity_initial_query.yaml) |
| LSASS Access From Non System Account | 🟡 medium | 50 | `T1003.001` | [`lsass_access_from_non_system_account.yaml`](./lsass_access_from_non_system_account.yaml) |
| New or Renamed User Account with '$' Character | 🟡 medium | 50 | `T1036` | [`new_or_renamed_user_account_with_character.yaml`](./new_or_renamed_user_account_with_character.yaml) |
| Pass the Hash Activity 2 | 🟡 medium | 50 | `T1550.002` | [`pass_the_hash_activity_2.yaml`](./pass_the_hash_activity_2.yaml) |
| Password Policy Enumerated | 🟡 medium | 50 | `T1201` | [`password_policy_enumerated.yaml`](./password_policy_enumerated.yaml) |
| Password Protected ZIP File Opened | 🟡 medium | 50 | `T1027` | [`password_protected_zip_file_opened.yaml`](./password_protected_zip_file_opened.yaml) |
| Possible DC Shadow Attack | 🟡 medium | 50 | `T1207` | [`possible_dc_shadow_attack.yaml`](./possible_dc_shadow_attack.yaml) |
| Potential Access Token Abuse | 🟡 medium | 50 | `T1134.001` | [`potential_access_token_abuse.yaml`](./potential_access_token_abuse.yaml) |
| Potential AD User Enumeration From Non-Machine Account | 🟡 medium | 50 | `T1087.002` | [`potential_ad_user_enumeration_from_non_machine_account.yaml`](./potential_ad_user_enumeration_from_non_machine_account.yaml) |
| Potential AS-REP Roasting via Kerberos TGT Requests | 🟡 medium | 50 | — | [`potential_as_rep_roasting_via_kerberos_tgt_requests.yaml`](./potential_as_rep_roasting_via_kerberos_tgt_requests.yaml) |
| Potential Privileged System Service Operation - SeLoadDriverPrivilege | 🟡 medium | 50 | `T1685` | [`potential_privileged_system_service_operation_seloaddriverprivilege.yaml`](./potential_privileged_system_service_operation_seloaddriverprivilege.yaml) |
| Potential Secure Deletion with SDelete | 🟡 medium | 50 | `T1070.004`, `T1027.005`, `T1485`… | [`potential_secure_deletion_with_sdelete.yaml`](./potential_secure_deletion_with_sdelete.yaml) |
| Potentially Suspicious AccessMask Requested From LSASS | 🟡 medium | 50 | `T1003.001` | [`potentially_suspicious_accessmask_requested_from_lsass.yaml`](./potentially_suspicious_accessmask_requested_from_lsass.yaml) |
| Processes Accessing the Microphone and Webcam | 🟡 medium | 50 | `T1123` | [`processes_accessing_the_microphone_and_webcam.yaml`](./processes_accessing_the_microphone_and_webcam.yaml) |
| Remote Access Tool Services Have Been Installed - Security | 🟡 medium | 50 | `T1543.003`, `T1569.002` | [`remote_access_tool_services_have_been_installed_security.yaml`](./remote_access_tool_services_have_been_installed_security.yaml) |
| Remote Service Activity via SVCCTL Named Pipe | 🟡 medium | 50 | `T1021.002` | [`remote_service_activity_via_svcctl_named_pipe.yaml`](./remote_service_activity_via_svcctl_named_pipe.yaml) |
| Remote Task Creation via ATSVC Named Pipe | 🟡 medium | 50 | `T1053.002` | [`remote_task_creation_via_atsvc_named_pipe.yaml`](./remote_task_creation_via_atsvc_named_pipe.yaml) |
| SCM Database Handle Failure | 🟡 medium | 50 | `T1010` | [`scm_database_handle_failure.yaml`](./scm_database_handle_failure.yaml) |
| SCM Database Privileged Operation | 🟡 medium | 50 | `T1548` | [`scm_database_privileged_operation.yaml`](./scm_database_privileged_operation.yaml) |
| ScreenConnect User Database Modification - Security | 🟡 medium | 50 | — | [`screenconnect_user_database_modification_security.yaml`](./screenconnect_user_database_modification_security.yaml) |
| Startup/Logon Script Added to Group Policy Object | 🟡 medium | 50 | `T1484.001`, `T1547` | [`startup_logon_script_added_to_group_policy_object.yaml`](./startup_logon_script_added_to_group_policy_object.yaml) |
| Suspicious Access to Sensitive File Extensions | 🟡 medium | 50 | `T1039` | [`suspicious_access_to_sensitive_file_extensions.yaml`](./suspicious_access_to_sensitive_file_extensions.yaml) |
| Suspicious Kerberos RC4 Ticket Encryption | 🟡 medium | 50 | `T1558.003` | [`suspicious_kerberos_rc4_ticket_encryption.yaml`](./suspicious_kerberos_rc4_ticket_encryption.yaml) |
| Suspicious Remote Logon with Explicit Credentials | 🟡 medium | 50 | `T1078` | [`suspicious_remote_logon_with_explicit_credentials.yaml`](./suspicious_remote_logon_with_explicit_credentials.yaml) |
| Transferring Files with Credential Data via Network Shares | 🟡 medium | 50 | `T1003.002`, `T1003.001`, `T1003.003` | [`transferring_files_with_credential_data_via_network_shares.yaml`](./transferring_files_with_credential_data_via_network_shares.yaml) |
| Uncommon Outbound Kerberos Connection - Security | 🟡 medium | 50 | `T1558.003` | [`uncommon_outbound_kerberos_connection_security.yaml`](./uncommon_outbound_kerberos_connection_security.yaml) |
| User Added to Local Administrator Group | 🟡 medium | 50 | `T1078`, `T1098` | [`user_added_to_local_administrator_group.yaml`](./user_added_to_local_administrator_group.yaml) |
| Windows Access Token Manipulation SeDebugPrivilege | 🟡 medium | 36 | `T1134.002` | [`windows_access_token_manipulation_sedebugprivilege.yaml`](./windows_access_token_manipulation_sedebugprivilege.yaml) |
| Windows Create Local Account | 🟡 medium | 20 | `T1136.001` | [`windows_create_local_account.yaml`](./windows_create_local_account.yaml) |
| Windows Default Domain GPO Modification | 🟡 medium | 50 | `T1484.001` | [`windows_default_domain_gpo_modification.yaml`](./windows_default_domain_gpo_modification.yaml) |
| Windows Defender Exclusion List Modified | 🟡 medium | 50 | `T1685` | [`windows_defender_exclusion_list_modified.yaml`](./windows_defender_exclusion_list_modified.yaml) |
| Windows Defender Exclusion Registry Key - Write Access Requested | 🟡 medium | 50 | `T1685` | [`windows_defender_exclusion_registry_key_write_access_requested.yaml`](./windows_defender_exclusion_registry_key_write_access_requested.yaml) |
| Windows Network Access Suspicious desktop.ini Action | 🟡 medium | 50 | `T1547.009` | [`windows_network_access_suspicious_desktop_ini_action.yaml`](./windows_network_access_suspicious_desktop_ini_action.yaml) |
| Windows Pcap Drivers | 🟡 medium | 50 | `T1040` | [`windows_pcap_drivers.yaml`](./windows_pcap_drivers.yaml) |
| Windows Splashtop Software Usage | 🟡 medium | 50 | `T1219` | [`windows_splashtop_software_usage.yaml`](./windows_splashtop_software_usage.yaml) |
| WMI Persistence - Security | 🟡 medium | 50 | `T1546.003` | [`wmi_persistence_security.yaml`](./wmi_persistence_security.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
