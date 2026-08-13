# Sysmon Event ID 13 — Registry Value Set

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **266 rules**

Registry value writes — the main persistence, defence-evasion and configuration-tampering source.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🔴 critical 4 · 🟠 high 140 · 🟡 medium 111 · 🔵 low 11 |
| Status | experimental 205, production 61 |
| ATT&CK techniques | 68 distinct |
| Provenance | 206 Sigma-derived, 60 written for this repo |
| Event IDs queried | `13` (266) |

## Onboarding

Enable `RegistryEvent` in the Sysmon config. Filter to the hives and key paths your rules reference; unfiltered this is extremely high volume.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 266 |
| `data_win_eventdata_targetObject` | 265 |
| `data_win_eventdata_details` | 203 |
| `data_win_eventdata_image` | 45 |
| `data_win_eventdata_user` | 2 |

## Top ATT&CK techniques

[`T1112`](https://attack.mitre.org/techniques/T1112/) (86) · [`T1685`](https://attack.mitre.org/techniques/T1685/) (28) · [`T1547.001`](https://attack.mitre.org/techniques/T1547/001/) (23) · [`T1548.002`](https://attack.mitre.org/techniques/T1548/002/) (10) · [`T1546.015`](https://attack.mitre.org/techniques/T1546/015/) (6) · [`T1685.001`](https://attack.mitre.org/techniques/T1685/001/) (5) · [`T1137`](https://attack.mitre.org/techniques/T1137/) (5) · [`T1547.010`](https://attack.mitre.org/techniques/T1547/010/) (4)

## Rules (266)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| CVE-2021-31979 CVE-2021-33771 Exploits | 🔴 critical | 90 | `T1566`, `T1203` | [`cve_2021_31979_cve_2021_33771_exploits.yaml`](./cve_2021_31979_cve_2021_33771_exploits.yaml) |
| Windows Disable Memory Crash Dump | 🔴 critical | 96 | `T1485` | [`windows_disable_memory_crash_dump.yaml`](./windows_disable_memory_crash_dump.yaml) |
| Windows Modify Registry ValleyRAT C2 Config | 🔴 critical | 90 | `T1112` | [`windows_modify_registry_valleyrat_c2_config.yaml`](./windows_modify_registry_valleyrat_c2_config.yaml) |
| Windows Modify Registry ValleyRAT PWN Reg Entry | 🔴 critical | 90 | `T1112` | [`windows_modify_registry_valleyrat_pwn_reg_entry.yaml`](./windows_modify_registry_valleyrat_pwn_reg_entry.yaml) |
| Add Debugger Entry To Hangs Key For Persistence | 🟠 high | 75 | — | [`add_debugger_entry_to_hangs_key_for_persistence.yaml`](./add_debugger_entry_to_hangs_key_for_persistence.yaml) |
| AMSI Disabled via Registry Modification | 🟠 high | 75 | `T1685` | [`amsi_disabled_via_registry_modification.yaml`](./amsi_disabled_via_registry_modification.yaml) |
| Antivirus Filter Driver Disallowed On Dev Drive - Registry | 🟠 high | 75 | `T1685` | [`antivirus_filter_driver_disallowed_on_dev_drive_registry.yaml`](./antivirus_filter_driver_disallowed_on_dev_drive_registry.yaml) |
| Blackbyte Ransomware Registry | 🟠 high | 75 | `T1112` | [`blackbyte_ransomware_registry.yaml`](./blackbyte_ransomware_registry.yaml) |
| Blue Mockingbird - Registry | 🟠 high | 75 | `T1112`, `T1047` | [`blue_mockingbird_registry.yaml`](./blue_mockingbird_registry.yaml) |
| Bypass UAC Using DelegateExecute | 🟠 high | 75 | `T1548.002` | [`bypass_uac_using_delegateexecute.yaml`](./bypass_uac_using_delegateexecute.yaml) |
| Bypass UAC Using Event Viewer | 🟠 high | 75 | `T1547.010` | [`bypass_uac_using_event_viewer.yaml`](./bypass_uac_using_event_viewer.yaml) |
| Bypass UAC Using SilentCleanup Task | 🟠 high | 75 | `T1548.002` | [`bypass_uac_using_silentcleanup_task.yaml`](./bypass_uac_using_silentcleanup_task.yaml) |
| Change the Fax Dll | 🟠 high | 75 | `T1112` | [`change_the_fax_dll.yaml`](./change_the_fax_dll.yaml) |
| Change User Account Associated with the FAX Service | 🟠 high | 75 | `T1112` | [`change_user_account_associated_with_the_fax_service.yaml`](./change_user_account_associated_with_the_fax_service.yaml) |
| Change Winevt Channel Access Permission Via Registry | 🟠 high | 75 | `T1685.001` | [`change_winevt_channel_access_permission_via_registry.yaml`](./change_winevt_channel_access_permission_via_registry.yaml) |
| COM Hijack via Sdclt | 🟠 high | 75 | `T1546`, `T1548` | [`com_hijack_via_sdclt.yaml`](./com_hijack_via_sdclt.yaml) |
| COM Object Hijacking Via Modification Of Default System CLSID Default Value | 🟠 high | 75 | `T1546.015` | [`com_object_hijacking_via_modification_of_default_system_clsid_default_value.yaml`](./com_object_hijacking_via_modification_of_default_system_clsid_default_value.yaml) |
| Custom File Open Handler Executes PowerShell | 🟠 high | 75 | `T1202` | [`custom_file_open_handler_executes_powershell.yaml`](./custom_file_open_handler_executes_powershell.yaml) |
| CVE-2020-1048 Exploitation Attempt - Suspicious New Printer Ports - Registry | 🟠 high | 75 | `T1112` | [`cve_2020_1048_exploitation_attempt_suspicious_new_printer_ports_registry.yaml`](./cve_2020_1048_exploitation_attempt_suspicious_new_printer_ports_registry.yaml) |
| Default RDP Port Changed to Non Standard Port | 🟠 high | 75 | `T1547.010` | [`default_rdp_port_changed_to_non_standard_port.yaml`](./default_rdp_port_changed_to_non_standard_port.yaml) |
| DHCP Callout DLL Installation | 🟠 high | 75 | `T1574.001`, `T1112` | [`dhcp_callout_dll_installation.yaml`](./dhcp_callout_dll_installation.yaml) |
| Directory Service Restore Mode(DSRM) Registry Value Tampering | 🟠 high | 75 | `T1556` | [`directory_service_restore_mode_dsrm_registry_value_tampering.yaml`](./directory_service_restore_mode_dsrm_registry_value_tampering.yaml) |
| Disable Macro Runtime Scan Scope | 🟠 high | 75 | — | [`disable_macro_runtime_scan_scope.yaml`](./disable_macro_runtime_scan_scope.yaml) |
| Disable PUA Protection on Windows Defender | 🟠 high | 75 | `T1685` | [`disable_pua_protection_on_windows_defender.yaml`](./disable_pua_protection_on_windows_defender.yaml) |
| Disable Windows Defender Functionalities Via Registry Keys | 🟠 high | 75 | `T1685` | [`disable_windows_defender_functionalities_via_registry_keys.yaml`](./disable_windows_defender_functionalities_via_registry_keys.yaml) |
| Disable Windows Event Logging Via Registry | 🟠 high | 75 | `T1685.001` | [`disable_windows_event_logging_via_registry.yaml`](./disable_windows_event_logging_via_registry.yaml) |
| Disabled Windows Defender Eventlog | 🟠 high | 75 | `T1685` | [`disabled_windows_defender_eventlog.yaml`](./disabled_windows_defender_eventlog.yaml) |
| Driver Added To Disallowed Images In HVCI - Registry | 🟠 high | 75 | — | [`driver_added_to_disallowed_images_in_hvci_registry.yaml`](./driver_added_to_disallowed_images_in_hvci_registry.yaml) |
| Enable LM Hash Storage | 🟠 high | 75 | `T1112` | [`enable_lm_hash_storage.yaml`](./enable_lm_hash_storage.yaml) |
| ETW Logging Disabled In .NET Processes - Sysmon Registry | 🟠 high | 75 | `T1112`, `T1685` | [`etw_logging_disabled_in_net_processes_sysmon_registry.yaml`](./etw_logging_disabled_in_net_processes_sysmon_registry.yaml) |
| Execution DLL of Choice Using WAB.EXE | 🟠 high | 75 | `T1218` | [`execution_dll_of_choice_using_wab_exe.yaml`](./execution_dll_of_choice_using_wab_exe.yaml) |
| FileFix - Command Evidence in TypedPaths | 🟠 high | 75 | `T1204.004` | [`filefix_command_evidence_in_typedpaths.yaml`](./filefix_command_evidence_in_typedpaths.yaml) |
| Forest Blizzard APT - Custom Protocol Handler Creation | 🟠 high | 75 | `T1547.001` | [`forest_blizzard_apt_custom_protocol_handler_creation.yaml`](./forest_blizzard_apt_custom_protocol_handler_creation.yaml) |
| Forest Blizzard APT - Custom Protocol Handler DLL Registry Set | 🟠 high | 75 | `T1547.001` | [`forest_blizzard_apt_custom_protocol_handler_dll_registry_set.yaml`](./forest_blizzard_apt_custom_protocol_handler_dll_registry_set.yaml) |
| Hide Schedule Task Via Index Value Tamper | 🟠 high | 75 | `T1685` | [`hide_schedule_task_via_index_value_tamper.yaml`](./hide_schedule_task_via_index_value_tamper.yaml) |
| Hiding User Account Via SpecialAccounts Registry Key | 🟠 high | 75 | `T1564.002` | [`hiding_user_account_via_specialaccounts_registry_key.yaml`](./hiding_user_account_via_specialaccounts_registry_key.yaml) |
| Hypervisor Enforced Paging Translation Disabled | 🟠 high | 75 | `T1685` | [`hypervisor_enforced_paging_translation_disabled.yaml`](./hypervisor_enforced_paging_translation_disabled.yaml) |
| IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols | 🟠 high | 75 | — | [`ie_zonemap_setting_downgraded_to_mycomputer_zone_for_http_protocols.yaml`](./ie_zonemap_setting_downgraded_to_mycomputer_zone_for_http_protocols.yaml) |
| Kapeka Backdoor Autorun Persistence | 🟠 high | 75 | `T1547.001` | [`kapeka_backdoor_autorun_persistence.yaml`](./kapeka_backdoor_autorun_persistence.yaml) |
| Lolbas OneDriveStandaloneUpdater.exe Proxy Download | 🟠 high | 75 | `T1105` | [`lolbas_onedrivestandaloneupdater_exe_proxy_download.yaml`](./lolbas_onedrivestandaloneupdater_exe_proxy_download.yaml) |
| Lsass Full Dump Request Via DumpType Registry Settings | 🟠 high | 75 | `T1003.001` | [`lsass_full_dump_request_via_dumptype_registry_settings.yaml`](./lsass_full_dump_request_via_dumptype_registry_settings.yaml) |
| Macro Enabled In A Potentially Suspicious Document | 🟠 high | 75 | `T1112` | [`macro_enabled_in_a_potentially_suspicious_document.yaml`](./macro_enabled_in_a_potentially_suspicious_document.yaml) |
| Microsoft Office Protected View Disabled | 🟠 high | 75 | `T1685` | [`microsoft_office_protected_view_disabled.yaml`](./microsoft_office_protected_view_disabled.yaml) |
| Modify User Shell Folders Startup Value | 🟠 high | 75 | `T1547.001` | [`modify_user_shell_folders_startup_value.yaml`](./modify_user_shell_folders_startup_value.yaml) |
| NET NGenAssemblyUsageLog Registry Key Tamper | 🟠 high | 75 | `T1112` | [`net_ngenassemblyusagelog_registry_key_tamper.yaml`](./net_ngenassemblyusagelog_registry_key_tamper.yaml) |
| New DNS ServerLevelPluginDll Installed | 🟠 high | 75 | `T1574.001`, `T1112` | [`new_dns_serverlevelplugindll_installed.yaml`](./new_dns_serverlevelplugindll_installed.yaml) |
| New File Association Using Exefile | 🟠 high | 75 | — | [`new_file_association_using_exefile.yaml`](./new_file_association_using_exefile.yaml) |
| New Netsh Helper DLL Registered From A Suspicious Location | 🟠 high | 75 | `T1546.007` | [`new_netsh_helper_dll_registered_from_a_suspicious_location.yaml`](./new_netsh_helper_dll_registered_from_a_suspicious_location.yaml) |
| New RUN Key Pointing to Suspicious Folder | 🟠 high | 75 | `T1547.001` | [`new_run_key_pointing_to_suspicious_folder.yaml`](./new_run_key_pointing_to_suspicious_folder.yaml) |
| New TimeProviders Registered With Uncommon DLL Name | 🟠 high | 75 | `T1547.003` | [`new_timeproviders_registered_with_uncommon_dll_name.yaml`](./new_timeproviders_registered_with_uncommon_dll_name.yaml) |
| Office Macros Warning Disabled | 🟠 high | 75 | `T1112` | [`office_macros_warning_disabled.yaml`](./office_macros_warning_disabled.yaml) |
| Outlook EnableUnsafeClientMailRules Setting Enabled - Registry | 🟠 high | 75 | `T1112` | [`outlook_enableunsafeclientmailrules_setting_enabled_registry.yaml`](./outlook_enableunsafeclientmailrules_setting_enabled_registry.yaml) |
| Outlook Macro Execution Without Warning Setting Enabled | 🟠 high | 75 | `T1137`, `T1008`, `T1546` | [`outlook_macro_execution_without_warning_setting_enabled.yaml`](./outlook_macro_execution_without_warning_setting_enabled.yaml) |
| Persistence Via Hhctrl.ocx | 🟠 high | 75 | — | [`persistence_via_hhctrl_ocx.yaml`](./persistence_via_hhctrl_ocx.yaml) |
| Potential AMSI COM Server Hijacking | 🟠 high | 75 | `T1685` | [`potential_amsi_com_server_hijacking.yaml`](./potential_amsi_com_server_hijacking.yaml) |
| Potential Attachment Manager Settings Associations Tamper | 🟠 high | 75 | — | [`potential_attachment_manager_settings_associations_tamper.yaml`](./potential_attachment_manager_settings_associations_tamper.yaml) |
| Potential Attachment Manager Settings Attachments Tamper | 🟠 high | 75 | — | [`potential_attachment_manager_settings_attachments_tamper.yaml`](./potential_attachment_manager_settings_attachments_tamper.yaml) |
| Potential AutoLogger Sessions Tampering | 🟠 high | 75 | `T1685.001` | [`potential_autologger_sessions_tampering.yaml`](./potential_autologger_sessions_tampering.yaml) |
| Potential ClickFix Execution Pattern - Registry | 🟠 high | 75 | `T1204.001` | [`potential_clickfix_execution_pattern_registry.yaml`](./potential_clickfix_execution_pattern_registry.yaml) |
| Potential CobaltStrike Service Installations - Registry | 🟠 high | 75 | `T1021.002`, `T1543.003`, `T1569.002` | [`potential_cobaltstrike_service_installations_registry.yaml`](./potential_cobaltstrike_service_installations_registry.yaml) |
| Potential COLDSTEEL RAT Windows User Creation | 🟠 high | 75 | — | [`potential_coldsteel_rat_windows_user_creation.yaml`](./potential_coldsteel_rat_windows_user_creation.yaml) |
| Potential EventLog File Location Tampering | 🟠 high | 75 | `T1685.001` | [`potential_eventlog_file_location_tampering.yaml`](./potential_eventlog_file_location_tampering.yaml) |
| Potential KamiKakaBot Activity - Winlogon Shell Persistence | 🟠 high | 75 | `T1547.001` | [`potential_kamikakabot_activity_winlogon_shell_persistence.yaml`](./potential_kamikakabot_activity_winlogon_shell_persistence.yaml) |
| Potential Persistence Via App Paths Default Property | 🟠 high | 75 | `T1546.012` | [`potential_persistence_via_app_paths_default_property.yaml`](./potential_persistence_via_app_paths_default_property.yaml) |
| Potential Persistence Via AutodialDLL | 🟠 high | 75 | — | [`potential_persistence_via_autodialdll.yaml`](./potential_persistence_via_autodialdll.yaml) |
| Potential Persistence Via CHM Helper DLL | 🟠 high | 75 | — | [`potential_persistence_via_chm_helper_dll.yaml`](./potential_persistence_via_chm_helper_dll.yaml) |
| Potential Persistence Via DLLPathOverride | 🟠 high | 75 | — | [`potential_persistence_via_dllpathoverride.yaml`](./potential_persistence_via_dllpathoverride.yaml) |
| Potential Persistence Via Excel Add-in - Registry | 🟠 high | 75 | `T1137.006` | [`potential_persistence_via_excel_add_in_registry.yaml`](./potential_persistence_via_excel_add_in_registry.yaml) |
| Potential Persistence Via GlobalFlags | 🟠 high | 75 | `T1546.012` | [`potential_persistence_via_globalflags.yaml`](./potential_persistence_via_globalflags.yaml) |
| Potential Persistence Via LSA Extensions | 🟠 high | 75 | — | [`potential_persistence_via_lsa_extensions.yaml`](./potential_persistence_via_lsa_extensions.yaml) |
| Potential Persistence Via Mpnotify | 🟠 high | 75 | — | [`potential_persistence_via_mpnotify.yaml`](./potential_persistence_via_mpnotify.yaml) |
| Potential Persistence Via MyComputer Registry Keys | 🟠 high | 75 | — | [`potential_persistence_via_mycomputer_registry_keys.yaml`](./potential_persistence_via_mycomputer_registry_keys.yaml) |
| Potential Persistence Via Outlook Home Page | 🟠 high | 75 | `T1112` | [`potential_persistence_via_outlook_home_page.yaml`](./potential_persistence_via_outlook_home_page.yaml) |
| Potential Persistence Via Outlook LoadMacroProviderOnBoot Setting | 🟠 high | 75 | `T1137`, `T1008`, `T1546` | [`potential_persistence_via_outlook_loadmacroprovideronboot_setting.yaml`](./potential_persistence_via_outlook_loadmacroprovideronboot_setting.yaml) |
| Potential Persistence Via Outlook Today Page | 🟠 high | 75 | `T1112` | [`potential_persistence_via_outlook_today_page.yaml`](./potential_persistence_via_outlook_today_page.yaml) |
| Potential Persistence Via Shim Database In Uncommon Location | 🟠 high | 75 | `T1546.011` | [`potential_persistence_via_shim_database_in_uncommon_location.yaml`](./potential_persistence_via_shim_database_in_uncommon_location.yaml) |
| Potential Persistence Via TypedPaths | 🟠 high | 75 | — | [`potential_persistence_via_typedpaths.yaml`](./potential_persistence_via_typedpaths.yaml) |
| Potential Provisioning Registry Key Abuse For Binary Proxy Execution - REG | 🟠 high | 75 | `T1218` | [`potential_provisioning_registry_key_abuse_for_binary_proxy_execution_reg.yaml`](./potential_provisioning_registry_key_abuse_for_binary_proxy_execution_reg.yaml) |
| Potential PSFactoryBuffer COM Hijacking | 🟠 high | 75 | `T1546.015` | [`potential_psfactorybuffer_com_hijacking.yaml`](./potential_psfactorybuffer_com_hijacking.yaml) |
| Potential Ransomware Activity Using LegalNotice Message | 🟠 high | 75 | `T1491.001` | [`potential_ransomware_activity_using_legalnotice_message.yaml`](./potential_ransomware_activity_using_legalnotice_message.yaml) |
| Potential Registry Persistence Attempt Via Windows Telemetry | 🟠 high | 75 | `T1053.005` | [`potential_registry_persistence_attempt_via_windows_telemetry.yaml`](./potential_registry_persistence_attempt_via_windows_telemetry.yaml) |
| Potential Signing Bypass Via Windows Developer Features - Registry | 🟠 high | 75 | — | [`potential_signing_bypass_via_windows_developer_features_registry.yaml`](./potential_signing_bypass_via_windows_developer_features_registry.yaml) |
| Potential WerFault ReflectDebugger Registry Value Abuse | 🟠 high | 75 | `T1036.003` | [`potential_werfault_reflectdebugger_registry_value_abuse.yaml`](./potential_werfault_reflectdebugger_registry_value_abuse.yaml) |
| Potentially Suspicious Command Executed Via Run Dialog Box - Registry | 🟠 high | 75 | `T1059.001` | [`potentially_suspicious_command_executed_via_run_dialog_box_registry.yaml`](./potentially_suspicious_command_executed_via_run_dialog_box_registry.yaml) |
| Potentially Suspicious ODBC Driver Registered | 🟠 high | 75 | `T1003` | [`potentially_suspicious_odbc_driver_registered.yaml`](./potentially_suspicious_odbc_driver_registered.yaml) |
| PowerShell as a Service in Registry | 🟠 high | 75 | `T1569.002` | [`powershell_as_a_service_in_registry.yaml`](./powershell_as_a_service_in_registry.yaml) |
| Powershell Executed As A Service | 🟠 high | 72 | `T1569.002` | [`powershell_executed_as_a_service.yaml`](./powershell_executed_as_a_service.yaml) |
| PowerShell Logging Disabled Via Registry Key Tampering | 🟠 high | 75 | `T1564.001`, `T1112` | [`powershell_logging_disabled_via_registry_key_tampering.yaml`](./powershell_logging_disabled_via_registry_key_tampering.yaml) |
| Python Function Execution Security Warning Disabled In Excel - Registry | 🟠 high | 75 | `T1685` | [`python_function_execution_security_warning_disabled_in_excel_registry.yaml`](./python_function_execution_security_warning_disabled_in_excel_registry.yaml) |
| RDP Sensitive Settings Changed | 🟠 high | 75 | `T1112` | [`rdp_sensitive_settings_changed.yaml`](./rdp_sensitive_settings_changed.yaml) |
| Registry Disable System Restore | 🟠 high | 75 | `T1490` | [`registry_disable_system_restore.yaml`](./registry_disable_system_restore.yaml) |
| Registry Modification for OCI DLL Redirection | 🟠 high | 75 | `T1112`, `T1574.001` | [`registry_modification_for_oci_dll_redirection.yaml`](./registry_modification_for_oci_dll_redirection.yaml) |
| Registry Persistence via Explorer Run Key | 🟠 high | 75 | `T1547.001` | [`registry_persistence_via_explorer_run_key.yaml`](./registry_persistence_via_explorer_run_key.yaml) |
| Registry Persistence via Service in Safe Mode | 🟠 high | 75 | `T1564.001` | [`registry_persistence_via_service_in_safe_mode.yaml`](./registry_persistence_via_service_in_safe_mode.yaml) |
| RestrictedAdminMode Registry Value Tampering | 🟠 high | 75 | `T1112` | [`restrictedadminmode_registry_value_tampering.yaml`](./restrictedadminmode_registry_value_tampering.yaml) |
| Scheduled TaskCache Change by Uncommon Program | 🟠 high | 75 | `T1053`, `T1053.005` | [`scheduled_taskcache_change_by_uncommon_program.yaml`](./scheduled_taskcache_change_by_uncommon_program.yaml) |
| Security Event Logging Disabled via MiniNt Registry Key - Registry Set | 🟠 high | 75 | `T1685.001`, `T1112` | [`security_event_logging_disabled_via_minint_registry_key_registry_set.yaml`](./security_event_logging_disabled_via_minint_registry_key_registry_set.yaml) |
| Service Binary in Suspicious Folder | 🟠 high | 75 | `T1112` | [`service_binary_in_suspicious_folder.yaml`](./service_binary_in_suspicious_folder.yaml) |
| Small Sieve Malware Registry Persistence | 🟠 high | 75 | — | [`small_sieve_malware_registry_persistence.yaml`](./small_sieve_malware_registry_persistence.yaml) |
| Suspicious Application Allowed Through Exploit Guard | 🟠 high | 75 | `T1685` | [`suspicious_application_allowed_through_exploit_guard.yaml`](./suspicious_application_allowed_through_exploit_guard.yaml) |
| Suspicious Environment Variable Has Been Registered | 🟠 high | 75 | — | [`suspicious_environment_variable_has_been_registered.yaml`](./suspicious_environment_variable_has_been_registered.yaml) |
| Suspicious Execution Of Renamed Sysinternals Tools - Registry | 🟠 high | 75 | `T1588.002` | [`suspicious_execution_of_renamed_sysinternals_tools_registry.yaml`](./suspicious_execution_of_renamed_sysinternals_tools_registry.yaml) |
| Suspicious Path In Keyboard Layout IME File Registry Value | 🟠 high | 75 | `T1685` | [`suspicious_path_in_keyboard_layout_ime_file_registry_value.yaml`](./suspicious_path_in_keyboard_layout_ime_file_registry_value.yaml) |
| Suspicious Printer Driver Empty Manufacturer | 🟠 high | 75 | `T1574` | [`suspicious_printer_driver_empty_manufacturer.yaml`](./suspicious_printer_driver_empty_manufacturer.yaml) |
| Suspicious Shim Database Patching Activity | 🟠 high | 75 | `T1546.011` | [`suspicious_shim_database_patching_activity.yaml`](./suspicious_shim_database_patching_activity.yaml) |
| Suspicious Space Characters in RunMRU Registry Path - ClickFix | 🟠 high | 75 | `T1204.004`, `T1027.010` | [`suspicious_space_characters_in_runmru_registry_path_clickfix.yaml`](./suspicious_space_characters_in_runmru_registry_path_clickfix.yaml) |
| Suspicious Space Characters in TypedPaths Registry Path - FileFix | 🟠 high | 75 | `T1204.004`, `T1027.010` | [`suspicious_space_characters_in_typedpaths_registry_path_filefix.yaml`](./suspicious_space_characters_in_typedpaths_registry_path_filefix.yaml) |
| Sysmon Driver Altitude Change | 🟠 high | 75 | `T1685` | [`sysmon_driver_altitude_change.yaml`](./sysmon_driver_altitude_change.yaml) |
| Tamper With Sophos AV Registry Keys | 🟠 high | 75 | `T1685` | [`tamper_with_sophos_av_registry_keys.yaml`](./tamper_with_sophos_av_registry_keys.yaml) |
| Trust Access Disable For VBApplications | 🟠 high | 75 | `T1112` | [`trust_access_disable_for_vbapplications.yaml`](./trust_access_disable_for_vbapplications.yaml) |
| UAC Bypass Abusing Winsat Path Parsing - Registry | 🟠 high | 75 | `T1548.002` | [`uac_bypass_abusing_winsat_path_parsing_registry.yaml`](./uac_bypass_abusing_winsat_path_parsing_registry.yaml) |
| UAC Bypass Using Windows Media Player - Registry | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_windows_media_player_registry.yaml`](./uac_bypass_using_windows_media_player_registry.yaml) |
| UAC Bypass via Event Viewer | 🟠 high | 75 | `T1548.002` | [`uac_bypass_via_event_viewer.yaml`](./uac_bypass_via_event_viewer.yaml) |
| UAC Bypass via Sdclt | 🟠 high | 75 | `T1548.002` | [`uac_bypass_via_sdclt.yaml`](./uac_bypass_via_sdclt.yaml) |
| Uncommon Extension In Keyboard Layout IME File Registry Value | 🟠 high | 75 | `T1685` | [`uncommon_extension_in_keyboard_layout_ime_file_registry_value.yaml`](./uncommon_extension_in_keyboard_layout_ime_file_registry_value.yaml) |
| Uncommon Microsoft Office Trusted Location Added | 🟠 high | 75 | `T1112` | [`uncommon_microsoft_office_trusted_location_added.yaml`](./uncommon_microsoft_office_trusted_location_added.yaml) |
| Usage of Renamed Sysinternals Tools - RegistrySet | 🟠 high | 75 | `T1588.002` | [`usage_of_renamed_sysinternals_tools_registryset.yaml`](./usage_of_renamed_sysinternals_tools_registryset.yaml) |
| VBScript Payload Stored in Registry | 🟠 high | 75 | `T1547.001` | [`vbscript_payload_stored_in_registry.yaml`](./vbscript_payload_stored_in_registry.yaml) |
| Wdigest Enable UseLogonCredential | 🟠 high | 75 | `T1112` | [`wdigest_enable_uselogoncredential.yaml`](./wdigest_enable_uselogoncredential.yaml) |
| Windows Audit Policy Auditing Option Modified - Registry | 🟠 high | 64 | `T1547.014` | [`windows_audit_policy_auditing_option_modified_registry.yaml`](./windows_audit_policy_auditing_option_modified_registry.yaml) |
| Windows Autoruns Run Key Value Set By Suspicious Process | 🟠 high | 60 | `T1547.001` | [`windows_autoruns_run_key_value_set_by_suspicious_process.yaml`](./windows_autoruns_run_key_value_set_by_suspicious_process.yaml) |
| Windows Autostart Execution LSASS Driver Registry Modification | 🟠 high | 49 | `T1547.008` | [`windows_autostart_execution_lsass_driver_registry_modification.yaml`](./windows_autostart_execution_lsass_driver_registry_modification.yaml) |
| Windows Credential Guard Disabled - Registry | 🟠 high | 75 | `T1685` | [`windows_credential_guard_disabled_registry.yaml`](./windows_credential_guard_disabled_registry.yaml) |
| Windows Defender Service Disabled - Registry | 🟠 high | 75 | `T1685` | [`windows_defender_service_disabled_registry.yaml`](./windows_defender_service_disabled_registry.yaml) |
| Windows Disable Change Password Through Registry | 🟠 high | 50 | `T1112` | [`windows_disable_change_password_through_registry.yaml`](./windows_disable_change_password_through_registry.yaml) |
| Windows Disable Lock Workstation Feature Through Registry | 🟠 high | 50 | `T1112` | [`windows_disable_lock_workstation_feature_through_registry.yaml`](./windows_disable_lock_workstation_feature_through_registry.yaml) |
| Windows Disable LogOff Button Through Registry | 🟠 high | 50 | `T1112` | [`windows_disable_logoff_button_through_registry.yaml`](./windows_disable_logoff_button_through_registry.yaml) |
| Windows Enable Win32 ScheduledJob via Registry | 🟠 high | 65 | `T1053.005` | [`windows_enable_win32_scheduledjob_via_registry.yaml`](./windows_enable_win32_scheduledjob_via_registry.yaml) |
| Windows Event Log Access Tampering Via Registry | 🟠 high | 75 | `T1547.001`, `T1112` | [`windows_event_log_access_tampering_via_registry.yaml`](./windows_event_log_access_tampering_via_registry.yaml) |
| Windows Hide Notification Features Through Registry | 🟠 high | 75 | `T1112` | [`windows_hide_notification_features_through_registry.yaml`](./windows_hide_notification_features_through_registry.yaml) |
| Windows Hypervisor Enforced Code Integrity Disabled | 🟠 high | 75 | `T1685` | [`windows_hypervisor_enforced_code_integrity_disabled.yaml`](./windows_hypervisor_enforced_code_integrity_disabled.yaml) |
| Windows InProcServer32 New Outlook Form | 🟠 high | 80 | `T1566`, `T1112` | [`windows_inprocserver32_new_outlook_form.yaml`](./windows_inprocserver32_new_outlook_form.yaml) |
| Windows LSA Secrets NoLMHash Registry | 🟠 high | 64 | `T1003.004` | [`windows_lsa_secrets_nolmhash_registry.yaml`](./windows_lsa_secrets_nolmhash_registry.yaml) |
| Windows Modify Registry Configure BitLocker | 🟠 high | 64 | `T1112` | [`windows_modify_registry_configure_bitlocker.yaml`](./windows_modify_registry_configure_bitlocker.yaml) |
| Windows Modify Registry Default Icon Setting | 🟠 high | 80 | `T1112` | [`windows_modify_registry_default_icon_setting.yaml`](./windows_modify_registry_default_icon_setting.yaml) |
| Windows Modify Registry Disable Restricted Admin | 🟠 high | 64 | `T1112` | [`windows_modify_registry_disable_restricted_admin.yaml`](./windows_modify_registry_disable_restricted_admin.yaml) |
| Windows Modify Registry EnableLinkedConnections | 🟠 high | 64 | `T1112` | [`windows_modify_registry_enablelinkedconnections.yaml`](./windows_modify_registry_enablelinkedconnections.yaml) |
| Windows Monitor Registry Keys for Print Monitors | 🟠 high | 64 | `T1547.010` | [`monitor_registry_keys_for_print_monitors.yaml`](./monitor_registry_keys_for_print_monitors.yaml) |
| Windows Mshta Execution In Registry | 🟠 high | 72 | `T1218.005` | [`windows_mshta_execution_in_registry.yaml`](./windows_mshta_execution_in_registry.yaml) |
| Windows New Custom Security Descriptor Set On EventLog Channel | 🟠 high | 64 | `T1562.002` | [`windows_new_custom_security_descriptor_set_on_eventlog_channel.yaml`](./windows_new_custom_security_descriptor_set_on_eventlog_channel.yaml) |
| Windows Print Processor Registry Autostart | 🟠 high | 72 | `T1547.012` | [`print_processor_registry_autostart.yaml`](./print_processor_registry_autostart.yaml) |
| Windows Privilege Elevation - LSA Secrets Leak | 🟠 high | 75 | `T1003.004` | [`windows_privilege_elevation_lsa_secrets_leak.yaml`](./windows_privilege_elevation_lsa_secrets_leak.yaml) |
| Windows Vulnerable Driver Blocklist Disabled | 🟠 high | 75 | `T1685` | [`windows_vulnerable_driver_blocklist_disabled.yaml`](./windows_vulnerable_driver_blocklist_disabled.yaml) |
| Winlogon Notify Key Logon Persistence | 🟠 high | 75 | `T1547.004` | [`winlogon_notify_key_logon_persistence.yaml`](./winlogon_notify_key_logon_persistence.yaml) |
| Activate Suppression of Windows Security Center Notifications | 🟡 medium | 50 | `T1112` | [`activate_suppression_of_windows_security_center_notifications.yaml`](./activate_suppression_of_windows_security_center_notifications.yaml) |
| Add Debugger Entry To AeDebug For Persistence | 🟡 medium | 50 | — | [`add_debugger_entry_to_aedebug_for_persistence.yaml`](./add_debugger_entry_to_aedebug_for_persistence.yaml) |
| Add DisallowRun Execution to Registry | 🟡 medium | 50 | `T1112` | [`add_disallowrun_execution_to_registry.yaml`](./add_disallowrun_execution_to_registry.yaml) |
| Add Port Monitor Persistence in Registry | 🟡 medium | 50 | `T1547.010` | [`add_port_monitor_persistence_in_registry.yaml`](./add_port_monitor_persistence_in_registry.yaml) |
| Allow RDP Remote Assistance Feature | 🟡 medium | 50 | `T1112` | [`allow_rdp_remote_assistance_feature.yaml`](./allow_rdp_remote_assistance_feature.yaml) |
| Classes Autorun Keys Modification | 🟡 medium | 50 | `T1547.001` | [`classes_autorun_keys_modification.yaml`](./classes_autorun_keys_modification.yaml) |
| ClickOnce Trust Prompt Tampering | 🟡 medium | 50 | `T1112` | [`clickonce_trust_prompt_tampering.yaml`](./clickonce_trust_prompt_tampering.yaml) |
| COM Hijacking via TreatAs | 🟡 medium | 50 | `T1546.015` | [`com_hijacking_via_treatas.yaml`](./com_hijacking_via_treatas.yaml) |
| Common Autorun Keys Modification | 🟡 medium | 50 | `T1547.001` | [`common_autorun_keys_modification.yaml`](./common_autorun_keys_modification.yaml) |
| CrashControl CrashDump Disabled | 🟡 medium | 50 | `T1564`, `T1112` | [`crashcontrol_crashdump_disabled.yaml`](./crashcontrol_crashdump_disabled.yaml) |
| CurrentControlSet Autorun Keys Modification | 🟡 medium | 50 | `T1547.001` | [`currentcontrolset_autorun_keys_modification.yaml`](./currentcontrolset_autorun_keys_modification.yaml) |
| CurrentVersion NT Autorun Keys Modification | 🟡 medium | 50 | `T1547.001` | [`currentversion_nt_autorun_keys_modification.yaml`](./currentversion_nt_autorun_keys_modification.yaml) |
| Disable Administrative Share Creation at Startup | 🟡 medium | 50 | `T1070.005` | [`disable_administrative_share_creation_at_startup.yaml`](./disable_administrative_share_creation_at_startup.yaml) |
| Disable Exploit Guard Network Protection on Windows Defender | 🟡 medium | 50 | `T1685` | [`disable_exploit_guard_network_protection_on_windows_defender.yaml`](./disable_exploit_guard_network_protection_on_windows_defender.yaml) |
| Disable Internal Tools or Feature in Registry | 🟡 medium | 50 | `T1112` | [`disable_internal_tools_or_feature_in_registry.yaml`](./disable_internal_tools_or_feature_in_registry.yaml) |
| Disable Microsoft Defender Firewall via Registry | 🟡 medium | 50 | `T1686.003` | [`disable_microsoft_defender_firewall_via_registry.yaml`](./disable_microsoft_defender_firewall_via_registry.yaml) |
| Disable Privacy Settings Experience in Registry | 🟡 medium | 50 | `T1685` | [`disable_privacy_settings_experience_in_registry.yaml`](./disable_privacy_settings_experience_in_registry.yaml) |
| Disable Tamper Protection on Windows Defender | 🟡 medium | 50 | `T1685` | [`disable_tamper_protection_on_windows_defender.yaml`](./disable_tamper_protection_on_windows_defender.yaml) |
| Disable Windows Firewall by Registry | 🟡 medium | 50 | `T1686.003` | [`disable_windows_firewall_by_registry.yaml`](./disable_windows_firewall_by_registry.yaml) |
| Disable Windows Security Center Notifications | 🟡 medium | 50 | `T1112` | [`disable_windows_security_center_notifications.yaml`](./disable_windows_security_center_notifications.yaml) |
| Displaying Hidden Files Feature Disabled | 🟡 medium | 50 | `T1564.001` | [`displaying_hidden_files_feature_disabled.yaml`](./displaying_hidden_files_feature_disabled.yaml) |
| DNS-over-HTTPS Enabled by Registry | 🟡 medium | 50 | `T1140`, `T1112` | [`dns_over_https_enabled_by_registry.yaml`](./dns_over_https_enabled_by_registry.yaml) |
| Enable Local Manifest Installation With Winget | 🟡 medium | 50 | — | [`enable_local_manifest_installation_with_winget.yaml`](./enable_local_manifest_installation_with_winget.yaml) |
| Enable Microsoft Dynamic Data Exchange | 🟡 medium | 50 | `T1559.002` | [`enable_microsoft_dynamic_data_exchange.yaml`](./enable_microsoft_dynamic_data_exchange.yaml) |
| Enable Remote Connection Between Anonymous Computer - AllowAnonymousCallback | 🟡 medium | 50 | `T1685` | [`enable_remote_connection_between_anonymous_computer_allowanonymouscallback.yaml`](./enable_remote_connection_between_anonymous_computer_allowanonymouscallback.yaml) |
| Enabling COR Profiler Environment Variables | 🟡 medium | 50 | `T1574.012` | [`enabling_cor_profiler_environment_variables.yaml`](./enabling_cor_profiler_environment_variables.yaml) |
| IE Change Domain Zone | 🟡 medium | 50 | `T1137` | [`ie_change_domain_zone.yaml`](./ie_change_domain_zone.yaml) |
| Internet Explorer Autorun Keys Modification | 🟡 medium | 50 | `T1547.001` | [`internet_explorer_autorun_keys_modification.yaml`](./internet_explorer_autorun_keys_modification.yaml) |
| Internet Explorer DisableFirstRunCustomize Enabled | 🟡 medium | 50 | — | [`internet_explorer_disablefirstruncustomize_enabled.yaml`](./internet_explorer_disablefirstruncustomize_enabled.yaml) |
| Kapeka Backdoor Configuration Persistence | 🟡 medium | 50 | `T1553.003` | [`kapeka_backdoor_configuration_persistence.yaml`](./kapeka_backdoor_configuration_persistence.yaml) |
| New BgInfo.EXE Custom DB Path Registry Configuration | 🟡 medium | 50 | `T1112` | [`new_bginfo_exe_custom_db_path_registry_configuration.yaml`](./new_bginfo_exe_custom_db_path_registry_configuration.yaml) |
| New BgInfo.EXE Custom VBScript Registry Configuration | 🟡 medium | 50 | `T1112` | [`new_bginfo_exe_custom_vbscript_registry_configuration.yaml`](./new_bginfo_exe_custom_vbscript_registry_configuration.yaml) |
| New BgInfo.EXE Custom WMI Query Registry Configuration | 🟡 medium | 50 | `T1112` | [`new_bginfo_exe_custom_wmi_query_registry_configuration.yaml`](./new_bginfo_exe_custom_wmi_query_registry_configuration.yaml) |
| New Root or CA or AuthRoot Certificate to Store | 🟡 medium | 50 | `T1490` | [`new_root_or_ca_or_authroot_certificate_to_store.yaml`](./new_root_or_ca_or_authroot_certificate_to_store.yaml) |
| Office Autorun Keys Modification | 🟡 medium | 50 | `T1547.001` | [`office_autorun_keys_modification.yaml`](./office_autorun_keys_modification.yaml) |
| Old TLS1.0/TLS1.1 Protocol Version Enabled | 🟡 medium | 50 | — | [`old_tls1_0_tls1_1_protocol_version_enabled.yaml`](./old_tls1_0_tls1_1_protocol_version_enabled.yaml) |
| Outlook Security Settings Updated - Registry | 🟡 medium | 50 | `T1137` | [`outlook_security_settings_updated_registry.yaml`](./outlook_security_settings_updated_registry.yaml) |
| Periodic Backup For System Registry Hives Enabled | 🟡 medium | 50 | `T1113` | [`periodic_backup_for_system_registry_hives_enabled.yaml`](./periodic_backup_for_system_registry_hives_enabled.yaml) |
| Persistence Via Disk Cleanup Handler - Autorun | 🟡 medium | 50 | — | [`persistence_via_disk_cleanup_handler_autorun.yaml`](./persistence_via_disk_cleanup_handler_autorun.yaml) |
| Persistence Via New SIP Provider | 🟡 medium | 50 | `T1553.003` | [`persistence_via_new_sip_provider.yaml`](./persistence_via_new_sip_provider.yaml) |
| Potential COM Object Hijacking Via TreatAs Subkey - Registry | 🟡 medium | 50 | `T1546.015` | [`potential_com_object_hijacking_via_treatas_subkey_registry.yaml`](./potential_com_object_hijacking_via_treatas_subkey_registry.yaml) |
| Potential Credential Dumping Attempt Using New NetworkProvider - REG | 🟡 medium | 50 | `T1003` | [`potential_credential_dumping_attempt_using_new_networkprovider_reg.yaml`](./potential_credential_dumping_attempt_using_new_networkprovider_reg.yaml) |
| Potential Encrypted Registry Blob Related To SNAKE Malware | 🟡 medium | 50 | — | [`potential_encrypted_registry_blob_related_to_snake_malware.yaml`](./potential_encrypted_registry_blob_related_to_snake_malware.yaml) |
| Potential PendingFileRenameOperations Tampering | 🟡 medium | 50 | `T1036.003` | [`potential_pendingfilerenameoperations_tampering.yaml`](./potential_pendingfilerenameoperations_tampering.yaml) |
| Potential Persistence Using DebugPath | 🟡 medium | 50 | `T1546.015` | [`potential_persistence_using_debugpath.yaml`](./potential_persistence_using_debugpath.yaml) |
| Potential Persistence Via AppCompat RegisterAppRestart Layer | 🟡 medium | 50 | `T1546.011` | [`potential_persistence_via_appcompat_registerapprestart_layer.yaml`](./potential_persistence_via_appcompat_registerapprestart_layer.yaml) |
| Potential Persistence Via Custom Protocol Handler | 🟡 medium | 50 | `T1112` | [`potential_persistence_via_custom_protocol_handler.yaml`](./potential_persistence_via_custom_protocol_handler.yaml) |
| Potential Persistence Via Event Viewer Events.asp | 🟡 medium | 50 | `T1112` | [`potential_persistence_via_event_viewer_events_asp.yaml`](./potential_persistence_via_event_viewer_events_asp.yaml) |
| Potential Persistence Via Logon Scripts - Registry | 🟡 medium | 50 | `T1037.001` | [`potential_persistence_via_logon_scripts_registry.yaml`](./potential_persistence_via_logon_scripts_registry.yaml) |
| Potential Persistence Via Netsh Helper DLL - Registry | 🟡 medium | 50 | `T1546.007` | [`potential_persistence_via_netsh_helper_dll_registry.yaml`](./potential_persistence_via_netsh_helper_dll_registry.yaml) |
| Potential Persistence Via New AMSI Providers - Registry | 🟡 medium | 50 | — | [`potential_persistence_via_new_amsi_providers_registry.yaml`](./potential_persistence_via_new_amsi_providers_registry.yaml) |
| Potential Persistence Via Scrobj.dll COM Hijacking | 🟡 medium | 50 | `T1546.015` | [`potential_persistence_via_scrobj_dll_com_hijacking.yaml`](./potential_persistence_via_scrobj_dll_com_hijacking.yaml) |
| Potential Persistence Via Shim Database Modification | 🟡 medium | 50 | `T1546.011` | [`potential_persistence_via_shim_database_modification.yaml`](./potential_persistence_via_shim_database_modification.yaml) |
| Potential Persistence Via Visual Studio Tools for Office | 🟡 medium | 50 | `T1137.006` | [`potential_persistence_via_visual_studio_tools_for_office.yaml`](./potential_persistence_via_visual_studio_tools_for_office.yaml) |
| Potential PowerShell Execution Policy Tampering | 🟡 medium | 50 | — | [`potential_powershell_execution_policy_tampering.yaml`](./potential_powershell_execution_policy_tampering.yaml) |
| Potential Registry Persistence Attempt Via DbgManagedDebugger | 🟡 medium | 50 | `T1574` | [`potential_registry_persistence_attempt_via_dbgmanageddebugger.yaml`](./potential_registry_persistence_attempt_via_dbgmanageddebugger.yaml) |
| Potential SentinelOne Shell Context Menu Scan Command Tampering | 🟡 medium | 50 | — | [`potential_sentinelone_shell_context_menu_scan_command_tampering.yaml`](./potential_sentinelone_shell_context_menu_scan_command_tampering.yaml) |
| Potentially Suspicious Desktop Background Change Via Registry | 🟡 medium | 50 | `T1112`, `T1491.001` | [`potentially_suspicious_desktop_background_change_via_registry.yaml`](./potentially_suspicious_desktop_background_change_via_registry.yaml) |
| PUA - Sysinternals Tools Execution - Registry | 🟡 medium | 50 | `T1588.002` | [`pua_sysinternals_tools_execution_registry.yaml`](./pua_sysinternals_tools_execution_registry.yaml) |
| RDP Sensitive Settings Changed to Zero | 🟡 medium | 50 | `T1112` | [`rdp_sensitive_settings_changed_to_zero.yaml`](./rdp_sensitive_settings_changed_to_zero.yaml) |
| Register New IFiltre For Persistence | 🟡 medium | 50 | — | [`register_new_ifiltre_for_persistence.yaml`](./register_new_ifiltre_for_persistence.yaml) |
| Registry Explorer Policy Modification | 🟡 medium | 50 | `T1112` | [`registry_explorer_policy_modification.yaml`](./registry_explorer_policy_modification.yaml) |
| Registry Hide Function from User | 🟡 medium | 50 | `T1112` | [`registry_hide_function_from_user.yaml`](./registry_hide_function_from_user.yaml) |
| Registry Modification to Hidden File Extension | 🟡 medium | 50 | `T1137` | [`registry_modification_to_hidden_file_extension.yaml`](./registry_modification_to_hidden_file_extension.yaml) |
| ScreenSaver Registry Key Set | 🟡 medium | 50 | `T1218.011` | [`screensaver_registry_key_set.yaml`](./screensaver_registry_key_set.yaml) |
| Scripted Diagnostics Turn Off Check Enabled - Registry | 🟡 medium | 50 | `T1685` | [`scripted_diagnostics_turn_off_check_enabled_registry.yaml`](./scripted_diagnostics_turn_off_check_enabled_registry.yaml) |
| ServiceDll Hijack | 🟡 medium | 50 | `T1543.003` | [`servicedll_hijack.yaml`](./servicedll_hijack.yaml) |
| Session Manager Autorun Keys Modification | 🟡 medium | 50 | `T1547.001`, `T1546.009` | [`session_manager_autorun_keys_modification.yaml`](./session_manager_autorun_keys_modification.yaml) |
| Suspicious Keyboard Layout Load | 🟡 medium | 50 | `T1588.002` | [`suspicious_keyboard_layout_load.yaml`](./suspicious_keyboard_layout_load.yaml) |
| Suspicious PowerShell In Registry Run Keys | 🟡 medium | 50 | `T1547.001` | [`suspicious_powershell_in_registry_run_keys.yaml`](./suspicious_powershell_in_registry_run_keys.yaml) |
| Suspicious Service Installed | 🟡 medium | 50 | `T1685` | [`suspicious_service_installed.yaml`](./suspicious_service_installed.yaml) |
| Suspicious Set Value of MSDT in Registry (CVE-2022-30190) | 🟡 medium | 50 | `T1221` | [`suspicious_set_value_of_msdt_in_registry_cve_2022_30190.yaml`](./suspicious_set_value_of_msdt_in_registry_cve_2022_30190.yaml) |
| Suspicious Shell Open Command Registry Modification | 🟡 medium | 50 | `T1548.002`, `T1546.001` | [`suspicious_shell_open_command_registry_modification.yaml`](./suspicious_shell_open_command_registry_modification.yaml) |
| System Scripts Autorun Keys Modification | 🟡 medium | 50 | `T1547.001` | [`system_scripts_autorun_keys_modification.yaml`](./system_scripts_autorun_keys_modification.yaml) |
| UAC Disabled | 🟡 medium | 50 | `T1548.002` | [`uac_disabled.yaml`](./uac_disabled.yaml) |
| UAC Notification Disabled | 🟡 medium | 50 | `T1548.002` | [`uac_notification_disabled.yaml`](./uac_notification_disabled.yaml) |
| UAC Secure Desktop Prompt Disabled | 🟡 medium | 50 | `T1548.002` | [`uac_secure_desktop_prompt_disabled.yaml`](./uac_secure_desktop_prompt_disabled.yaml) |
| WFP Filter Added via Registry | 🟡 medium | 50 | `T1685`, `T1569.002` | [`wfp_filter_added_via_registry.yaml`](./wfp_filter_added_via_registry.yaml) |
| Windows Chrome Auto-Update Disabled via Registry | 🟡 medium | 36 | `T1185` | [`windows_chrome_auto_update_disabled_via_registry.yaml`](./windows_chrome_auto_update_disabled_via_registry.yaml) |
| Windows Chrome Extension Allowed Registry Modification | 🟡 medium | 30 | `T1185` | [`windows_chrome_extension_allowed_registry_modification.yaml`](./windows_chrome_extension_allowed_registry_modification.yaml) |
| Windows Defender Exclusions Added - Registry | 🟡 medium | 50 | `T1685` | [`windows_defender_exclusions_added_registry.yaml`](./windows_defender_exclusions_added_registry.yaml) |
| Windows Disable Notification Center | 🟡 medium | 40 | `T1112` | [`windows_disable_notification_center.yaml`](./windows_disable_notification_center.yaml) |
| Windows Disable Shutdown Button Through Registry | 🟡 medium | 49 | `T1112` | [`windows_disable_shutdown_button_through_registry.yaml`](./windows_disable_shutdown_button_through_registry.yaml) |
| Windows Disable Windows Group Policy Features Through Registry | 🟡 medium | 49 | `T1112` | [`windows_disable_windows_group_policy_features_through_registry.yaml`](./windows_disable_windows_group_policy_features_through_registry.yaml) |
| Windows DisableAntiSpyware Registry | 🟡 medium | 24 | `T1562.001` | [`windows_disableantispyware_registry.yaml`](./windows_disableantispyware_registry.yaml) |
| Windows Modify Registry AuthenticationLevelOverride | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_authenticationleveloverride.yaml`](./windows_modify_registry_authenticationleveloverride.yaml) |
| Windows Modify Registry Auto Minor Updates | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_auto_minor_updates.yaml`](./windows_modify_registry_auto_minor_updates.yaml) |
| Windows Modify Registry Auto Update Notif | 🟡 medium | 65 | `T1112` | [`windows_modify_registry_auto_update_notif.yaml`](./windows_modify_registry_auto_update_notif.yaml) |
| Windows Modify Registry Disable Toast Notifications | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_disable_toast_notifications.yaml`](./windows_modify_registry_disable_toast_notifications.yaml) |
| Windows Modify Registry Disable Win Defender Raw Write Notif | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_disable_win_defender_raw_write_notif.yaml`](./windows_modify_registry_disable_win_defender_raw_write_notif.yaml) |
| Windows Modify Registry Disable WinDefender Notifications | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_disable_windefender_notifications.yaml`](./windows_modify_registry_disable_windefender_notifications.yaml) |
| Windows Modify Registry Disable Windows Security Center Notif | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_disable_windows_security_center_notif.yaml`](./windows_modify_registry_disable_windows_security_center_notif.yaml) |
| Windows Modify Registry DisableRemoteDesktopAntiAlias | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_disableremotedesktopantialias.yaml`](./windows_modify_registry_disableremotedesktopantialias.yaml) |
| Windows Modify Registry DisableSecuritySettings | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_disablesecuritysettings.yaml`](./windows_modify_registry_disablesecuritysettings.yaml) |
| Windows Modify Registry Disabling WER Settings | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_disabling_wer_settings.yaml`](./windows_modify_registry_disabling_wer_settings.yaml) |
| Windows Modify Registry DoNotConnectToWindowsUpdateInternetLocations | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_do_not_connect_to_win_update.yaml`](./windows_modify_registry_do_not_connect_to_win_update.yaml) |
| Windows Modify Registry No Auto Update | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_no_auto_update.yaml`](./windows_modify_registry_no_auto_update.yaml) |
| Windows Modify Registry NoChangingWallPaper | 🟡 medium | 36 | `T1112` | [`windows_modify_registry_nochangingwallpaper.yaml`](./windows_modify_registry_nochangingwallpaper.yaml) |
| Windows Modify Registry ProxyEnable | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_proxyenable.yaml`](./windows_modify_registry_proxyenable.yaml) |
| Windows Modify Registry ProxyServer | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_proxyserver.yaml`](./windows_modify_registry_proxyserver.yaml) |
| Windows Modify Registry Suppress Win Defender Notif | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_suppress_win_defender_notif.yaml`](./windows_modify_registry_suppress_win_defender_notif.yaml) |
| Windows Modify Registry Utilize ProgIDs | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_utilize_progids.yaml`](./windows_modify_registry_utilize_progids.yaml) |
| Windows Modify Registry WER DontShowUI | 🟡 medium | 36 | `T1112` | [`windows_modify_registry_dontshowui.yaml`](./windows_modify_registry_dontshowui.yaml) |
| Windows Modify Registry With MD5 Reg Key Name | 🟡 medium | 36 | `T1112` | [`windows_modify_registry_with_md5_reg_key_name.yaml`](./windows_modify_registry_with_md5_reg_key_name.yaml) |
| Windows New Default File Association Value Set | 🟡 medium | 40 | `T1546.001` | [`windows_new_default_file_association_value_set.yaml`](./windows_new_default_file_association_value_set.yaml) |
| Windows Recall Feature Enabled - Registry | 🟡 medium | 50 | `T1113` | [`windows_recall_feature_enabled_registry.yaml`](./windows_recall_feature_enabled_registry.yaml) |
| Winlogon AllowMultipleTSSessions Enable | 🟡 medium | 50 | `T1112` | [`winlogon_allowmultipletssessions_enable.yaml`](./winlogon_allowmultipletssessions_enable.yaml) |
| WinSock2 Autorun Keys Modification | 🟡 medium | 50 | `T1547.001` | [`winsock2_autorun_keys_modification.yaml`](./winsock2_autorun_keys_modification.yaml) |
| Wow6432Node Classes Autorun Keys Modification | 🟡 medium | 50 | `T1547.001` | [`wow6432node_classes_autorun_keys_modification.yaml`](./wow6432node_classes_autorun_keys_modification.yaml) |
| Wow6432Node CurrentVersion Autorun Keys Modification | 🟡 medium | 50 | `T1547.001` | [`wow6432node_currentversion_autorun_keys_modification.yaml`](./wow6432node_currentversion_autorun_keys_modification.yaml) |
| Wow6432Node Windows NT CurrentVersion Autorun Keys Modification | 🟡 medium | 50 | `T1547.001` | [`wow6432node_windows_nt_currentversion_autorun_keys_modification.yaml`](./wow6432node_windows_nt_currentversion_autorun_keys_modification.yaml) |
| Windows Modify Registry Disable RDP | 🔵 low | 25 | `T1112` | [`windows_modify_registry_disable_rdp.yaml`](./windows_modify_registry_disable_rdp.yaml) |
| Windows Modify Registry LongPathsEnabled | 🔵 low | 16 | `T1112` | [`windows_modify_registry_longpathsenabled.yaml`](./windows_modify_registry_longpathsenabled.yaml) |
| Windows Modify Registry MaxConnectionPerServer | 🔵 low | 25 | `T1112` | [`windows_modify_registry_maxconnectionperserver.yaml`](./windows_modify_registry_maxconnectionperserver.yaml) |
| Windows Modify Registry No Auto Reboot With Logon User | 🔵 low | 9 | `T1112` | [`windows_modify_registry_no_auto_reboot_with_logon_user.yaml`](./windows_modify_registry_no_auto_reboot_with_logon_user.yaml) |
| Windows Modify Registry on Smart Card Group Policy | 🔵 low | 25 | `T1112` | [`windows_modify_registry_on_smart_card_group_policy.yaml`](./windows_modify_registry_on_smart_card_group_policy.yaml) |
| Windows Modify Registry UpdateServiceUrlAlternate | 🔵 low | 25 | `T1112` | [`windows_modify_registry_updateserviceurlalternate.yaml`](./windows_modify_registry_updateserviceurlalternate.yaml) |
| Windows Modify Registry UseWUServer | 🔵 low | 9 | `T1112` | [`windows_modify_registry_usewuserver.yaml`](./windows_modify_registry_usewuserver.yaml) |
| Windows Modify Registry WuServer | 🔵 low | 25 | `T1112` | [`windows_modify_registry_wuserver.yaml`](./windows_modify_registry_wuserver.yaml) |
| Windows Modify Registry WUStatusServer | 🔵 low | 25 | `T1112` | [`windows_modify_registry_wustatusserver.yaml`](./windows_modify_registry_wustatusserver.yaml) |
| Windows Modify Show Compress Color And Info Tip Registry | 🔵 low | 25 | `T1112` | [`windows_modify_show_compress_color_and_info_tip_registry.yaml`](./windows_modify_show_compress_color_and_info_tip_registry.yaml) |
| Windows WPDBusEnum Registry Key Modification - USB Device Detection | 🔵 low | 25 | `T1200`, `T1025`, `T1091` | [`windows_wpdbusenum_registry_key_modification.yaml`](./windows_wpdbusenum_registry_key_modification.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
