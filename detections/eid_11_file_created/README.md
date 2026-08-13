# Sysmon Event ID 11 — File Created

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **201 rules**

File creation events, used for dropper, staging, startup-folder persistence and ransomware note detection.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🔴 critical 15 · 🟠 high 114 · 🟡 medium 71 · 🔵 low 1 |
| Status | experimental 197, production 4 |
| ATT&CK techniques | 85 distinct |
| Provenance | 198 Sigma-derived, 3 written for this repo |
| Event IDs queried | `11` (201) |

## Onboarding

Enable `FileCreate` in the Sysmon config, scoped to the directories your rules target (Startup, Temp, Public, web roots).

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 201 |
| `data_win_eventdata_targetFilename` | 200 |
| `data_win_eventdata_image` | 94 |
| `data_win_eventdata_commandLine` | 4 |
| `data_win_eventdata_parentImage` | 3 |
| `data_win_eventdata_user` | 1 |
| `data_win_eventdata_creationUtcTime` | 1 |
| `data_win_eventdata_parentCommandLine` | 1 |

## Top ATT&CK techniques

[`T1219.002`](https://attack.mitre.org/techniques/T1219/002/) (9) · [`T1003.001`](https://attack.mitre.org/techniques/T1003/001/) (9) · [`T1548.002`](https://attack.mitre.org/techniques/T1548/002/) (8) · [`T1218`](https://attack.mitre.org/techniques/T1218/) (7) · [`T1574.001`](https://attack.mitre.org/techniques/T1574/001/) (7) · [`T1190`](https://attack.mitre.org/techniques/T1190/) (7) · [`T1547.001`](https://attack.mitre.org/techniques/T1547/001/) (6) · [`T1566.001`](https://attack.mitre.org/techniques/T1566/001/) (6)

## Rules (201)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| APT29 2018 Phishing Campaign File Indicators | 🔴 critical | 90 | `T1218.011` | [`apt29_2018_phishing_campaign_file_indicators.yaml`](./apt29_2018_phishing_campaign_file_indicators.yaml) |
| CVE-2021-1675 Print Spooler Exploitation Filename Pattern | 🔴 critical | 90 | `T1587` | [`cve_2021_1675_print_spooler_exploitation_filename_pattern.yaml`](./cve_2021_1675_print_spooler_exploitation_filename_pattern.yaml) |
| CVE-2021-31979 CVE-2021-33771 Exploits by Sourgum | 🔴 critical | 90 | `T1566`, `T1203` | [`cve_2021_31979_cve_2021_33771_exploits_by_sourgum.yaml`](./cve_2021_31979_cve_2021_33771_exploits_by_sourgum.yaml) |
| HackTool - Dumpert Process Dumper Default File | 🔴 critical | 90 | `T1003.001` | [`hacktool_dumpert_process_dumper_default_file.yaml`](./hacktool_dumpert_process_dumper_default_file.yaml) |
| HackTool - Inveigh Execution Artefacts | 🔴 critical | 90 | `T1219.002` | [`hacktool_inveigh_execution_artefacts.yaml`](./hacktool_inveigh_execution_artefacts.yaml) |
| HackTool - Mimikatz Kirbi File Creation | 🔴 critical | 90 | `T1558` | [`hacktool_mimikatz_kirbi_file_creation.yaml`](./hacktool_mimikatz_kirbi_file_creation.yaml) |
| HackTool - QuarksPwDump Dump File | 🔴 critical | 90 | `T1003.002` | [`hacktool_quarkspwdump_dump_file.yaml`](./hacktool_quarkspwdump_dump_file.yaml) |
| InstallerFileTakeOver LPE CVE-2021-41379 File Create Event | 🔴 critical | 90 | `T1068` | [`installerfiletakeover_lpe_cve_2021_41379_file_create_event.yaml`](./installerfiletakeover_lpe_cve_2021_41379_file_create_event.yaml) |
| Moriya Rootkit File Created | 🔴 critical | 90 | `T1543.003` | [`moriya_rootkit_file_created.yaml`](./moriya_rootkit_file_created.yaml) |
| Potential DCOM InternetExplorer.Application DLL Hijack | 🔴 critical | 90 | `T1021.002`, `T1021.003` | [`potential_dcom_internetexplorer_application_dll_hijack.yaml`](./potential_dcom_internetexplorer_application_dll_hijack.yaml) |
| Potential SharePoint ToolShell CVE-2025-53770 Exploitation - File Create | 🔴 critical | 90 | `T1190` | [`potential_sharepoint_toolshell_cve_2025_53770_exploitation_file_create.yaml`](./potential_sharepoint_toolshell_cve_2025_53770_exploitation_file_create.yaml) |
| RedSun - TieringEngineService.exe Staged in RS-Prefixed Temp Dir | 🔴 critical | 90 | `T1036.005` | [`redsun_tieringengineservice_exe_staged_in_rs_prefixed_temp_dir.yaml`](./redsun_tieringengineservice_exe_staged_in_rs_prefixed_temp_dir.yaml) |
| SNAKE Malware Kernel Driver File Indicator | 🔴 critical | 90 | — | [`snake_malware_kernel_driver_file_indicator.yaml`](./snake_malware_kernel_driver_file_indicator.yaml) |
| Wmiexec Default Output File | 🔴 critical | 90 | `T1047` | [`wmiexec_default_output_file.yaml`](./wmiexec_default_output_file.yaml) |
| Wmiprvse Wbemcomn DLL Hijack - File | 🔴 critical | 90 | `T1047`, `T1021.002` | [`wmiprvse_wbemcomn_dll_hijack_file.yaml`](./wmiprvse_wbemcomn_dll_hijack_file.yaml) |
| .RDP File Created By Uncommon Application | 🟠 high | 75 | — | [`rdp_file_created_by_uncommon_application.yaml`](./rdp_file_created_by_uncommon_application.yaml) |
| Adwind RAT / JRAT File Artifact | 🟠 high | 75 | `T1059.005`, `T1059.007` | [`adwind_rat_jrat_file_artifact.yaml`](./adwind_rat_jrat_file_artifact.yaml) |
| Axios NPM Compromise File Creation Indicators - Windows | 🟠 high | 75 | `T1195.002` | [`axios_npm_compromise_file_creation_indicators_windows.yaml`](./axios_npm_compromise_file_creation_indicators_windows.yaml) |
| BloodHound Collection Files | 🟠 high | 75 | `T1087.001`, `T1087.002`, `T1482`… | [`bloodhound_collection_files.yaml`](./bloodhound_collection_files.yaml) |
| Creation Exe for Service with Unquoted Path | 🟠 high | 75 | `T1547.009` | [`creation_exe_for_service_with_unquoted_path.yaml`](./creation_exe_for_service_with_unquoted_path.yaml) |
| Cred Dump Tools Dropped Files | 🟠 high | 75 | `T1003.001`, `T1003.002`, `T1003.003`… | [`cred_dump_tools_dropped_files.yaml`](./cred_dump_tools_dropped_files.yaml) |
| CVE-2021-26858 Exchange Exploitation | 🟠 high | 75 | `T1203` | [`cve_2021_26858_exchange_exploitation.yaml`](./cve_2021_26858_exchange_exploitation.yaml) |
| CVE-2021-44077 POC Default Dropped File | 🟠 high | 75 | — | [`cve_2021_44077_poc_default_dropped_file.yaml`](./cve_2021_44077_poc_default_dropped_file.yaml) |
| CVE-2022-24527 Microsoft Connected Cache LPE | 🟠 high | 75 | `T1059.001` | [`cve_2022_24527_microsoft_connected_cache_lpe.yaml`](./cve_2022_24527_microsoft_connected_cache_lpe.yaml) |
| CVE-2023-38331 Exploitation Attempt - Suspicious Double Extension File | 🟠 high | 75 | — | [`cve_2023_38331_exploitation_attempt_suspicious_double_extension_file.yaml`](./cve_2023_38331_exploitation_attempt_suspicious_double_extension_file.yaml) |
| Diamond Sleet APT File Creation Indicators | 🟠 high | 75 | — | [`diamond_sleet_apt_file_creation_indicators.yaml`](./diamond_sleet_apt_file_creation_indicators.yaml) |
| DLL Search Order Hijackig Via Additional Space in Path | 🟠 high | 75 | `T1574.001` | [`dll_search_order_hijackig_via_additional_space_in_path.yaml`](./dll_search_order_hijackig_via_additional_space_in_path.yaml) |
| DPAPI Backup Keys And Certificate Export Activity IOC | 🟠 high | 75 | `T1555`, `T1552.004` | [`dpapi_backup_keys_and_certificate_export_activity_ioc.yaml`](./dpapi_backup_keys_and_certificate_export_activity_ioc.yaml) |
| File Creation In Suspicious Directory By Msdt.EXE | 🟠 high | 75 | `T1547.001` | [`file_creation_in_suspicious_directory_by_msdt_exe.yaml`](./file_creation_in_suspicious_directory_by_msdt_exe.yaml) |
| File Creation Related To RAT Clients | 🟠 high | 75 | — | [`file_creation_related_to_rat_clients.yaml`](./file_creation_related_to_rat_clients.yaml) |
| File With Uncommon Extension Created By An Office Application | 🟠 high | 75 | `T1204.002` | [`file_with_uncommon_extension_created_by_an_office_application.yaml`](./file_with_uncommon_extension_created_by_an_office_application.yaml) |
| Forest Blizzard APT - File Creation Activity | 🟠 high | 75 | `T1685.001` | [`forest_blizzard_apt_file_creation_activity.yaml`](./forest_blizzard_apt_file_creation_activity.yaml) |
| FunkLocker Ransomware File Creation | 🟠 high | 75 | `T1486` | [`funklocker_ransomware_file_creation.yaml`](./funklocker_ransomware_file_creation.yaml) |
| Goofy Guineapig Backdoor IOC | 🟠 high | 75 | — | [`goofy_guineapig_backdoor_ioc.yaml`](./goofy_guineapig_backdoor_ioc.yaml) |
| HackTool - CrackMapExec File Indicators | 🟠 high | 75 | `T1003.001` | [`hacktool_crackmapexec_file_indicators.yaml`](./hacktool_crackmapexec_file_indicators.yaml) |
| HackTool - Impacket File Indicators | 🟠 high | 75 | `T1003.001` | [`hacktool_impacket_file_indicators.yaml`](./hacktool_impacket_file_indicators.yaml) |
| HackTool - NetExec File Indicators | 🟠 high | 75 | `T1021.002`, `T1059.005` | [`hacktool_netexec_file_indicators.yaml`](./hacktool_netexec_file_indicators.yaml) |
| HackTool - NPPSpy Hacktool Usage | 🟠 high | 75 | — | [`hacktool_nppspy_hacktool_usage.yaml`](./hacktool_nppspy_hacktool_usage.yaml) |
| HackTool - Potential Remote Credential Dumping Activity Via CrackMapExec Or Impacket-Secretsdump | 🟠 high | 75 | `T1003` | [`hacktool_potential_remote_credential_dumping_activity_via_crackmapexec_or_impacket_secretsdump.yaml`](./hacktool_potential_remote_credential_dumping_activity_via_crackmapexec_or_impacket_secretsdump.yaml) |
| HackTool - Powerup Write Hijack DLL | 🟠 high | 75 | `T1574.001` | [`hacktool_powerup_write_hijack_dll.yaml`](./hacktool_powerup_write_hijack_dll.yaml) |
| HackTool - RemoteKrbRelay SMB Relay Secrets Dump Module Indicators | 🟠 high | 75 | `T1219.002` | [`hacktool_remotekrbrelay_smb_relay_secrets_dump_module_indicators.yaml`](./hacktool_remotekrbrelay_smb_relay_secrets_dump_module_indicators.yaml) |
| HackTool - SafetyKatz Dump Indicator | 🟠 high | 75 | `T1003.001` | [`hacktool_safetykatz_dump_indicator.yaml`](./hacktool_safetykatz_dump_indicator.yaml) |
| HackTool - Typical HiveNightmare SAM File Export | 🟠 high | 75 | `T1552.001` | [`hacktool_typical_hivenightmare_sam_file_export.yaml`](./hacktool_typical_hivenightmare_sam_file_export.yaml) |
| Hijack Legit RDP Session to Move Laterally | 🟠 high | 75 | `T1219.002` | [`hijack_legit_rdp_session_to_move_laterally.yaml`](./hijack_legit_rdp_session_to_move_laterally.yaml) |
| ISO File Created Within Temp Folders | 🟠 high | 75 | `T1566.001` | [`iso_file_created_within_temp_folders.yaml`](./iso_file_created_within_temp_folders.yaml) |
| Lace Tempest File Indicators | 🟠 high | 75 | — | [`lace_tempest_file_indicators.yaml`](./lace_tempest_file_indicators.yaml) |
| Legitimate Application Dropped Archive | 🟠 high | 75 | `T1218` | [`legitimate_application_dropped_archive.yaml`](./legitimate_application_dropped_archive.yaml) |
| Legitimate Application Dropped Executable | 🟠 high | 75 | `T1218` | [`legitimate_application_dropped_executable.yaml`](./legitimate_application_dropped_executable.yaml) |
| Legitimate Application Dropped Script | 🟠 high | 75 | `T1218` | [`legitimate_application_dropped_script.yaml`](./legitimate_application_dropped_script.yaml) |
| Legitimate Application Writing Files In Uncommon Location | 🟠 high | 75 | `T1218`, `T1105` | [`legitimate_application_writing_files_in_uncommon_location.yaml`](./legitimate_application_writing_files_in_uncommon_location.yaml) |
| LiveKD Driver Creation By Uncommon Process | 🟠 high | 75 | — | [`livekd_driver_creation_by_uncommon_process.yaml`](./livekd_driver_creation_by_uncommon_process.yaml) |
| LiveKD Kernel Memory Dump File Created | 🟠 high | 75 | — | [`livekd_kernel_memory_dump_file_created.yaml`](./livekd_kernel_memory_dump_file_created.yaml) |
| LSASS Process Dump Artefact In CrashDumps Folder | 🟠 high | 75 | `T1003.001` | [`lsass_process_dump_artefact_in_crashdumps_folder.yaml`](./lsass_process_dump_artefact_in_crashdumps_folder.yaml) |
| LSASS Process Memory Dump Creation Via Taskmgr.EXE | 🟠 high | 75 | `T1003.001` | [`lsass_process_memory_dump_creation_via_taskmgr_exe.yaml`](./lsass_process_memory_dump_creation_via_taskmgr_exe.yaml) |
| LSASS Process Memory Dump Files | 🟠 high | 75 | `T1003.001` | [`lsass_process_memory_dump_files.yaml`](./lsass_process_memory_dump_files.yaml) |
| Malicious DLL File Dropped in the Teams or OneDrive Folder | 🟠 high | 75 | `T1574.001` | [`malicious_dll_file_dropped_in_the_teams_or_onedrive_folder.yaml`](./malicious_dll_file_dropped_in_the_teams_or_onedrive_folder.yaml) |
| NTDS Exfiltration Filename Patterns | 🟠 high | 75 | `T1003.003` | [`ntds_exfiltration_filename_patterns.yaml`](./ntds_exfiltration_filename_patterns.yaml) |
| NTDS.DIT Creation By Uncommon Parent Process | 🟠 high | 75 | `T1003.003` | [`ntds_dit_creation_by_uncommon_parent_process.yaml`](./ntds_dit_creation_by_uncommon_parent_process.yaml) |
| NTDS.DIT Creation By Uncommon Process | 🟠 high | 75 | `T1003.002`, `T1003.003` | [`ntds_dit_creation_by_uncommon_process.yaml`](./ntds_dit_creation_by_uncommon_process.yaml) |
| Octopus Scanner Malware | 🟠 high | 75 | `T1195`, `T1195.001` | [`octopus_scanner_malware.yaml`](./octopus_scanner_malware.yaml) |
| Office Macro File Creation From Suspicious Process | 🟠 high | 75 | `T1566.001` | [`office_macro_file_creation_from_suspicious_process.yaml`](./office_macro_file_creation_from_suspicious_process.yaml) |
| Onyx Sleet APT File Creation Indicators | 🟠 high | 75 | — | [`onyx_sleet_apt_file_creation_indicators.yaml`](./onyx_sleet_apt_file_creation_indicators.yaml) |
| PCRE.NET Package Temp Files | 🟠 high | 75 | `T1059` | [`pcre_net_package_temp_files.yaml`](./pcre_net_package_temp_files.yaml) |
| PDF File Created By RegEdit.EXE | 🟠 high | 75 | — | [`pdf_file_created_by_regedit_exe.yaml`](./pdf_file_created_by_regedit_exe.yaml) |
| Pingback Backdoor File Indicators | 🟠 high | 75 | `T1574.001` | [`pingback_backdoor_file_indicators.yaml`](./pingback_backdoor_file_indicators.yaml) |
| Potential APT FIN7 Related PowerShell Script Created | 🟠 high | 75 | — | [`potential_apt_fin7_related_powershell_script_created.yaml`](./potential_apt_fin7_related_powershell_script_created.yaml) |
| Potential COLDSTEEL Persistence Service DLL Creation | 🟠 high | 75 | — | [`potential_coldsteel_persistence_service_dll_creation.yaml`](./potential_coldsteel_persistence_service_dll_creation.yaml) |
| Potential COLDSTEEL RAT File Indicators | 🟠 high | 75 | — | [`potential_coldsteel_rat_file_indicators.yaml`](./potential_coldsteel_rat_file_indicators.yaml) |
| Potential CVE-2023-27363 Exploitation - HTA File Creation By FoxitPDFReader | 🟠 high | 75 | `T1505.001` | [`potential_cve_2023_27363_exploitation_hta_file_creation_by_foxitpdfreader.yaml`](./potential_cve_2023_27363_exploitation_hta_file_creation_by_foxitpdfreader.yaml) |
| Potential CVE-2023-36874 Exploitation - Fake Wermgr.Exe Creation | 🟠 high | 75 | — | [`potential_cve_2023_36874_exploitation_fake_wermgr_exe_creation.yaml`](./potential_cve_2023_36874_exploitation_fake_wermgr_exe_creation.yaml) |
| Potential Devil Bait Related Indicator | 🟠 high | 75 | — | [`potential_devil_bait_related_indicator.yaml`](./potential_devil_bait_related_indicator.yaml) |
| Potential File Extension Spoofing Using Right-to-Left Override | 🟠 high | 75 | `T1036.002` | [`potential_file_extension_spoofing_using_right_to_left_override.yaml`](./potential_file_extension_spoofing_using_right_to_left_override.yaml) |
| Potential Kapeka Decrypted Backdoor Indicator | 🟠 high | 75 | — | [`potential_kapeka_decrypted_backdoor_indicator.yaml`](./potential_kapeka_decrypted_backdoor_indicator.yaml) |
| Potential MOVEit Transfer CVE-2023-34362 Exploitation - File Activity | 🟠 high | 75 | `T1190` | [`potential_moveit_transfer_cve_2023_34362_exploitation_file_activity.yaml`](./potential_moveit_transfer_cve_2023_34362_exploitation_file_activity.yaml) |
| Potential Persistence Via Microsoft Office Add-In | 🟠 high | 75 | `T1137.006` | [`potential_persistence_via_microsoft_office_add_in.yaml`](./potential_persistence_via_microsoft_office_add_in.yaml) |
| Potential Persistence Via Microsoft Office Startup Folder | 🟠 high | 75 | `T1137` | [`potential_persistence_via_microsoft_office_startup_folder.yaml`](./potential_persistence_via_microsoft_office_startup_folder.yaml) |
| Potential Persistence Via Outlook Form | 🟠 high | 75 | `T1137.003` | [`potential_persistence_via_outlook_form.yaml`](./potential_persistence_via_outlook_form.yaml) |
| Potential Privilege Escalation Attempt Via .Exe.Local Technique | 🟠 high | 75 | — | [`potential_privilege_escalation_attempt_via_exe_local_technique.yaml`](./potential_privilege_escalation_attempt_via_exe_local_technique.yaml) |
| Potential RipZip Attack on Startup Folder | 🟠 high | 75 | `T1547` | [`potential_ripzip_attack_on_startup_folder.yaml`](./potential_ripzip_attack_on_startup_folder.yaml) |
| Potential SAM Database Dump | 🟠 high | 75 | `T1003.002` | [`potential_sam_database_dump.yaml`](./potential_sam_database_dump.yaml) |
| Potential Startup Shortcut Persistence Via PowerShell.EXE | 🟠 high | 75 | `T1547.001` | [`potential_startup_shortcut_persistence_via_powershell_exe.yaml`](./potential_startup_shortcut_persistence_via_powershell_exe.yaml) |
| Potential Winnti Dropper Activity | 🟠 high | 75 | `T1027` | [`potential_winnti_dropper_activity.yaml`](./potential_winnti_dropper_activity.yaml) |
| Process Explorer Driver Creation By Non-Sysinternals Binary | 🟠 high | 75 | `T1068` | [`process_explorer_driver_creation_by_non_sysinternals_binary.yaml`](./process_explorer_driver_creation_by_non_sysinternals_binary.yaml) |
| PSEXEC Remote Execution File Artefact | 🟠 high | 75 | `T1136.002`, `T1543.003`, `T1570` | [`psexec_remote_execution_file_artefact.yaml`](./psexec_remote_execution_file_artefact.yaml) |
| Renamed VsCode Code Tunnel Execution - File Indicator | 🟠 high | 75 | — | [`renamed_vscode_code_tunnel_execution_file_indicator.yaml`](./renamed_vscode_code_tunnel_execution_file_indicator.yaml) |
| ScreenConnect - SlashAndGrab Exploitation Indicators | 🟠 high | 75 | — | [`screenconnect_slashandgrab_exploitation_indicators.yaml`](./screenconnect_slashandgrab_exploitation_indicators.yaml) |
| Small Sieve Malware File Indicator Creation | 🟠 high | 75 | `T1036.005` | [`small_sieve_malware_file_indicator_creation.yaml`](./small_sieve_malware_file_indicator_creation.yaml) |
| SNAKE Malware WerFault Persistence File Creation | 🟠 high | 75 | — | [`snake_malware_werfault_persistence_file_creation.yaml`](./snake_malware_werfault_persistence_file_creation.yaml) |
| Suspicious ASPX File Drop by Exchange | 🟠 high | 75 | `T1505.003` | [`suspicious_aspx_file_drop_by_exchange.yaml`](./suspicious_aspx_file_drop_by_exchange.yaml) |
| Suspicious Binaries and Scripts in Public Folder | 🟠 high | 75 | `T1204` | [`suspicious_binaries_and_scripts_in_public_folder.yaml`](./suspicious_binaries_and_scripts_in_public_folder.yaml) |
| Suspicious Binary Writes Via AnyDesk | 🟠 high | 75 | `T1219.002` | [`suspicious_binary_writes_via_anydesk.yaml`](./suspicious_binary_writes_via_anydesk.yaml) |
| Suspicious Creation with Colorcpl | 🟠 high | 75 | `T1564` | [`suspicious_creation_with_colorcpl.yaml`](./suspicious_creation_with_colorcpl.yaml) |
| Suspicious Desktopimgdownldr Target File | 🟠 high | 75 | `T1105` | [`suspicious_desktopimgdownldr_target_file.yaml`](./suspicious_desktopimgdownldr_target_file.yaml) |
| Suspicious DotNET CLR Usage Log Artifact | 🟠 high | 75 | `T1218` | [`suspicious_dotnet_clr_usage_log_artifact.yaml`](./suspicious_dotnet_clr_usage_log_artifact.yaml) |
| Suspicious Double Extension Files | 🟠 high | 75 | `T1036.007` | [`suspicious_double_extension_files.yaml`](./suspicious_double_extension_files.yaml) |
| Suspicious Executable File Creation | 🟠 high | 75 | `T1564` | [`suspicious_executable_file_creation.yaml`](./suspicious_executable_file_creation.yaml) |
| Suspicious File Created by ArcSOC.exe | 🟠 high | 75 | `T1127`, `T1105`, `T1133` | [`suspicious_file_created_by_arcsoc_exe.yaml`](./suspicious_file_created_by_arcsoc_exe.yaml) |
| Suspicious File Created in Outlook Temporary Directory | 🟠 high | 75 | `T1566.001` | [`suspicious_file_created_in_outlook_temporary_directory.yaml`](./suspicious_file_created_in_outlook_temporary_directory.yaml) |
| Suspicious File Created Via OneNote Application | 🟠 high | 75 | — | [`suspicious_file_created_via_onenote_application.yaml`](./suspicious_file_created_via_onenote_application.yaml) |
| Suspicious File Creation Activity From Fake Recycle.Bin Folder | 🟠 high | 75 | — | [`suspicious_file_creation_activity_from_fake_recycle_bin_folder.yaml`](./suspicious_file_creation_activity_from_fake_recycle_bin_folder.yaml) |
| Suspicious File Creation In Uncommon AppData Folder | 🟠 high | 75 | — | [`suspicious_file_creation_in_uncommon_appdata_folder.yaml`](./suspicious_file_creation_in_uncommon_appdata_folder.yaml) |
| Suspicious File Write to SharePoint Layouts Directory | 🟠 high | 75 | `T1190`, `T1505.003` | [`suspicious_file_write_to_sharepoint_layouts_directory.yaml`](./suspicious_file_write_to_sharepoint_layouts_directory.yaml) |
| Suspicious Get-Variable.exe Creation | 🟠 high | 75 | `T1546`, `T1027` | [`suspicious_get_variable_exe_creation.yaml`](./suspicious_get_variable_exe_creation.yaml) |
| Suspicious Interactive PowerShell as SYSTEM | 🟠 high | 75 | `T1059.001` | [`suspicious_interactive_powershell_as_system.yaml`](./suspicious_interactive_powershell_as_system.yaml) |
| Suspicious MSExchangeMailboxReplication ASPX Write | 🟠 high | 75 | `T1190`, `T1505.003` | [`suspicious_msexchangemailboxreplication_aspx_write.yaml`](./suspicious_msexchangemailboxreplication_aspx_write.yaml) |
| Suspicious Outlook Macro Created | 🟠 high | 75 | `T1137`, `T1008`, `T1546` | [`suspicious_outlook_macro_created.yaml`](./suspicious_outlook_macro_created.yaml) |
| Suspicious Scheduled Task Write to System32 Tasks | 🟠 high | 75 | `T1053` | [`suspicious_scheduled_task_write_to_system32_tasks.yaml`](./suspicious_scheduled_task_write_to_system32_tasks.yaml) |
| Suspicious Startup Folder Persistence | 🟠 high | 75 | `T1204.002`, `T1547.001` | [`suspicious_startup_folder_persistence.yaml`](./suspicious_startup_folder_persistence.yaml) |
| Suspicious Word Cab File Write CVE-2021-40444 | 🟠 high | 75 | `T1587` | [`suspicious_word_cab_file_write_cve_2021_40444.yaml`](./suspicious_word_cab_file_write_cve_2021_40444.yaml) |
| UAC Bypass Abusing Winsat Path Parsing - File | 🟠 high | 75 | `T1548.002` | [`uac_bypass_abusing_winsat_path_parsing_file.yaml`](./uac_bypass_abusing_winsat_path_parsing_file.yaml) |
| UAC Bypass Using .NET Code Profiler on MMC | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_net_code_profiler_on_mmc.yaml`](./uac_bypass_using_net_code_profiler_on_mmc.yaml) |
| UAC Bypass Using Consent and Comctl32 - File | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_consent_and_comctl32_file.yaml`](./uac_bypass_using_consent_and_comctl32_file.yaml) |
| UAC Bypass Using EventVwr | 🟠 high | 75 | — | [`uac_bypass_using_eventvwr.yaml`](./uac_bypass_using_eventvwr.yaml) |
| UAC Bypass Using IDiagnostic Profile - File | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_idiagnostic_profile_file.yaml`](./uac_bypass_using_idiagnostic_profile_file.yaml) |
| UAC Bypass Using IEInstal - File | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_ieinstal_file.yaml`](./uac_bypass_using_ieinstal_file.yaml) |
| UAC Bypass Using MSConfig Token Modification - File | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_msconfig_token_modification_file.yaml`](./uac_bypass_using_msconfig_token_modification_file.yaml) |
| UAC Bypass Using NTFS Reparse Point - File | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_ntfs_reparse_point_file.yaml`](./uac_bypass_using_ntfs_reparse_point_file.yaml) |
| UAC Bypass Using Windows Media Player - File | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_windows_media_player_file.yaml`](./uac_bypass_using_windows_media_player_file.yaml) |
| UEFI Persistence Via Wpbbin - FileCreation | 🟠 high | 75 | `T1542.001` | [`uefi_persistence_via_wpbbin_filecreation.yaml`](./uefi_persistence_via_wpbbin_filecreation.yaml) |
| Uncommon File Created by Notepad++ Updater Gup.EXE | 🟠 high | 75 | `T1195.002`, `T1557` | [`uncommon_file_created_by_notepad_updater_gup_exe.yaml`](./uncommon_file_created_by_notepad_updater_gup_exe.yaml) |
| Uncommon File Created In Office Startup Folder | 🟠 high | 75 | `T1587.001` | [`uncommon_file_created_in_office_startup_folder.yaml`](./uncommon_file_created_in_office_startup_folder.yaml) |
| Uncommon File Creation By Mysql Daemon Process | 🟠 high | 75 | — | [`uncommon_file_creation_by_mysql_daemon_process.yaml`](./uncommon_file_creation_by_mysql_daemon_process.yaml) |
| WerFault LSASS Process Memory Dump | 🟠 high | 75 | `T1003.001` | [`werfault_lsass_process_memory_dump.yaml`](./werfault_lsass_process_memory_dump.yaml) |
| Windows Binaries Write Suspicious Extensions | 🟠 high | 75 | `T1036` | [`windows_binaries_write_suspicious_extensions.yaml`](./windows_binaries_write_suspicious_extensions.yaml) |
| Windows EXE File Created in Startup Folder | 🟠 high | 60 | `T1547.001` | [`windows_exe_file_created_in_startup_folder.yaml`](./windows_exe_file_created_in_startup_folder.yaml) |
| Windows Shell/Scripting Application File Write to Suspicious Folder | 🟠 high | 75 | `T1059` | [`windows_shell_scripting_application_file_write_to_suspicious_folder.yaml`](./windows_shell_scripting_application_file_write_to_suspicious_folder.yaml) |
| WinRAR Creating Files in Startup Locations | 🟠 high | 75 | `T1547.001` | [`winrar_creating_files_in_startup_locations.yaml`](./winrar_creating_files_in_startup_locations.yaml) |
| WMI Persistence - Script Event Consumer File Write | 🟠 high | 75 | `T1546.003` | [`wmi_persistence_script_event_consumer_file_write.yaml`](./wmi_persistence_script_event_consumer_file_write.yaml) |
| WScript or CScript Dropper - File | 🟠 high | 75 | `T1059.005`, `T1059.007` | [`wscript_or_cscript_dropper_file.yaml`](./wscript_or_cscript_dropper_file.yaml) |
| ADExplorer Writing Complete AD Snapshot Into .dat File | 🟡 medium | 50 | `T1087.002`, `T1069.002`, `T1482` | [`adexplorer_writing_complete_ad_snapshot_into_dat_file.yaml`](./adexplorer_writing_complete_ad_snapshot_into_dat_file.yaml) |
| ADSI-Cache File Creation By Uncommon Tool | 🟡 medium | 50 | `T1001.003` | [`adsi_cache_file_creation_by_uncommon_tool.yaml`](./adsi_cache_file_creation_by_uncommon_tool.yaml) |
| Advanced IP Scanner - File Event | 🟡 medium | 50 | `T1046` | [`advanced_ip_scanner_file_event.yaml`](./advanced_ip_scanner_file_event.yaml) |
| Anydesk Temporary Artefact | 🟡 medium | 50 | `T1219.002` | [`anydesk_temporary_artefact.yaml`](./anydesk_temporary_artefact.yaml) |
| Assembly DLL Creation Via AspNetCompiler | 🟡 medium | 50 | — | [`assembly_dll_creation_via_aspnetcompiler.yaml`](./assembly_dll_creation_via_aspnetcompiler.yaml) |
| AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File | 🟡 medium | 50 | `T1216` | [`awl_bypass_with_winrm_vbs_and_malicious_wsmpty_xsl_wsmtxt_xsl_file.yaml`](./awl_bypass_with_winrm_vbs_and_malicious_wsmpty_xsl_wsmtxt_xsl_file.yaml) |
| Created Files by Microsoft Sync Center | 🟡 medium | 50 | `T1055`, `T1218` | [`created_files_by_microsoft_sync_center.yaml`](./created_files_by_microsoft_sync_center.yaml) |
| Creation of a Diagcab | 🟡 medium | 50 | — | [`creation_of_a_diagcab.yaml`](./creation_of_a_diagcab.yaml) |
| Creation Of Non-Existent System DLL | 🟡 medium | 50 | `T1574.001` | [`creation_of_non_existent_system_dll.yaml`](./creation_of_non_existent_system_dll.yaml) |
| Creation of WerFault.exe/Wer.dll in Unusual Folder | 🟡 medium | 50 | `T1574.001` | [`creation_of_werfault_exe_wer_dll_in_unusual_folder.yaml`](./creation_of_werfault_exe_wer_dll_in_unusual_folder.yaml) |
| CSExec Service File Creation | 🟡 medium | 50 | `T1569.002` | [`csexec_service_file_creation.yaml`](./csexec_service_file_creation.yaml) |
| CVE-2024-1708 - ScreenConnect Path Traversal Exploitation | 🟡 medium | 50 | — | [`cve_2024_1708_screenconnect_path_traversal_exploitation.yaml`](./cve_2024_1708_screenconnect_path_traversal_exploitation.yaml) |
| DarkGate - Autoit3.EXE File Creation By Uncommon Process | 🟡 medium | 50 | `T1105`, `T1059` | [`darkgate_autoit3_exe_file_creation_by_uncommon_process.yaml`](./darkgate_autoit3_exe_file_creation_by_uncommon_process.yaml) |
| DarkGate - Drop DarkGate Loader In C:\Temp Directory | 🟡 medium | 50 | `T1059` | [`darkgate_drop_darkgate_loader_in_c_temp_directory.yaml`](./darkgate_drop_darkgate_loader_in_c_temp_directory.yaml) |
| Desktop.INI Created by Uncommon Process | 🟡 medium | 50 | `T1547.009` | [`desktop_ini_created_by_uncommon_process.yaml`](./desktop_ini_created_by_uncommon_process.yaml) |
| Drop Binaries Into Spool Drivers Color Folder | 🟡 medium | 50 | — | [`drop_binaries_into_spool_drivers_color_folder.yaml`](./drop_binaries_into_spool_drivers_color_folder.yaml) |
| EVTX Created In Uncommon Location | 🟡 medium | 50 | `T1685.001` | [`evtx_created_in_uncommon_location.yaml`](./evtx_created_in_uncommon_location.yaml) |
| Files With System DLL Name In Unsuspected Locations | 🟡 medium | 50 | `T1036.005` | [`files_with_system_dll_name_in_unsuspected_locations.yaml`](./files_with_system_dll_name_in_unsuspected_locations.yaml) |
| Files With System Process Name In Unsuspected Locations | 🟡 medium | 50 | `T1036.005` | [`files_with_system_process_name_in_unsuspected_locations.yaml`](./files_with_system_process_name_in_unsuspected_locations.yaml) |
| Forest Blizzard APT - JavaScript Constrained File Creation | 🟡 medium | 50 | `T1685.001` | [`forest_blizzard_apt_javascript_constrained_file_creation.yaml`](./forest_blizzard_apt_javascript_constrained_file_creation.yaml) |
| GatherNetworkInfo.VBS Reconnaissance Script Output | 🟡 medium | 50 | — | [`gathernetworkinfo_vbs_reconnaissance_script_output.yaml`](./gathernetworkinfo_vbs_reconnaissance_script_output.yaml) |
| GoToAssist Temporary Installation Artefact | 🟡 medium | 50 | `T1219.002` | [`gotoassist_temporary_installation_artefact.yaml`](./gotoassist_temporary_installation_artefact.yaml) |
| Installation of TeamViewer Desktop | 🟡 medium | 50 | `T1219.002` | [`installation_of_teamviewer_desktop.yaml`](./installation_of_teamviewer_desktop.yaml) |
| ISO or Image Mount Indicator in Recent Files | 🟡 medium | 50 | `T1566.001` | [`iso_or_image_mount_indicator_in_recent_files.yaml`](./iso_or_image_mount_indicator_in_recent_files.yaml) |
| LiveKD Driver Creation | 🟡 medium | 50 | — | [`livekd_driver_creation.yaml`](./livekd_driver_creation.yaml) |
| New Custom Shim Database Created | 🟡 medium | 50 | `T1547.009` | [`new_custom_shim_database_created.yaml`](./new_custom_shim_database_created.yaml) |
| New Outlook Macro Created | 🟡 medium | 50 | `T1137`, `T1008`, `T1546` | [`new_outlook_macro_created.yaml`](./new_outlook_macro_created.yaml) |
| OneNote Attachment File Dropped In Suspicious Location | 🟡 medium | 50 | — | [`onenote_attachment_file_dropped_in_suspicious_location.yaml`](./onenote_attachment_file_dropped_in_suspicious_location.yaml) |
| Potential Binary Or Script Dropper Via PowerShell | 🟡 medium | 50 | — | [`potential_binary_or_script_dropper_via_powershell.yaml`](./potential_binary_or_script_dropper_via_powershell.yaml) |
| Potential CVE-2023-36874 Exploitation - Uncommon Report.Wer Location | 🟡 medium | 50 | — | [`potential_cve_2023_36874_exploitation_uncommon_report_wer_location.yaml`](./potential_cve_2023_36874_exploitation_uncommon_report_wer_location.yaml) |
| Potential CVE-2023-36884 Exploitation Dropped File | 🟡 medium | 50 | — | [`potential_cve_2023_36884_exploitation_dropped_file.yaml`](./potential_cve_2023_36884_exploitation_dropped_file.yaml) |
| Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream | 🟡 medium | 50 | `T1564.004` | [`potential_hidden_directory_creation_via_ntfs_index_allocation_stream.yaml`](./potential_hidden_directory_creation_via_ntfs_index_allocation_stream.yaml) |
| Potential Homoglyph Attack Using Lookalike Characters in Filename | 🟡 medium | 50 | `T1036`, `T1036.003` | [`potential_homoglyph_attack_using_lookalike_characters_in_filename.yaml`](./potential_homoglyph_attack_using_lookalike_characters_in_filename.yaml) |
| Potential Initial Access via DLL Search Order Hijacking | 🟡 medium | 50 | `T1566`, `T1566.001`, `T1574`… | [`potential_initial_access_via_dll_search_order_hijacking.yaml`](./potential_initial_access_via_dll_search_order_hijacking.yaml) |
| Potential Persistence Attempt Via ErrorHandler.Cmd | 🟡 medium | 50 | — | [`potential_persistence_attempt_via_errorhandler_cmd.yaml`](./potential_persistence_attempt_via_errorhandler_cmd.yaml) |
| Potential Persistence Via Notepad++ Plugins | 🟡 medium | 50 | — | [`potential_persistence_via_notepad_plugins.yaml`](./potential_persistence_via_notepad_plugins.yaml) |
| Potential SAP NetWeaver Webshell Creation | 🟡 medium | 50 | `T1190`, `T1059.003` | [`potential_sap_netweaver_webshell_creation.yaml`](./potential_sap_netweaver_webshell_creation.yaml) |
| Potential Suspicious PowerShell Module File Created | 🟡 medium | 50 | — | [`potential_suspicious_powershell_module_file_created.yaml`](./potential_suspicious_powershell_module_file_created.yaml) |
| Potential Webshell Creation On Static Website | 🟡 medium | 50 | `T1505.003` | [`potential_webshell_creation_on_static_website.yaml`](./potential_webshell_creation_on_static_website.yaml) |
| Potentially Suspicious DMP/HDMP File Creation | 🟡 medium | 50 | — | [`potentially_suspicious_dmp_hdmp_file_creation.yaml`](./potentially_suspicious_dmp_hdmp_file_creation.yaml) |
| Potentially Suspicious File Creation by OpenEDR's ITSMService | 🟡 medium | 50 | `T1105`, `T1570`, `T1219` | [`potentially_suspicious_file_creation_by_openedr_s_itsmservice.yaml`](./potentially_suspicious_file_creation_by_openedr_s_itsmservice.yaml) |
| Potentially Suspicious WDAC Policy File Creation | 🟡 medium | 50 | — | [`potentially_suspicious_wdac_policy_file_creation.yaml`](./potentially_suspicious_wdac_policy_file_creation.yaml) |
| PowerShell Module File Created By Non-PowerShell Process | 🟡 medium | 50 | — | [`powershell_module_file_created_by_non_powershell_process.yaml`](./powershell_module_file_created_by_non_powershell_process.yaml) |
| PowerShell Profile Modification | 🟡 medium | 50 | `T1546.013` | [`powershell_profile_modification.yaml`](./powershell_profile_modification.yaml) |
| Process Monitor Driver Creation By Non-Sysinternals Binary | 🟡 medium | 50 | `T1068` | [`process_monitor_driver_creation_by_non_sysinternals_binary.yaml`](./process_monitor_driver_creation_by_non_sysinternals_binary.yaml) |
| PSScriptPolicyTest Creation By Uncommon Process | 🟡 medium | 50 | — | [`psscriptpolicytest_creation_by_uncommon_process.yaml`](./psscriptpolicytest_creation_by_uncommon_process.yaml) |
| Publisher Attachment File Dropped In Suspicious Location | 🟡 medium | 50 | — | [`publisher_attachment_file_dropped_in_suspicious_location.yaml`](./publisher_attachment_file_dropped_in_suspicious_location.yaml) |
| Rclone Config File Creation | 🟡 medium | 50 | `T1567.002` | [`rclone_config_file_creation.yaml`](./rclone_config_file_creation.yaml) |
| RemCom Service File Creation | 🟡 medium | 50 | `T1569.002` | [`remcom_service_file_creation.yaml`](./remcom_service_file_creation.yaml) |
| SCR File Write Event | 🟡 medium | 50 | `T1218.011` | [`scr_file_write_event.yaml`](./scr_file_write_event.yaml) |
| ScreenConnect Temporary Installation Artefact | 🟡 medium | 50 | `T1219.002` | [`screenconnect_temporary_installation_artefact.yaml`](./screenconnect_temporary_installation_artefact.yaml) |
| ScreenConnect User Database Modification | 🟡 medium | 50 | — | [`screenconnect_user_database_modification.yaml`](./screenconnect_user_database_modification.yaml) |
| Self Extraction Directive File Created In Potentially Suspicious Location | 🟡 medium | 50 | `T1218` | [`self_extraction_directive_file_created_in_potentially_suspicious_location.yaml`](./self_extraction_directive_file_created_in_potentially_suspicious_location.yaml) |
| Startup Folder File Write | 🟡 medium | 50 | `T1547.001` | [`startup_folder_file_write.yaml`](./startup_folder_file_write.yaml) |
| Suspicious Creation of .library-ms File — Potential CVE-2025-24054 Exploit | 🟡 medium | 50 | `T1187` | [`suspicious_creation_of_library_ms_file_potential_cve_2025_24054_exploit.yaml`](./suspicious_creation_of_library_ms_file_potential_cve_2025_24054_exploit.yaml) |
| Suspicious File Created In PerfLogs | 🟡 medium | 50 | `T1059` | [`suspicious_file_created_in_perflogs.yaml`](./suspicious_file_created_in_perflogs.yaml) |
| Suspicious File Drop by Exchange | 🟡 medium | 50 | `T1190`, `T1505.003` | [`suspicious_file_drop_by_exchange.yaml`](./suspicious_file_drop_by_exchange.yaml) |
| Suspicious File Write to Webapps Root Directory | 🟡 medium | 50 | `T1505.003`, `T1190` | [`suspicious_file_write_to_webapps_root_directory.yaml`](./suspicious_file_write_to_webapps_root_directory.yaml) |
| Suspicious Files in Default GPO Folder | 🟡 medium | 50 | `T1036.005` | [`suspicious_files_in_default_gpo_folder.yaml`](./suspicious_files_in_default_gpo_folder.yaml) |
| Suspicious LNK Double Extension File Created | 🟡 medium | 50 | `T1036.007` | [`suspicious_lnk_double_extension_file_created.yaml`](./suspicious_lnk_double_extension_file_created.yaml) |
| Suspicious PROCEXP152.sys File Created In TMP | 🟡 medium | 50 | `T1685` | [`suspicious_procexp152_sys_file_created_in_tmp.yaml`](./suspicious_procexp152_sys_file_created_in_tmp.yaml) |
| Suspicious Screensaver Binary File Creation | 🟡 medium | 50 | `T1546.002` | [`suspicious_screensaver_binary_file_creation.yaml`](./suspicious_screensaver_binary_file_creation.yaml) |
| TanStack Supply-Chain Attack File Creation Indicators - Windows | 🟡 medium | 50 | `T1195.002`, `T1059.007`, `T1554` | [`tanstack_supply_chain_attack_file_creation_indicators_windows.yaml`](./tanstack_supply_chain_attack_file_creation_indicators_windows.yaml) |
| TeamViewer Remote Session | 🟡 medium | 50 | `T1219.002` | [`teamviewer_remote_session.yaml`](./teamviewer_remote_session.yaml) |
| VHD Image Download Via Browser | 🟡 medium | 50 | `T1587.001` | [`vhd_image_download_via_browser.yaml`](./vhd_image_download_via_browser.yaml) |
| Visual Studio Code Tunnel Remote File Creation | 🟡 medium | 50 | — | [`visual_studio_code_tunnel_remote_file_creation.yaml`](./visual_studio_code_tunnel_remote_file_creation.yaml) |
| VsCode Powershell Profile Modification | 🟡 medium | 50 | `T1546.013` | [`vscode_powershell_profile_modification.yaml`](./vscode_powershell_profile_modification.yaml) |
| Windows Process Creating LNK File in Suspicious Location | 🟡 medium | 50 | `T1566.002` | [`process_creating_lnk_file_in_suspicious_location.yaml`](./process_creating_lnk_file_in_suspicious_location.yaml) |
| Windows Terminal Profile Settings Modification By Uncommon Process | 🟡 medium | 50 | `T1547.015` | [`windows_terminal_profile_settings_modification_by_uncommon_process.yaml`](./windows_terminal_profile_settings_modification_by_uncommon_process.yaml) |
| WinSxS Executable File Creation By Non-System Process | 🟡 medium | 50 | — | [`winsxs_executable_file_creation_by_non_system_process.yaml`](./winsxs_executable_file_creation_by_non_system_process.yaml) |
| Writing Local Admin Share | 🟡 medium | 50 | `T1546.002` | [`writing_local_admin_share.yaml`](./writing_local_admin_share.yaml) |
| Windows CAB File on Disk | 🔵 low | 25 | `T1566.001` | [`windows_cab_file_on_disk.yaml`](./windows_cab_file_on_disk.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
