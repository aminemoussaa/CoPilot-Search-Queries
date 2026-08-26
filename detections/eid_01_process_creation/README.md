# Sysmon Event ID 1 — Process Creation

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **1496 rules**

Every process launched on the host, with full command line, parent process, hashes and signature status. The single richest endpoint telemetry source and by far the largest rule set here.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🔴 critical 77 · 🟠 high 773 · 🟡 medium 625 · 🔵 low 21 |
| Status | experimental 1231, production 265 |
| ATT&CK techniques | 255 distinct |
| Provenance | 1267 Sigma-derived, 229 written for this repo |
| Event IDs queried | `1` (1496) |

## Onboarding

Install Sysmon with a config that logs `ProcessCreate` including `CommandLine`, `ParentImage` and `OriginalFileName`, then collect the Sysmon Operational channel with the Wazuh agent.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 1496 |
| `data_win_eventdata_commandLine` | 1179 |
| `data_win_eventdata_image` | 1162 |
| `data_win_eventdata_originalFileName` | 632 |
| `data_win_eventdata_parentImage` | 336 |
| `data_win_eventdata_parentCommandLine` | 75 |
| `data_win_eventdata_description` | 70 |
| `data_win_eventdata_product` | 47 |
| `data_win_eventdata_hashes` | 42 |
| `data_win_eventdata_integrityLevel` | 28 |

## Top ATT&CK techniques

[`T1218`](https://attack.mitre.org/techniques/T1218/) (117) · [`T1059.001`](https://attack.mitre.org/techniques/T1059/001/) (105) · [`T1059`](https://attack.mitre.org/techniques/T1059/) (62) · [`T1685`](https://attack.mitre.org/techniques/T1685/) (55) · [`T1105`](https://attack.mitre.org/techniques/T1105/) (51) · [`T1047`](https://attack.mitre.org/techniques/T1047/) (47) · [`T1202`](https://attack.mitre.org/techniques/T1202/) (36) · [`T1059.003`](https://attack.mitre.org/techniques/T1059/003/) (35)

## Rules (1496)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| APT27 - Emissary Panda Activity | 🔴 critical | 90 | `T1574.001` | [`apt27_emissary_panda_activity.yaml`](./apt27_emissary_panda_activity.yaml) |
| APT29 2018 Phishing Campaign CommandLine Indicators | 🔴 critical | 90 | `T1218.011` | [`apt29_2018_phishing_campaign_commandline_indicators.yaml`](./apt29_2018_phishing_campaign_commandline_indicators.yaml) |
| APT31 Judgement Panda Activity | 🔴 critical | 90 | `T1003.001`, `T1560.001` | [`apt31_judgement_panda_activity.yaml`](./apt31_judgement_panda_activity.yaml) |
| COLDSTEEL RAT Cleanup Command Execution | 🔴 critical | 90 | — | [`coldsteel_rat_cleanup_command_execution.yaml`](./coldsteel_rat_cleanup_command_execution.yaml) |
| COLDSTEEL RAT Service Persistence Execution | 🔴 critical | 90 | — | [`coldsteel_rat_service_persistence_execution.yaml`](./coldsteel_rat_service_persistence_execution.yaml) |
| DarkSide Ransomware Pattern | 🔴 critical | 90 | `T1204` | [`darkside_ransomware_pattern.yaml`](./darkside_ransomware_pattern.yaml) |
| DNS RCE CVE-2020-1350 | 🔴 critical | 90 | `T1190`, `T1569.002` | [`dns_rce_cve_2020_1350.yaml`](./dns_rce_cve_2020_1350.yaml) |
| Droppers Exploiting CVE-2017-11882 | 🔴 critical | 90 | `T1203`, `T1204.002`, `T1566.001` | [`droppers_exploiting_cve_2017_11882.yaml`](./droppers_exploiting_cve_2017_11882.yaml) |
| Dump LSASS via comsvcs DLL | 🔴 critical | 90 | `T1003.001` | [`dump_lsass_via_comsvcs_dll.yaml`](./dump_lsass_via_comsvcs_dll.yaml) |
| DumpStack.log Defender Evasion | 🔴 critical | 90 | — | [`dumpstack_log_defender_evasion.yaml`](./dumpstack_log_defender_evasion.yaml) |
| Elise Backdoor Activity | 🔴 critical | 90 | `T1059.003` | [`elise_backdoor_activity.yaml`](./elise_backdoor_activity.yaml) |
| Equation Group DLL_U Export Function Load | 🔴 critical | 90 | `T1218.011` | [`equation_group_dll_u_export_function_load.yaml`](./equation_group_dll_u_export_function_load.yaml) |
| EvilNum APT Golden Chickens Deployment Via OCX Files | 🔴 critical | 90 | `T1218.011` | [`evilnum_apt_golden_chickens_deployment_via_ocx_files.yaml`](./evilnum_apt_golden_chickens_deployment_via_ocx_files.yaml) |
| Exploit for CVE-2015-1641 | 🔴 critical | 90 | `T1036.005` | [`exploit_for_cve_2015_1641.yaml`](./exploit_for_cve_2015_1641.yaml) |
| Exploit for CVE-2017-8759 | 🔴 critical | 90 | `T1203`, `T1204.002`, `T1566.001` | [`exploit_for_cve_2017_8759.yaml`](./exploit_for_cve_2017_8759.yaml) |
| Exploiting CVE-2019-1388 | 🔴 critical | 90 | `T1068` | [`exploiting_cve_2019_1388.yaml`](./exploiting_cve_2019_1388.yaml) |
| Greenbug Espionage Group Indicators | 🔴 critical | 90 | `T1059.001`, `T1105`, `T1036.005` | [`greenbug_espionage_group_indicators.yaml`](./greenbug_espionage_group_indicators.yaml) |
| Griffon Malware Attack Pattern | 🔴 critical | 90 | — | [`griffon_malware_attack_pattern.yaml`](./griffon_malware_attack_pattern.yaml) |
| HackTool - DInjector PowerShell Cradle Execution | 🔴 critical | 90 | `T1055` | [`hacktool_dinjector_powershell_cradle_execution.yaml`](./hacktool_dinjector_powershell_cradle_execution.yaml) |
| HackTool - Dumpert Process Dumper Execution | 🔴 critical | 90 | `T1003.001` | [`hacktool_dumpert_process_dumper_execution.yaml`](./hacktool_dumpert_process_dumper_execution.yaml) |
| HackTool - Empire PowerShell UAC Bypass | 🔴 critical | 90 | `T1548.002` | [`hacktool_empire_powershell_uac_bypass.yaml`](./hacktool_empire_powershell_uac_bypass.yaml) |
| HackTool - F-Secure C3 Load by Rundll32 | 🔴 critical | 90 | `T1218.011` | [`hacktool_f_secure_c3_load_by_rundll32.yaml`](./hacktool_f_secure_c3_load_by_rundll32.yaml) |
| HackTool - Inveigh Execution | 🔴 critical | 90 | `T1003.001` | [`hacktool_inveigh_execution.yaml`](./hacktool_inveigh_execution.yaml) |
| HackTool - PurpleSharp Execution | 🔴 critical | 90 | `T1587` | [`hacktool_purplesharp_execution.yaml`](./hacktool_purplesharp_execution.yaml) |
| HackTool - Rubeus Execution | 🔴 critical | 90 | `T1003`, `T1558.003`, `T1550.003` | [`hacktool_rubeus_execution.yaml`](./hacktool_rubeus_execution.yaml) |
| HackTool - SafetyKatz Execution | 🔴 critical | 90 | `T1003.001` | [`hacktool_safetykatz_execution.yaml`](./hacktool_safetykatz_execution.yaml) |
| HackTool - SecurityXploded Execution | 🔴 critical | 90 | `T1555` | [`hacktool_securityxploded_execution.yaml`](./hacktool_securityxploded_execution.yaml) |
| HackTool - SharpUp PrivEsc Tool Execution | 🔴 critical | 90 | `T1615`, `T1569.002`, `T1574.005` | [`hacktool_sharpup_privesc_tool_execution.yaml`](./hacktool_sharpup_privesc_tool_execution.yaml) |
| HackTool - Sliver C2 Implant Activity Pattern | 🔴 critical | 90 | `T1059` | [`hacktool_sliver_c2_implant_activity_pattern.yaml`](./hacktool_sliver_c2_implant_activity_pattern.yaml) |
| HackTool - SysmonEOP Execution | 🔴 critical | 90 | `T1068` | [`hacktool_sysmoneop_execution.yaml`](./hacktool_sysmoneop_execution.yaml) |
| HackTool - Windows Credential Editor (WCE) Execution | 🔴 critical | 90 | `T1003.001` | [`hacktool_windows_credential_editor_wce_execution.yaml`](./hacktool_windows_credential_editor_wce_execution.yaml) |
| Hacktool Execution - Imphash | 🔴 critical | 90 | `T1588.002`, `T1003` | [`hacktool_execution_imphash.yaml`](./hacktool_execution_imphash.yaml) |
| HAFNIUM Exchange Exploitation Activity | 🔴 critical | 90 | `T1546`, `T1053` | [`hafnium_exchange_exploitation_activity.yaml`](./hafnium_exchange_exploitation_activity.yaml) |
| Impacket Lateral Movement smbexec CommandLine Parameters | 🔴 critical | 90 | `T1021.002`, `T1021.003`, `T1047`… | [`impacket_lateral_movement_smbexec_commandline_parameters.yaml`](./impacket_lateral_movement_smbexec_commandline_parameters.yaml) |
| Impacket Lateral Movement WMIExec Commandline Parameters | 🔴 critical | 90 | `T1021.002`, `T1021.003`, `T1047`… | [`impacket_lateral_movement_wmiexec_commandline_parameters.yaml`](./impacket_lateral_movement_wmiexec_commandline_parameters.yaml) |
| Lazarus Group Activity | 🔴 critical | 90 | `T1059` | [`lazarus_group_activity.yaml`](./lazarus_group_activity.yaml) |
| LockerGoga Ransomware Activity | 🔴 critical | 90 | `T1486` | [`lockergoga_ransomware_activity.yaml`](./lockergoga_ransomware_activity.yaml) |
| Mint Sandstorm - AsperaFaspex Suspicious Process Execution | 🔴 critical | 90 | — | [`mint_sandstorm_asperafaspex_suspicious_process_execution.yaml`](./mint_sandstorm_asperafaspex_suspicious_process_execution.yaml) |
| Mint Sandstorm - ManageEngine Suspicious Process Execution | 🔴 critical | 90 | — | [`mint_sandstorm_manageengine_suspicious_process_execution.yaml`](./mint_sandstorm_manageengine_suspicious_process_execution.yaml) |
| OilRig APT Activity | 🔴 critical | 90 | `T1053.005`, `T1543.003`, `T1112`… | [`oilrig_apt_activity.yaml`](./oilrig_apt_activity.yaml) |
| Persistence Via Sticky Key Backdoor | 🔴 critical | 90 | `T1546.008` | [`persistence_via_sticky_key_backdoor.yaml`](./persistence_via_sticky_key_backdoor.yaml) |
| Potential Conti Ransomware Activity | 🔴 critical | 90 | `T1486` | [`potential_conti_ransomware_activity.yaml`](./potential_conti_ransomware_activity.yaml) |
| Potential Credential Dumping Via LSASS Process Clone | 🔴 critical | 90 | `T1003`, `T1003.001` | [`potential_credential_dumping_via_lsass_process_clone.yaml`](./potential_credential_dumping_via_lsass_process_clone.yaml) |
| Potential CVE-2021-41379 Exploitation Attempt | 🔴 critical | 90 | `T1068` | [`potential_cve_2021_41379_exploitation_attempt.yaml`](./potential_cve_2021_41379_exploitation_attempt.yaml) |
| Potential Dridex Activity | 🔴 critical | 90 | `T1055`, `T1135`, `T1033` | [`potential_dridex_activity.yaml`](./potential_dridex_activity.yaml) |
| Potential Dtrack RAT Activity | 🔴 critical | 90 | `T1490` | [`potential_dtrack_rat_activity.yaml`](./potential_dtrack_rat_activity.yaml) |
| Potential Emotet Rundll32 Execution | 🔴 critical | 90 | `T1218.011` | [`potential_emotet_rundll32_execution.yaml`](./potential_emotet_rundll32_execution.yaml) |
| Potential Maze Ransomware Activity | 🔴 critical | 90 | `T1204.002`, `T1047`, `T1490` | [`potential_maze_ransomware_activity.yaml`](./potential_maze_ransomware_activity.yaml) |
| Potential QBot Activity | 🔴 critical | 90 | `T1059.005` | [`potential_qbot_activity.yaml`](./potential_qbot_activity.yaml) |
| Potential Russian APT Credential Theft Activity | 🔴 critical | 90 | `T1552.001`, `T1003.003` | [`potential_russian_apt_credential_theft_activity.yaml`](./potential_russian_apt_credential_theft_activity.yaml) |
| Potential SMB Relay Attack Tool Execution | 🔴 critical | 90 | `T1557.001` | [`potential_smb_relay_attack_tool_execution.yaml`](./potential_smb_relay_attack_tool_execution.yaml) |
| Potential SystemNightmare Exploitation Attempt | 🔴 critical | 90 | `T1068` | [`potential_systemnightmare_exploitation_attempt.yaml`](./potential_systemnightmare_exploitation_attempt.yaml) |
| Qakbot Rundll32 Exports Execution | 🔴 critical | 90 | — | [`qakbot_rundll32_exports_execution.yaml`](./qakbot_rundll32_exports_execution.yaml) |
| Qakbot Rundll32 Fake DLL Extension Execution | 🔴 critical | 90 | — | [`qakbot_rundll32_fake_dll_extension_execution.yaml`](./qakbot_rundll32_fake_dll_extension_execution.yaml) |
| Renamed Whoami Execution | 🔴 critical | 90 | `T1033` | [`renamed_whoami_execution.yaml`](./renamed_whoami_execution.yaml) |
| REvil Kaseya Incident Malware Patterns | 🔴 critical | 90 | `T1059` | [`revil_kaseya_incident_malware_patterns.yaml`](./revil_kaseya_incident_malware_patterns.yaml) |
| Rorschach Ransomware Execution Activity | 🔴 critical | 90 | `T1059.003`, `T1059.001` | [`rorschach_ransomware_execution_activity.yaml`](./rorschach_ransomware_execution_activity.yaml) |
| Serv-U Exploitation CVE-2021-35211 by DEV-0322 | 🔴 critical | 90 | `T1136.001` | [`serv_u_exploitation_cve_2021_35211_by_dev_0322.yaml`](./serv_u_exploitation_cve_2021_35211_by_dev_0322.yaml) |
| Sticky Key Like Backdoor Execution | 🔴 critical | 90 | `T1546.008` | [`sticky_key_like_backdoor_execution.yaml`](./sticky_key_like_backdoor_execution.yaml) |
| Suspicious Child Process Of Veeam Dabatase | 🔴 critical | 90 | — | [`suspicious_child_process_of_veeam_dabatase.yaml`](./suspicious_child_process_of_veeam_dabatase.yaml) |
| Suspicious PowerShell Mailbox Export to Share | 🔴 critical | 90 | — | [`suspicious_powershell_mailbox_export_to_share.yaml`](./suspicious_powershell_mailbox_export_to_share.yaml) |
| TrustedPath UAC Bypass Pattern | 🔴 critical | 90 | `T1548.002` | [`trustedpath_uac_bypass_pattern.yaml`](./trustedpath_uac_bypass_pattern.yaml) |
| Turla Group Commands May 2020 | 🔴 critical | 90 | `T1059.001`, `T1053.005`, `T1027` | [`turla_group_commands_may_2020.yaml`](./turla_group_commands_may_2020.yaml) |
| Turla Group Lateral Movement | 🔴 critical | 90 | `T1059`, `T1021.002`, `T1083`… | [`turla_group_lateral_movement.yaml`](./turla_group_lateral_movement.yaml) |
| UNC2452 PowerShell Pattern | 🔴 critical | 90 | `T1059.001`, `T1047` | [`unc2452_powershell_pattern.yaml`](./unc2452_powershell_pattern.yaml) |
| WannaCry Ransomware Activity | 🔴 critical | 90 | `T1210`, `T1083`, `T1222.001`… | [`wannacry_ransomware_activity.yaml`](./wannacry_ransomware_activity.yaml) |
| Windows Apache Benchmark Binary | 🔴 critical | 100 | `T1059` | [`windows_apache_benchmark_binary.yaml`](./windows_apache_benchmark_binary.yaml) |
| Windows DISM Remove Defender | 🔴 critical | 80 | `T1562.001` | [`windows_dism_remove_defender.yaml`](./windows_dism_remove_defender.yaml) |
| Windows Execute Arbitrary Commands with MSDT | 🔴 critical | 90 | `T1218` | [`windows_execute_arbitrary_commands_with_msdt.yaml`](./windows_execute_arbitrary_commands_with_msdt.yaml) |
| Windows Global Object Access Audit List Cleared Via Auditpol | 🔴 critical | 85 | `T1562.002` | [`windows_global_object_access_audit_list_cleared_via_auditpol.yaml`](./windows_global_object_access_audit_list_cleared_via_auditpol.yaml) |
| Windows InstallUtil URL in Command Line | 🔴 critical | 80 | `T1218.004` | [`windows_installutil_url_in_command_line.yaml`](./windows_installutil_url_in_command_line.yaml) |
| Windows Mimikatz Binary Execution | 🔴 critical | 100 | `T1003` | [`windows_mimikatz_binary_execution.yaml`](./windows_mimikatz_binary_execution.yaml) |
| Windows WSUS Spawning Shell | 🔴 critical | 90 | `T1190`, `T1505.003` | [`windows_wsus_spawning_shell.yaml`](./windows_wsus_spawning_shell.yaml) |
| Winnti Malware HK University Campaign | 🔴 critical | 90 | `T1574.001` | [`winnti_malware_hk_university_campaign.yaml`](./winnti_malware_hk_university_campaign.yaml) |
| Winnti Pipemon Characteristics | 🔴 critical | 90 | `T1574.001` | [`winnti_pipemon_characteristics.yaml`](./winnti_pipemon_characteristics.yaml) |
| WMI Backdoor Exchange Transport Agent | 🔴 critical | 90 | `T1546.003` | [`wmi_backdoor_exchange_transport_agent.yaml`](./wmi_backdoor_exchange_transport_agent.yaml) |
| ZxShell Malware | 🔴 critical | 90 | `T1059.003`, `T1218.011` | [`zxshell_malware.yaml`](./zxshell_malware.yaml) |
| AADInternals PowerShell Cmdlets Execution - ProccessCreation | 🟠 high | 75 | — | [`aadinternals_powershell_cmdlets_execution_proccesscreation.yaml`](./aadinternals_powershell_cmdlets_execution_proccesscreation.yaml) |
| Abuse of Service Permissions to Hide Services Via Set-Service | 🟠 high | 75 | `T1574.011` | [`abuse_of_service_permissions_to_hide_services_via_set_service.yaml`](./abuse_of_service_permissions_to_hide_services_via_set_service.yaml) |
| Abused Debug Privilege by Arbitrary Parent Processes | 🟠 high | 75 | `T1548` | [`abused_debug_privilege_by_arbitrary_parent_processes.yaml`](./abused_debug_privilege_by_arbitrary_parent_processes.yaml) |
| Add Insecure Download Source To Winget | 🟠 high | 75 | `T1059` | [`add_insecure_download_source_to_winget.yaml`](./add_insecure_download_source_to_winget.yaml) |
| Add SafeBoot Keys Via Reg Utility | 🟠 high | 75 | `T1685` | [`add_safeboot_keys_via_reg_utility.yaml`](./add_safeboot_keys_via_reg_utility.yaml) |
| Adwind RAT / JRAT | 🟠 high | 75 | `T1059.005`, `T1059.007` | [`adwind_rat_jrat.yaml`](./adwind_rat_jrat.yaml) |
| All Backups Deleted Via Wbadmin.EXE | 🟠 high | 75 | `T1490` | [`all_backups_deleted_via_wbadmin_exe.yaml`](./all_backups_deleted_via_wbadmin_exe.yaml) |
| Allow Service Access Using Security Descriptor Tampering Via Sc.EXE | 🟠 high | 75 | `T1543.003` | [`allow_service_access_using_security_descriptor_tampering_via_sc_exe.yaml`](./allow_service_access_using_security_descriptor_tampering_via_sc_exe.yaml) |
| Arbitrary File Download Via IMEWDBLD.EXE | 🟠 high | 75 | `T1218` | [`arbitrary_file_download_via_imewdbld_exe.yaml`](./arbitrary_file_download_via_imewdbld_exe.yaml) |
| Attempts of Kerberos Coercion Via DNS SPN Spoofing | 🟠 high | 75 | `T1557.001`, `T1187` | [`attempts_of_kerberos_coercion_via_dns_spn_spoofing.yaml`](./attempts_of_kerberos_coercion_via_dns_spn_spoofing.yaml) |
| Audit Policy Tampering Via Auditpol | 🟠 high | 75 | `T1685.001` | [`audit_policy_tampering_via_auditpol.yaml`](./audit_policy_tampering_via_auditpol.yaml) |
| Audit Policy Tampering Via NT Resource Kit Auditpol | 🟠 high | 75 | `T1685.001` | [`audit_policy_tampering_via_nt_resource_kit_auditpol.yaml`](./audit_policy_tampering_via_nt_resource_kit_auditpol.yaml) |
| Axios NPM Compromise Indicators - Windows | 🟠 high | 75 | `T1195.002`, `T1059.003`, `T1059.005`… | [`axios_npm_compromise_indicators_windows.yaml`](./axios_npm_compromise_indicators_windows.yaml) |
| Bad Opsec Defaults Sacrificial Processes With Improper Arguments | 🟠 high | 75 | `T1218.011` | [`bad_opsec_defaults_sacrificial_processes_with_improper_arguments.yaml`](./bad_opsec_defaults_sacrificial_processes_with_improper_arguments.yaml) |
| Base64 Encoded PowerShell Command Detected | 🟠 high | 75 | `T1027`, `T1140`, `T1059.001` | [`base64_encoded_powershell_command_detected.yaml`](./base64_encoded_powershell_command_detected.yaml) |
| Base64 MZ Header In CommandLine | 🟠 high | 75 | — | [`base64_mz_header_in_commandline.yaml`](./base64_mz_header_in_commandline.yaml) |
| Blue Mockingbird | 🟠 high | 75 | `T1112`, `T1047` | [`blue_mockingbird.yaml`](./blue_mockingbird.yaml) |
| Boot Configuration Tampering Via Bcdedit.EXE | 🟠 high | 75 | `T1490` | [`boot_configuration_tampering_via_bcdedit_exe.yaml`](./boot_configuration_tampering_via_bcdedit_exe.yaml) |
| Bypass UAC via CMSTP | 🟠 high | 75 | `T1548.002`, `T1218.003` | [`bypass_uac_via_cmstp.yaml`](./bypass_uac_via_cmstp.yaml) |
| Bypass UAC via Fodhelper.exe | 🟠 high | 75 | `T1548.002` | [`bypass_uac_via_fodhelper_exe.yaml`](./bypass_uac_via_fodhelper_exe.yaml) |
| Bypass UAC via WSReset.exe | 🟠 high | 75 | `T1548.002` | [`bypass_uac_via_wsreset_exe.yaml`](./bypass_uac_via_wsreset_exe.yaml) |
| Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths | 🟠 high | 75 | — | [`cab_file_extraction_via_wusa_exe_from_potentially_suspicious_paths.yaml`](./cab_file_extraction_via_wusa_exe_from_potentially_suspicious_paths.yaml) |
| Change Default File Association To Executable Via Assoc | 🟠 high | 75 | `T1546.001` | [`change_default_file_association_to_executable_via_assoc.yaml`](./change_default_file_association_to_executable_via_assoc.yaml) |
| Chopper Webshell Process Pattern | 🟠 high | 75 | `T1505.003`, `T1018`, `T1033`… | [`chopper_webshell_process_pattern.yaml`](./chopper_webshell_process_pattern.yaml) |
| ChromeLoader Malware Execution | 🟠 high | 75 | `T1053.005`, `T1059.001`, `T1176` | [`chromeloader_malware_execution.yaml`](./chromeloader_malware_execution.yaml) |
| Chromium Browser Headless Execution To Mockbin Like Site | 🟠 high | 75 | — | [`chromium_browser_headless_execution_to_mockbin_like_site.yaml`](./chromium_browser_headless_execution_to_mockbin_like_site.yaml) |
| Cmd.EXE Missing Space Characters Execution Anomaly | 🟠 high | 75 | `T1059.001` | [`cmd_exe_missing_space_characters_execution_anomaly.yaml`](./cmd_exe_missing_space_characters_execution_anomaly.yaml) |
| CMSTP Execution Process Creation | 🟠 high | 75 | `T1218.003` | [`cmstp_execution_process_creation.yaml`](./cmstp_execution_process_creation.yaml) |
| CMSTP UAC Bypass via COM Object Access | 🟠 high | 75 | `T1548.002`, `T1218.003` | [`cmstp_uac_bypass_via_com_object_access.yaml`](./cmstp_uac_bypass_via_com_object_access.yaml) |
| CobaltStrike Load by Rundll32 | 🟠 high | 75 | `T1218.011` | [`cobaltstrike_load_by_rundll32.yaml`](./cobaltstrike_load_by_rundll32.yaml) |
| COLDSTEEL RAT Anonymous User Process Execution | 🟠 high | 75 | — | [`coldsteel_rat_anonymous_user_process_execution.yaml`](./coldsteel_rat_anonymous_user_process_execution.yaml) |
| Commvault QLogin Argument Injection Authentication Bypass (CVE-2025-57791) | 🟠 high | 75 | `T1190` | [`commvault_qlogin_argument_injection_authentication_bypass_cve_2025_57791.yaml`](./commvault_qlogin_argument_injection_authentication_bypass_cve_2025_57791.yaml) |
| Commvault QOperation Path Traversal Webshell Drop (CVE-2025-57790) | 🟠 high | 75 | `T1505.003` | [`commvault_qoperation_path_traversal_webshell_drop_cve_2025_57790.yaml`](./commvault_qoperation_path_traversal_webshell_drop_cve_2025_57790.yaml) |
| Conhost.exe CommandLine Path Traversal | 🟠 high | 75 | `T1059.003` | [`conhost_exe_commandline_path_traversal.yaml`](./conhost_exe_commandline_path_traversal.yaml) |
| Conti NTDS Exfiltration Command | 🟠 high | 75 | `T1560` | [`conti_ntds_exfiltration_command.yaml`](./conti_ntds_exfiltration_command.yaml) |
| Conti Volume Shadow Listing | 🟠 high | 75 | `T1587.001` | [`conti_volume_shadow_listing.yaml`](./conti_volume_shadow_listing.yaml) |
| Control Panel Items | 🟠 high | 75 | `T1218.002`, `T1546` | [`control_panel_items.yaml`](./control_panel_items.yaml) |
| Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE | 🟠 high | 75 | — | [`copy_dmp_dump_files_from_remote_share_via_cmd_exe.yaml`](./copy_dmp_dump_files_from_remote_share_via_cmd_exe.yaml) |
| Copy From VolumeShadowCopy Via Cmd.EXE | 🟠 high | 75 | `T1490` | [`copy_from_volumeshadowcopy_via_cmd_exe.yaml`](./copy_from_volumeshadowcopy_via_cmd_exe.yaml) |
| Copying Sensitive Files with Credential Data | 🟠 high | 75 | `T1003.002`, `T1003.003` | [`copying_sensitive_files_with_credential_data.yaml`](./copying_sensitive_files_with_credential_data.yaml) |
| CreateDump Process Dump | 🟠 high | 75 | `T1036`, `T1003.001` | [`createdump_process_dump.yaml`](./createdump_process_dump.yaml) |
| Cscript/Wscript Uncommon Script Extension Execution | 🟠 high | 75 | `T1059.005`, `T1059.007` | [`cscript_wscript_uncommon_script_extension_execution.yaml`](./cscript_wscript_uncommon_script_extension_execution.yaml) |
| Curl Download And Execute Combination | 🟠 high | 75 | `T1218`, `T1105` | [`curl_download_and_execute_combination.yaml`](./curl_download_and_execute_combination.yaml) |
| Curl File Upload To File Sharing Websites | 🟠 high | 75 | `T1567.002` | [`curl_file_upload_to_file_sharing_websites.yaml`](./curl_file_upload_to_file_sharing_websites.yaml) |
| CVE-2023-38331 Exploitation Attempt - Suspicious WinRAR Child Process | 🟠 high | 75 | `T1203` | [`cve_2023_38331_exploitation_attempt_suspicious_winrar_child_process.yaml`](./cve_2023_38331_exploitation_attempt_suspicious_winrar_child_process.yaml) |
| CVE-2024-50623 Exploitation Attempt - Cleo | 🟠 high | 75 | `T1190` | [`cve_2024_50623_exploitation_attempt_cleo.yaml`](./cve_2024_50623_exploitation_attempt_cleo.yaml) |
| DarkGate - Autoit3.EXE Execution Parameters | 🟠 high | 75 | `T1059` | [`darkgate_autoit3_exe_execution_parameters.yaml`](./darkgate_autoit3_exe_execution_parameters.yaml) |
| DarkGate - User Created Via Net.EXE | 🟠 high | 75 | `T1136.001` | [`darkgate_user_created_via_net_exe.yaml`](./darkgate_user_created_via_net_exe.yaml) |
| Delete All Scheduled Tasks | 🟠 high | 75 | `T1489` | [`delete_all_scheduled_tasks.yaml`](./delete_all_scheduled_tasks.yaml) |
| Delete Important Scheduled Task | 🟠 high | 75 | `T1489` | [`delete_important_scheduled_task.yaml`](./delete_important_scheduled_task.yaml) |
| Deletion of Volume Shadow Copies via WMI with PowerShell | 🟠 high | 75 | `T1490` | [`deletion_of_volume_shadow_copies_via_wmi_with_powershell.yaml`](./deletion_of_volume_shadow_copies_via_wmi_with_powershell.yaml) |
| Deny Service Access Using Security Descriptor Tampering Via Sc.EXE | 🟠 high | 75 | `T1543.003` | [`deny_service_access_using_security_descriptor_tampering_via_sc_exe.yaml`](./deny_service_access_using_security_descriptor_tampering_via_sc_exe.yaml) |
| Detect mshta inline hta execution | 🟠 high | 60 | `T1218.005` | [`detect_mshta_inline_hta_execution.yaml`](./detect_mshta_inline_hta_execution.yaml) |
| Detect mshta renamed | 🟠 high | 70 | `T1218.005` | [`detect_mshta_renamed.yaml`](./detect_mshta_renamed.yaml) |
| Detect MSHTA Url in Command Line | 🟠 high | 65 | `T1218.005` | [`detect_mshta_url_in_command_line.yaml`](./detect_mshta_url_in_command_line.yaml) |
| Detect Path Interception By Creation Of program exe | 🟠 high | 70 | `T1574.009` | [`detect_path_interception_by_creation_of_program_exe.yaml`](./detect_path_interception_by_creation_of_program_exe.yaml) |
| Detect RClone Command-Line Usage | 🟠 high | 64 | `T1020` | [`detect_rclone_command_line_usage.yaml`](./detect_rclone_command_line_usage.yaml) |
| Detect Regasm Spawning a Process | 🟠 high | 64 | `T1218.009` | [`detect_regasm_spawning_a_process.yaml`](./detect_regasm_spawning_a_process.yaml) |
| Detect Regasm with no Command Line Arguments | 🟠 high | 72 | `T1218.009` | [`detect_regasm_with_no_command_line_arguments.yaml`](./detect_regasm_with_no_command_line_arguments.yaml) |
| Detect Regsvcs Spawning a Process | 🟠 high | 64 | `T1218.009` | [`detect_regsvcs_spawning_a_process.yaml`](./detect_regsvcs_spawning_a_process.yaml) |
| Detect Regsvcs with No Command Line Arguments | 🟠 high | 72 | `T1218.009` | [`detect_regsvcs_with_no_command_line_arguments.yaml`](./detect_regsvcs_with_no_command_line_arguments.yaml) |
| Detect Regsvr32 Application Control Bypass | 🟠 high | 72 | `T1218.010` | [`detect_regsvr32_application_control_bypass.yaml`](./detect_regsvr32_application_control_bypass.yaml) |
| Detect Renamed PSExec | 🟠 high | 80 | `T1569.002` | [`detect_renamed_psexec.yaml`](./detect_renamed_psexec.yaml) |
| Detect Renamed RClone | 🟠 high | 80 | `T1020` | [`detect_renamed_rclone.yaml`](./detect_renamed_rclone.yaml) |
| Detect Renamed WinRAR | 🟠 high | 72 | `T1560.001` | [`detect_renamed_winrar.yaml`](./detect_renamed_winrar.yaml) |
| Detect RTLO In Process | 🟠 high | 80 | `T1036.002` | [`detect_rtlo_in_process.yaml`](./detect_rtlo_in_process.yaml) |
| Detect Rundll32 Inline HTA Execution | 🟠 high | 80 | `T1218.005` | [`detect_rundll32_inline_hta_execution.yaml`](./detect_rundll32_inline_hta_execution.yaml) |
| Detect SharpHound Command-Line Arguments | 🟠 high | 72 | `T1069.001`, `T1069.002`, `T1087.001`… | [`detect_sharphound_command_line_arguments.yaml`](./detect_sharphound_command_line_arguments.yaml) |
| Detect SharpHound Usage | 🟠 high | 72 | `T1069.001`, `T1069.002`, `T1087.001`… | [`detect_sharphound_usage.yaml`](./detect_sharphound_usage.yaml) |
| Devcon Execution Disabling VMware VMCI Device | 🟠 high | 75 | `T1543.003`, `T1685` | [`devcon_execution_disabling_vmware_vmci_device.yaml`](./devcon_execution_disabling_vmware_vmci_device.yaml) |
| Devtoolslauncher.exe Executes Specified Binary | 🟠 high | 75 | `T1218` | [`devtoolslauncher_exe_executes_specified_binary.yaml`](./devtoolslauncher_exe_executes_specified_binary.yaml) |
| Diamond Sleet APT Process Activity Indicators | 🟠 high | 75 | — | [`diamond_sleet_apt_process_activity_indicators.yaml`](./diamond_sleet_apt_process_activity_indicators.yaml) |
| Disable Important Scheduled Task | 🟠 high | 75 | `T1489` | [`disable_important_scheduled_task.yaml`](./disable_important_scheduled_task.yaml) |
| Disable Logs Using WevtUtil | 🟠 high | 80 | `T1070.001` | [`disable_logs_using_wevtutil.yaml`](./disable_logs_using_wevtutil.yaml) |
| Disable Windows Defender AV Security Monitoring | 🟠 high | 75 | `T1685` | [`disable_windows_defender_av_security_monitoring.yaml`](./disable_windows_defender_av_security_monitoring.yaml) |
| Disable Windows IIS HTTP Logging | 🟠 high | 75 | `T1685.001` | [`disable_windows_iis_http_logging.yaml`](./disable_windows_iis_http_logging.yaml) |
| Disabled IE Security Features | 🟠 high | 75 | `T1685` | [`disabled_ie_security_features.yaml`](./disabled_ie_security_features.yaml) |
| Disabled Volume Snapshots | 🟠 high | 75 | `T1685` | [`disabled_volume_snapshots.yaml`](./disabled_volume_snapshots.yaml) |
| Disabling Windows Defender WMI Autologger Session via Reg.exe | 🟠 high | 75 | `T1685` | [`disabling_windows_defender_wmi_autologger_session_via_reg_exe.yaml`](./disabling_windows_defender_wmi_autologger_session_via_reg_exe.yaml) |
| DLL Sideloading by VMware Xfer Utility | 🟠 high | 75 | `T1574.001` | [`dll_sideloading_by_vmware_xfer_utility.yaml`](./dll_sideloading_by_vmware_xfer_utility.yaml) |
| Dllhost.EXE Execution Anomaly | 🟠 high | 75 | `T1055` | [`dllhost_exe_execution_anomaly.yaml`](./dllhost_exe_execution_anomaly.yaml) |
| DNS Exfiltration and Tunneling Tools Execution | 🟠 high | 75 | `T1048.001`, `T1071.004`, `T1132.001` | [`dns_exfiltration_and_tunneling_tools_execution.yaml`](./dns_exfiltration_and_tunneling_tools_execution.yaml) |
| Domain Account Discovery with Wmic | 🟠 high | 80 | `T1087.002`, `T1047` | [`domain_account_discovery_with_wmic.yaml`](./domain_account_discovery_with_wmic.yaml) |
| Domain Controller Discovery with Nltest | 🟠 high | 72 | `T1018` | [`domain_controller_discovery_with_nltest.yaml`](./domain_controller_discovery_with_nltest.yaml) |
| Domain Group Discovery With Wmic | 🟠 high | 72 | `T1069.002`, `T1047` | [`domain_group_discovery_with_wmic.yaml`](./domain_group_discovery_with_wmic.yaml) |
| DSInternals Suspicious PowerShell Cmdlets | 🟠 high | 75 | `T1059.001` | [`dsinternals_suspicious_powershell_cmdlets.yaml`](./dsinternals_suspicious_powershell_cmdlets.yaml) |
| DSQuery Domain Discovery | 🟠 high | 72 | `T1482` | [`dsquery_domain_discovery.yaml`](./dsquery_domain_discovery.yaml) |
| Dumping of Sensitive Hives Via Reg.EXE | 🟠 high | 75 | `T1003.002`, `T1003.004`, `T1003.005` | [`dumping_of_sensitive_hives_via_reg_exe.yaml`](./dumping_of_sensitive_hives_via_reg_exe.yaml) |
| Elevated Group Discovery With Wmic | 🟠 high | 80 | `T1069.002`, `T1047` | [`elevated_group_discovery_with_wmic.yaml`](./elevated_group_discovery_with_wmic.yaml) |
| Email Exifiltration Via Powershell | 🟠 high | 75 | — | [`email_exifiltration_via_powershell.yaml`](./email_exifiltration_via_powershell.yaml) |
| Emotet Loader Execution Via .LNK File | 🟠 high | 75 | `T1059.006` | [`emotet_loader_execution_via_lnk_file.yaml`](./emotet_loader_execution_via_lnk_file.yaml) |
| Enable LM Hash Storage - ProcCreation | 🟠 high | 75 | `T1112` | [`enable_lm_hash_storage_proccreation.yaml`](./enable_lm_hash_storage_proccreation.yaml) |
| Esentutl SAM Copy | 🟠 high | 80 | `T1003.002`, `T1003.003` | [`esentutl_sam_copy.yaml`](./esentutl_sam_copy.yaml) |
| ETW Logging Tamper In .NET Processes Via CommandLine | 🟠 high | 75 | `T1685` | [`etw_logging_tamper_in_net_processes_via_commandline.yaml`](./etw_logging_tamper_in_net_processes_via_commandline.yaml) |
| ETW Trace Evasion Activity | 🟠 high | 75 | `T1070`, `T1685` | [`etw_trace_evasion_activity.yaml`](./etw_trace_evasion_activity.yaml) |
| Exchange PowerShell Snap-Ins Usage | 🟠 high | 75 | `T1059.001`, `T1114` | [`exchange_powershell_snap_ins_usage.yaml`](./exchange_powershell_snap_ins_usage.yaml) |
| Execute Javascript With Jscript COM CLSID | 🟠 high | 80 | `T1059.005`, `T1059.007` | [`execute_javascript_with_jscript_com_clsid.yaml`](./execute_javascript_with_jscript_com_clsid.yaml) |
| Execute Pcwrun.EXE To Leverage Follina | 🟠 high | 75 | `T1218` | [`execute_pcwrun_exe_to_leverage_follina.yaml`](./execute_pcwrun_exe_to_leverage_follina.yaml) |
| Execution of File with Multiple Extensions | 🟠 high | 80 | `T1036.003`, `T1036.007` | [`execution_of_file_with_multiple_extensions.yaml`](./execution_of_file_with_multiple_extensions.yaml) |
| Execution Of Non-Existing File | 🟠 high | 75 | `T1055` | [`execution_of_non_existing_file.yaml`](./execution_of_non_existing_file.yaml) |
| Execution of Powershell Script in Public Folder | 🟠 high | 75 | `T1059.001` | [`execution_of_powershell_script_in_public_folder.yaml`](./execution_of_powershell_script_in_public_folder.yaml) |
| Execution via stordiag.exe | 🟠 high | 75 | `T1218` | [`execution_via_stordiag_exe.yaml`](./execution_via_stordiag_exe.yaml) |
| Execution via WorkFolders.exe | 🟠 high | 75 | `T1218` | [`execution_via_workfolders_exe.yaml`](./execution_via_workfolders_exe.yaml) |
| Exploitation Activity of CVE-2025-59287 - WSUS Suspicious Child Process | 🟠 high | 75 | `T1190`, `T1203` | [`exploitation_activity_of_cve_2025_59287_wsus_suspicious_child_process.yaml`](./exploitation_activity_of_cve_2025_59287_wsus_suspicious_child_process.yaml) |
| Exploitation Attempt Of CVE-2020-1472 - Execution of ZeroLogon PoC | 🟠 high | 75 | `T1210` | [`exploitation_attempt_of_cve_2020_1472_execution_of_zerologon_poc.yaml`](./exploitation_attempt_of_cve_2020_1472_execution_of_zerologon_poc.yaml) |
| Exploited CVE-2020-10189 Zoho ManageEngine | 🟠 high | 75 | `T1190`, `T1059.001`, `T1059.003` | [`exploited_cve_2020_10189_zoho_manageengine.yaml`](./exploited_cve_2020_10189_zoho_manageengine.yaml) |
| Exploiting SetupComplete.cmd CVE-2019-1378 | 🟠 high | 75 | `T1068`, `T1059.003`, `T1574` | [`exploiting_setupcomplete_cmd_cve_2019_1378.yaml`](./exploiting_setupcomplete_cmd_cve_2019_1378.yaml) |
| Explorer NOUACCHECK Flag | 🟠 high | 75 | `T1548.002` | [`explorer_nouaccheck_flag.yaml`](./explorer_nouaccheck_flag.yaml) |
| Exports Critical Registry Keys To a File | 🟠 high | 75 | `T1012` | [`exports_critical_registry_keys_to_a_file.yaml`](./exports_critical_registry_keys_to_a_file.yaml) |
| FakeUpdates/SocGholish Activity | 🟠 high | 75 | `T1059.001` | [`fakeupdates_socgholish_activity.yaml`](./fakeupdates_socgholish_activity.yaml) |
| File Decoded From Base64/Hex Via Certutil.EXE | 🟠 high | 75 | `T1027` | [`file_decoded_from_base64_hex_via_certutil_exe.yaml`](./file_decoded_from_base64_hex_via_certutil_exe.yaml) |
| File Download And Execution Via IEExec.EXE | 🟠 high | 75 | `T1105` | [`file_download_and_execution_via_ieexec_exe.yaml`](./file_download_and_execution_via_ieexec_exe.yaml) |
| File Download From IP Based URL Via CertOC.EXE | 🟠 high | 75 | `T1105` | [`file_download_from_ip_based_url_via_certoc_exe.yaml`](./file_download_from_ip_based_url_via_certoc_exe.yaml) |
| File Download or Read to Pipe Execution | 🟠 high | 80 | `T1105`, `T1059.001`, `T1059.004` | [`file_download_or_read_to_pipe_execution.yaml`](./file_download_or_read_to_pipe_execution.yaml) |
| File Download Using Notepad++ GUP Utility | 🟠 high | 75 | `T1105` | [`file_download_using_notepad_gup_utility.yaml`](./file_download_using_notepad_gup_utility.yaml) |
| File Download Via Bitsadmin To A Suspicious Target Folder | 🟠 high | 75 | `T1197`, `T1036.003`, `T1105` | [`file_download_via_bitsadmin_to_a_suspicious_target_folder.yaml`](./file_download_via_bitsadmin_to_a_suspicious_target_folder.yaml) |
| File Download Via Windows Defender MpCmpRun.EXE | 🟠 high | 75 | `T1218`, `T1105` | [`file_download_via_windows_defender_mpcmprun_exe.yaml`](./file_download_via_windows_defender_mpcmprun_exe.yaml) |
| File Download with Headless Browser | 🟠 high | 75 | `T1105`, `T1564.003` | [`file_download_with_headless_browser.yaml`](./file_download_with_headless_browser.yaml) |
| File Encryption/Decryption Via Gpg4win From Suspicious Locations | 🟠 high | 75 | — | [`file_encryption_decryption_via_gpg4win_from_suspicious_locations.yaml`](./file_encryption_decryption_via_gpg4win_from_suspicious_locations.yaml) |
| File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell | 🟠 high | 75 | `T1135` | [`file_explorer_folder_opened_using_explorer_folder_shortcut_via_shell.yaml`](./file_explorer_folder_opened_using_explorer_folder_shortcut_via_shell.yaml) |
| File In Suspicious Location Encoded To Base64 Via Certutil.EXE | 🟠 high | 75 | `T1027` | [`file_in_suspicious_location_encoded_to_base64_via_certutil_exe.yaml`](./file_in_suspicious_location_encoded_to_base64_via_certutil_exe.yaml) |
| File With Suspicious Extension Downloaded Via Bitsadmin | 🟠 high | 75 | `T1197`, `T1036.003`, `T1105` | [`file_with_suspicious_extension_downloaded_via_bitsadmin.yaml`](./file_with_suspicious_extension_downloaded_via_bitsadmin.yaml) |
| Findstr GPP Passwords | 🟠 high | 75 | `T1552.006` | [`findstr_gpp_passwords.yaml`](./findstr_gpp_passwords.yaml) |
| Finger.EXE Execution | 🟠 high | 75 | `T1105` | [`finger_exe_execution.yaml`](./finger_exe_execution.yaml) |
| Fireball Archer Install | 🟠 high | 75 | `T1218.011` | [`fireball_archer_install.yaml`](./fireball_archer_install.yaml) |
| FodHelper UAC Bypass | 🟠 high | 80 | `T1548.002`, `T1112` | [`fodhelper_uac_bypass.yaml`](./fodhelper_uac_bypass.yaml) |
| Forest Blizzard APT - Process Creation Activity | 🟠 high | 75 | — | [`forest_blizzard_apt_process_creation_activity.yaml`](./forest_blizzard_apt_process_creation_activity.yaml) |
| Forfiles.EXE Child Process Masquerading | 🟠 high | 75 | `T1036` | [`forfiles_exe_child_process_masquerading.yaml`](./forfiles_exe_child_process_masquerading.yaml) |
| Formbook Process Creation | 🟠 high | 75 | `T1587.001` | [`formbook_process_creation.yaml`](./formbook_process_creation.yaml) |
| Fsutil Suspicious Invocation | 🟠 high | 75 | `T1070`, `T1485` | [`fsutil_suspicious_invocation.yaml`](./fsutil_suspicious_invocation.yaml) |
| Fsutil Zeroing File | 🟠 high | 80 | `T1070`, `T1070.004` | [`fsutil_zeroing_file.yaml`](./fsutil_zeroing_file.yaml) |
| GALLIUM IOCs | 🟠 high | 75 | `T1212`, `T1071` | [`gallium_iocs.yaml`](./gallium_iocs.yaml) |
| Get DomainPolicy with Powershell | 🟠 high | 72 | `T1201` | [`get_domainpolicy_with_powershell.yaml`](./get_domainpolicy_with_powershell.yaml) |
| Get DomainUser with PowerShell | 🟠 high | 72 | `T1087.002` | [`get_domainuser_with_powershell.yaml`](./get_domainuser_with_powershell.yaml) |
| Get-DomainTrust with PowerShell | 🟠 high | 72 | `T1482` | [`get_domaintrust_with_powershell.yaml`](./get_domaintrust_with_powershell.yaml) |
| Get-ForestTrust with PowerShell | 🟠 high | 72 | `T1482` | [`get_foresttrust_with_powershell.yaml`](./get_foresttrust_with_powershell.yaml) |
| GetDomainComputer with PowerShell | 🟠 high | 72 | `T1018` | [`getdomaincomputer_with_powershell.yaml`](./getdomaincomputer_with_powershell.yaml) |
| GetDomainGroup with PowerShell | 🟠 high | 72 | `T1069.002` | [`getdomaingroup_with_powershell.yaml`](./getdomaingroup_with_powershell.yaml) |
| Grixba Malware Reconnaissance Activity | 🟠 high | 75 | `T1595.001`, `T1046` | [`grixba_malware_reconnaissance_activity.yaml`](./grixba_malware_reconnaissance_activity.yaml) |
| HackTool - ADCSPwn Execution | 🟠 high | 75 | `T1557.001` | [`hacktool_adcspwn_execution.yaml`](./hacktool_adcspwn_execution.yaml) |
| HackTool - Bloodhound/Sharphound Execution | 🟠 high | 75 | `T1087.001`, `T1087.002`, `T1482`… | [`hacktool_bloodhound_sharphound_execution.yaml`](./hacktool_bloodhound_sharphound_execution.yaml) |
| HackTool - Certify Execution | 🟠 high | 75 | `T1649` | [`hacktool_certify_execution.yaml`](./hacktool_certify_execution.yaml) |
| HackTool - Certipy Execution | 🟠 high | 75 | `T1649` | [`hacktool_certipy_execution.yaml`](./hacktool_certipy_execution.yaml) |
| HackTool - CoercedPotato Execution | 🟠 high | 75 | `T1055` | [`hacktool_coercedpotato_execution.yaml`](./hacktool_coercedpotato_execution.yaml) |
| HackTool - Covenant PowerShell Launcher | 🟠 high | 75 | `T1059.001`, `T1564.003` | [`hacktool_covenant_powershell_launcher.yaml`](./hacktool_covenant_powershell_launcher.yaml) |
| HackTool - CrackMapExec Execution | 🟠 high | 75 | `T1047`, `T1053`, `T1059.003`… | [`hacktool_crackmapexec_execution.yaml`](./hacktool_crackmapexec_execution.yaml) |
| HackTool - CrackMapExec Execution Patterns | 🟠 high | 75 | `T1047`, `T1053`, `T1059.003`… | [`hacktool_crackmapexec_execution_patterns.yaml`](./hacktool_crackmapexec_execution_patterns.yaml) |
| HackTool - CrackMapExec PowerShell Obfuscation | 🟠 high | 75 | `T1059.001`, `T1027.005` | [`hacktool_crackmapexec_powershell_obfuscation.yaml`](./hacktool_crackmapexec_powershell_obfuscation.yaml) |
| HackTool - CrackMapExec Process Patterns | 🟠 high | 75 | `T1003.001` | [`hacktool_crackmapexec_process_patterns.yaml`](./hacktool_crackmapexec_process_patterns.yaml) |
| HackTool - CreateMiniDump Execution | 🟠 high | 75 | `T1003.001` | [`hacktool_createminidump_execution.yaml`](./hacktool_createminidump_execution.yaml) |
| HackTool - Default PowerSploit/Empire Scheduled Task Creation | 🟠 high | 75 | `T1053.005`, `T1059.001` | [`hacktool_default_powersploit_empire_scheduled_task_creation.yaml`](./hacktool_default_powersploit_empire_scheduled_task_creation.yaml) |
| HackTool - Doppelanger LSASS Dumper Execution | 🟠 high | 75 | `T1003.001` | [`hacktool_doppelanger_lsass_dumper_execution.yaml`](./hacktool_doppelanger_lsass_dumper_execution.yaml) |
| Hacktool - EDR-Freeze Execution | 🟠 high | 75 | `T1685` | [`hacktool_edr_freeze_execution.yaml`](./hacktool_edr_freeze_execution.yaml) |
| HackTool - EDRSilencer Execution | 🟠 high | 75 | `T1685` | [`hacktool_edrsilencer_execution.yaml`](./hacktool_edrsilencer_execution.yaml) |
| HackTool - Empire PowerShell Launch Parameters | 🟠 high | 75 | `T1059.001` | [`hacktool_empire_powershell_launch_parameters.yaml`](./hacktool_empire_powershell_launch_parameters.yaml) |
| HackTool - GMER Rootkit Detector and Remover Execution | 🟠 high | 75 | — | [`hacktool_gmer_rootkit_detector_and_remover_execution.yaml`](./hacktool_gmer_rootkit_detector_and_remover_execution.yaml) |
| HackTool - HandleKatz LSASS Dumper Execution | 🟠 high | 75 | `T1003.001` | [`hacktool_handlekatz_lsass_dumper_execution.yaml`](./hacktool_handlekatz_lsass_dumper_execution.yaml) |
| HackTool - Hashcat Password Cracker Execution | 🟠 high | 75 | `T1110.002` | [`hacktool_hashcat_password_cracker_execution.yaml`](./hacktool_hashcat_password_cracker_execution.yaml) |
| HackTool - HollowReaper Execution | 🟠 high | 75 | `T1055.012` | [`hacktool_hollowreaper_execution.yaml`](./hacktool_hollowreaper_execution.yaml) |
| HackTool - Htran/NATBypass Execution | 🟠 high | 75 | `T1090` | [`hacktool_htran_natbypass_execution.yaml`](./hacktool_htran_natbypass_execution.yaml) |
| HackTool - Hydra Password Bruteforce Execution | 🟠 high | 75 | `T1110`, `T1110.001` | [`hacktool_hydra_password_bruteforce_execution.yaml`](./hacktool_hydra_password_bruteforce_execution.yaml) |
| HackTool - Impacket Tools Execution | 🟠 high | 75 | `T1557.001` | [`hacktool_impacket_tools_execution.yaml`](./hacktool_impacket_tools_execution.yaml) |
| HackTool - Koadic Execution | 🟠 high | 75 | `T1059.003`, `T1059.005`, `T1059.007` | [`hacktool_koadic_execution.yaml`](./hacktool_koadic_execution.yaml) |
| HackTool - KrbRelay Execution | 🟠 high | 75 | `T1558.003` | [`hacktool_krbrelay_execution.yaml`](./hacktool_krbrelay_execution.yaml) |
| HackTool - KrbRelayUp Execution | 🟠 high | 75 | `T1558.003`, `T1550.003` | [`hacktool_krbrelayup_execution.yaml`](./hacktool_krbrelayup_execution.yaml) |
| HackTool - LocalPotato Execution | 🟠 high | 75 | — | [`hacktool_localpotato_execution.yaml`](./hacktool_localpotato_execution.yaml) |
| HackTool - Mimikatz Execution | 🟠 high | 75 | `T1003.001`, `T1003.002`, `T1003.004`… | [`hacktool_mimikatz_execution.yaml`](./hacktool_mimikatz_execution.yaml) |
| HackTool - NetExec Execution | 🟠 high | 75 | `T1018`, `T1021` | [`hacktool_netexec_execution.yaml`](./hacktool_netexec_execution.yaml) |
| HackTool - PCHunter Execution | 🟠 high | 75 | `T1082`, `T1057`, `T1012`… | [`hacktool_pchunter_execution.yaml`](./hacktool_pchunter_execution.yaml) |
| HackTool - Potential Impacket Lateral Movement Activity | 🟠 high | 75 | `T1047`, `T1021.003` | [`hacktool_potential_impacket_lateral_movement_activity.yaml`](./hacktool_potential_impacket_lateral_movement_activity.yaml) |
| HackTool - PowerTool Execution | 🟠 high | 75 | `T1685` | [`hacktool_powertool_execution.yaml`](./hacktool_powertool_execution.yaml) |
| HackTool - PPID Spoofing SelectMyParent Tool Execution | 🟠 high | 75 | `T1134.004` | [`hacktool_ppid_spoofing_selectmyparent_tool_execution.yaml`](./hacktool_ppid_spoofing_selectmyparent_tool_execution.yaml) |
| HackTool - Pypykatz Credentials Dumping Activity | 🟠 high | 75 | `T1003.002` | [`hacktool_pypykatz_credentials_dumping_activity.yaml`](./hacktool_pypykatz_credentials_dumping_activity.yaml) |
| HackTool - Quarks PwDump Execution | 🟠 high | 75 | `T1003.002` | [`hacktool_quarks_pwdump_execution.yaml`](./hacktool_quarks_pwdump_execution.yaml) |
| HackTool - RedMimicry Winnti Playbook Execution | 🟠 high | 75 | `T1106`, `T1059.003`, `T1218.011` | [`hacktool_redmimicry_winnti_playbook_execution.yaml`](./hacktool_redmimicry_winnti_playbook_execution.yaml) |
| HackTool - RemoteKrbRelay Execution | 🟠 high | 75 | `T1558.003` | [`hacktool_remotekrbrelay_execution.yaml`](./hacktool_remotekrbrelay_execution.yaml) |
| HackTool - SharpChisel Execution | 🟠 high | 75 | `T1090.001` | [`hacktool_sharpchisel_execution.yaml`](./hacktool_sharpchisel_execution.yaml) |
| HackTool - SharpDPAPI Execution | 🟠 high | 75 | `T1134.001`, `T1134.003` | [`hacktool_sharpdpapi_execution.yaml`](./hacktool_sharpdpapi_execution.yaml) |
| HackTool - SharPersist Execution | 🟠 high | 75 | `T1053` | [`hacktool_sharpersist_execution.yaml`](./hacktool_sharpersist_execution.yaml) |
| HackTool - SharpEvtMute Execution | 🟠 high | 75 | `T1685.001` | [`hacktool_sharpevtmute_execution.yaml`](./hacktool_sharpevtmute_execution.yaml) |
| HackTool - SharpImpersonation Execution | 🟠 high | 75 | `T1134.001`, `T1134.003` | [`hacktool_sharpimpersonation_execution.yaml`](./hacktool_sharpimpersonation_execution.yaml) |
| HackTool - SharpLdapWhoami Execution | 🟠 high | 75 | `T1033` | [`hacktool_sharpldapwhoami_execution.yaml`](./hacktool_sharpldapwhoami_execution.yaml) |
| HackTool - SharpMove Tool Execution | 🟠 high | 75 | `T1021.002` | [`hacktool_sharpmove_tool_execution.yaml`](./hacktool_sharpmove_tool_execution.yaml) |
| HackTool - SharpView Execution | 🟠 high | 75 | `T1049`, `T1069.002`, `T1482`… | [`hacktool_sharpview_execution.yaml`](./hacktool_sharpview_execution.yaml) |
| HackTool - SharpWSUS/WSUSpendu Execution | 🟠 high | 75 | `T1210` | [`hacktool_sharpwsus_wsuspendu_execution.yaml`](./hacktool_sharpwsus_wsuspendu_execution.yaml) |
| HackTool - SILENTTRINITY Stager Execution | 🟠 high | 75 | `T1071` | [`hacktool_silenttrinity_stager_execution.yaml`](./hacktool_silenttrinity_stager_execution.yaml) |
| HackTool - SOAPHound Execution | 🟠 high | 75 | `T1087` | [`hacktool_soaphound_execution.yaml`](./hacktool_soaphound_execution.yaml) |
| HackTool - Stracciatella Execution | 🟠 high | 75 | `T1059`, `T1685` | [`hacktool_stracciatella_execution.yaml`](./hacktool_stracciatella_execution.yaml) |
| HackTool - TruffleSnout Execution | 🟠 high | 75 | `T1482` | [`hacktool_trufflesnout_execution.yaml`](./hacktool_trufflesnout_execution.yaml) |
| HackTool - UACMe Akagi Execution | 🟠 high | 75 | `T1548.002` | [`hacktool_uacme_akagi_execution.yaml`](./hacktool_uacme_akagi_execution.yaml) |
| HackTool - winPEAS Execution | 🟠 high | 75 | `T1082`, `T1087`, `T1046` | [`hacktool_winpeas_execution.yaml`](./hacktool_winpeas_execution.yaml) |
| HackTool - WinPwn Execution | 🟠 high | 75 | `T1046`, `T1082`, `T1106`… | [`hacktool_winpwn_execution.yaml`](./hacktool_winpwn_execution.yaml) |
| HackTool - Wmiexec Default Powershell Command | 🟠 high | 75 | — | [`hacktool_wmiexec_default_powershell_command.yaml`](./hacktool_wmiexec_default_powershell_command.yaml) |
| HackTool - XORDump Execution | 🟠 high | 75 | `T1036`, `T1003.001` | [`hacktool_xordump_execution.yaml`](./hacktool_xordump_execution.yaml) |
| Hacktool Execution - PE Metadata | 🟠 high | 75 | `T1588.002`, `T1003` | [`hacktool_execution_pe_metadata.yaml`](./hacktool_execution_pe_metadata.yaml) |
| Headless Browser Mockbin or Mocky Request | 🟠 high | 80 | `T1564.003` | [`headless_browser_mockbin_or_mocky_request.yaml`](./headless_browser_mockbin_or_mocky_request.yaml) |
| Hermetic Wiper TG Process Patterns | 🟠 high | 75 | `T1021.001` | [`hermetic_wiper_tg_process_patterns.yaml`](./hermetic_wiper_tg_process_patterns.yaml) |
| HKTL - SharpSuccessor Privilege Escalation Tool Execution | 🟠 high | 75 | `T1068` | [`hktl_sharpsuccessor_privilege_escalation_tool_execution.yaml`](./hktl_sharpsuccessor_privilege_escalation_tool_execution.yaml) |
| HTML Help HH.EXE Suspicious Child Process | 🟠 high | 75 | `T1047`, `T1059.001`, `T1059.003`… | [`html_help_hh_exe_suspicious_child_process.yaml`](./html_help_hh_exe_suspicious_child_process.yaml) |
| Hypervisor-protected Code Integrity (HVCI) Related Registry Tampering Via CommandLine | 🟠 high | 75 | `T1685` | [`hypervisor_protected_code_integrity_hvci_related_registry_tampering_via_commandline.yaml`](./hypervisor_protected_code_integrity_hvci_related_registry_tampering_via_commandline.yaml) |
| IcedID Malware Suspicious Single Digit DLL Execution Via Rundll32 | 🟠 high | 75 | `T1218.011` | [`icedid_malware_suspicious_single_digit_dll_execution_via_rundll32.yaml`](./icedid_malware_suspicious_single_digit_dll_execution_via_rundll32.yaml) |
| IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols Via CLI | 🟠 high | 75 | — | [`ie_zonemap_setting_downgraded_to_mycomputer_zone_for_http_protocols_via_cli.yaml`](./ie_zonemap_setting_downgraded_to_mycomputer_zone_for_http_protocols_via_cli.yaml) |
| ImagingDevices Unusual Parent/Child Processes | 🟠 high | 75 | — | [`imagingdevices_unusual_parent_child_processes.yaml`](./imagingdevices_unusual_parent_child_processes.yaml) |
| Impacket Lateral Movement Commandline Parameters | 🟠 high | 80 | `T1021.002`, `T1021.003`, `T1047`… | [`impacket_lateral_movement_commandline_parameters.yaml`](./impacket_lateral_movement_commandline_parameters.yaml) |
| Imports Registry Key From an ADS | 🟠 high | 75 | `T1112` | [`imports_registry_key_from_an_ads.yaml`](./imports_registry_key_from_an_ads.yaml) |
| Injected Browser Process Spawning Rundll32 - GuLoader Activity | 🟠 high | 75 | `T1055` | [`injected_browser_process_spawning_rundll32_guloader_activity.yaml`](./injected_browser_process_spawning_rundll32_guloader_activity.yaml) |
| Installation of WSL Kali-Linux | 🟠 high | 75 | `T1059` | [`installation_of_wsl_kali_linux.yaml`](./installation_of_wsl_kali_linux.yaml) |
| Interactive AT Job | 🟠 high | 75 | `T1053.002` | [`interactive_at_job.yaml`](./interactive_at_job.yaml) |
| Invoke-Obfuscation CLIP+ Launcher | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_clip_launcher.yaml`](./invoke_obfuscation_clip_launcher.yaml) |
| Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_var_launcher_obfuscation.yaml`](./invoke_obfuscation_var_launcher_obfuscation.yaml) |
| Invoke-Obfuscation Via Use MSHTA | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_via_use_mshta.yaml`](./invoke_obfuscation_via_use_mshta.yaml) |
| Kalambur Backdoor Curl TOR SOCKS Proxy Execution | 🟠 high | 75 | `T1090`, `T1573`, `T1071.001`… | [`kalambur_backdoor_curl_tor_socks_proxy_execution.yaml`](./kalambur_backdoor_curl_tor_socks_proxy_execution.yaml) |
| Kapeka Backdoor Execution Via RunDLL32.EXE | 🟠 high | 75 | `T1218.011` | [`kapeka_backdoor_execution_via_rundll32_exe.yaml`](./kapeka_backdoor_execution_via_rundll32_exe.yaml) |
| Kapeka Backdoor Persistence Activity | 🟠 high | 75 | `T1053.005` | [`kapeka_backdoor_persistence_activity.yaml`](./kapeka_backdoor_persistence_activity.yaml) |
| Kavremover Dropped Binary LOLBIN Usage | 🟠 high | 75 | `T1127` | [`kavremover_dropped_binary_lolbin_usage.yaml`](./kavremover_dropped_binary_lolbin_usage.yaml) |
| Kernel Memory Dump Via LiveKD | 🟠 high | 75 | — | [`kernel_memory_dump_via_livekd.yaml`](./kernel_memory_dump_via_livekd.yaml) |
| Lace Tempest Cobalt Strike Download | 🟠 high | 75 | — | [`lace_tempest_cobalt_strike_download.yaml`](./lace_tempest_cobalt_strike_download.yaml) |
| Lace Tempest Malware Loader Execution | 🟠 high | 75 | — | [`lace_tempest_malware_loader_execution.yaml`](./lace_tempest_malware_loader_execution.yaml) |
| Lazarus System Binary Masquerading | 🟠 high | 75 | `T1036.005` | [`lazarus_system_binary_masquerading.yaml`](./lazarus_system_binary_masquerading.yaml) |
| LOL-Binary Copied From System Directory | 🟠 high | 75 | `T1036.003` | [`lol_binary_copied_from_system_directory.yaml`](./lol_binary_copied_from_system_directory.yaml) |
| LSASS Dump Keyword In CommandLine | 🟠 high | 75 | `T1003.001` | [`lsass_dump_keyword_in_commandline.yaml`](./lsass_dump_keyword_in_commandline.yaml) |
| LSASS Process Reconnaissance Via Findstr.EXE | 🟠 high | 75 | `T1552.006` | [`lsass_process_reconnaissance_via_findstr_exe.yaml`](./lsass_process_reconnaissance_via_findstr_exe.yaml) |
| Lummac Stealer Activity - Execution Of More.com And Vbc.exe | 🟠 high | 75 | `T1055` | [`lummac_stealer_activity_execution_of_more_com_and_vbc_exe.yaml`](./lummac_stealer_activity_execution_of_more_com_and_vbc_exe.yaml) |
| Malicious Base64 Encoded PowerShell Keywords in Command Lines | 🟠 high | 75 | `T1059.001` | [`malicious_base64_encoded_powershell_keywords_in_command_lines.yaml`](./malicious_base64_encoded_powershell_keywords_in_command_lines.yaml) |
| ManageEngine Endpoint Central Dctask64.EXE Potential Abuse | 🟠 high | 75 | `T1055.001` | [`manageengine_endpoint_central_dctask64_exe_potential_abuse.yaml`](./manageengine_endpoint_central_dctask64_exe_potential_abuse.yaml) |
| Mavinject Inject DLL Into Running Process | 🟠 high | 75 | `T1055.001`, `T1218.013` | [`mavinject_inject_dll_into_running_process.yaml`](./mavinject_inject_dll_into_running_process.yaml) |
| MERCURY APT Activity | 🟠 high | 75 | `T1059.001` | [`mercury_apt_activity.yaml`](./mercury_apt_activity.yaml) |
| Microsoft IIS Connection Strings Decryption | 🟠 high | 75 | `T1003` | [`microsoft_iis_connection_strings_decryption.yaml`](./microsoft_iis_connection_strings_decryption.yaml) |
| Microsoft IIS Service Account Password Dumped | 🟠 high | 75 | `T1003` | [`microsoft_iis_service_account_password_dumped.yaml`](./microsoft_iis_service_account_password_dumped.yaml) |
| Mimikatz PassTheTicket CommandLine Parameters | 🟠 high | 80 | `T1550.003` | [`mimikatz_passtheticket_commandline_parameters.yaml`](./mimikatz_passtheticket_commandline_parameters.yaml) |
| Mint Sandstorm - Log4J Wstomcat Process Execution | 🟠 high | 75 | — | [`mint_sandstorm_log4j_wstomcat_process_execution.yaml`](./mint_sandstorm_log4j_wstomcat_process_execution.yaml) |
| MMC Executing Files with Reversed Extensions Using RTLO Abuse | 🟠 high | 75 | `T1204.002`, `T1218.014`, `T1036.002` | [`mmc_executing_files_with_reversed_extensions_using_rtlo_abuse.yaml`](./mmc_executing_files_with_reversed_extensions_using_rtlo_abuse.yaml) |
| MMC Spawning Windows Shell | 🟠 high | 75 | `T1021.003` | [`mmc_spawning_windows_shell.yaml`](./mmc_spawning_windows_shell.yaml) |
| MMC20 Lateral Movement | 🟠 high | 75 | `T1021.003` | [`mmc20_lateral_movement.yaml`](./mmc20_lateral_movement.yaml) |
| MpiExec Lolbin | 🟠 high | 75 | `T1218` | [`mpiexec_lolbin.yaml`](./mpiexec_lolbin.yaml) |
| MSDT Execution Via Answer File | 🟠 high | 75 | `T1218` | [`msdt_execution_via_answer_file.yaml`](./msdt_execution_via_answer_file.yaml) |
| MSHTA Execution with Suspicious File Extensions | 🟠 high | 75 | `T1140`, `T1218.005`, `T1059.007` | [`mshta_execution_with_suspicious_file_extensions.yaml`](./mshta_execution_with_suspicious_file_extensions.yaml) |
| Mshtml.DLL RunHTMLApplication Suspicious Usage | 🟠 high | 75 | — | [`mshtml_dll_runhtmlapplication_suspicious_usage.yaml`](./mshtml_dll_runhtmlapplication_suspicious_usage.yaml) |
| Mstsc.EXE Execution From Uncommon Parent | 🟠 high | 75 | — | [`mstsc_exe_execution_from_uncommon_parent.yaml`](./mstsc_exe_execution_from_uncommon_parent.yaml) |
| Mustang Panda Dropper | 🟠 high | 75 | `T1587.001` | [`mustang_panda_dropper.yaml`](./mustang_panda_dropper.yaml) |
| Network Reconnaissance Activity | 🟠 high | 75 | `T1087`, `T1082` | [`network_reconnaissance_activity.yaml`](./network_reconnaissance_activity.yaml) |
| New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE | 🟠 high | 75 | `T1574.001`, `T1112` | [`new_dns_serverlevelplugindll_installed_via_dnscmd_exe.yaml`](./new_dns_serverlevelplugindll_installed_via_dnscmd_exe.yaml) |
| New User Created Via Net.EXE With Never Expire Option | 🟠 high | 75 | `T1136.001` | [`new_user_created_via_net_exe_with_never_expire_option.yaml`](./new_user_created_via_net_exe_with_never_expire_option.yaml) |
| NewActiveScriptEventConsumer Creation Attempt via Wmic.EXE | 🟠 high | 75 | `T1546.003` | [`newactivescripteventconsumer_creation_attempt_via_wmic_exe.yaml`](./newactivescripteventconsumer_creation_attempt_via_wmic_exe.yaml) |
| Nishang PowershellTCPOneLine | 🟠 high | 80 | `T1059.001` | [`nishang_powershelltcponeline.yaml`](./nishang_powershelltcponeline.yaml) |
| Non-privileged Usage of Reg or Powershell | 🟠 high | 75 | `T1112` | [`non_privileged_usage_of_reg_or_powershell.yaml`](./non_privileged_usage_of_reg_or_powershell.yaml) |
| NtdllPipe Like Activity Execution | 🟠 high | 75 | — | [`ntdllpipe_like_activity_execution.yaml`](./ntdllpipe_like_activity_execution.yaml) |
| Ntdsutil Export NTDS | 🟠 high | 80 | `T1003.003` | [`ntdsutil_export_ntds.yaml`](./ntdsutil_export_ntds.yaml) |
| Obfuscated PowerShell MSI Install via WindowsInstaller COM | 🟠 high | 75 | `T1027.010`, `T1218.007`, `T1059.001` | [`obfuscated_powershell_msi_install_via_windowsinstaller_com.yaml`](./obfuscated_powershell_msi_install_via_windowsinstaller_com.yaml) |
| Obfuscated PowerShell OneLiner Execution | 🟠 high | 75 | `T1059.001`, `T1685` | [`obfuscated_powershell_oneliner_execution.yaml`](./obfuscated_powershell_oneliner_execution.yaml) |
| Odbcconf.EXE Suspicious DLL Location | 🟠 high | 75 | `T1218.008` | [`odbcconf_exe_suspicious_dll_location.yaml`](./odbcconf_exe_suspicious_dll_location.yaml) |
| OneNote.EXE Execution of Malicious Embedded Scripts | 🟠 high | 75 | `T1218.001` | [`onenote_exe_execution_of_malicious_embedded_scripts.yaml`](./onenote_exe_execution_of_malicious_embedded_scripts.yaml) |
| OpenWith.exe Executes Specified Binary | 🟠 high | 75 | `T1218` | [`openwith_exe_executes_specified_binary.yaml`](./openwith_exe_executes_specified_binary.yaml) |
| Operation Wocao Activity | 🟠 high | 75 | `T1012`, `T1036.004`, `T1027`… | [`operation_wocao_activity.yaml`](./operation_wocao_activity.yaml) |
| Operator Bloopers Cobalt Strike Commands | 🟠 high | 75 | `T1059.003` | [`operator_bloopers_cobalt_strike_commands.yaml`](./operator_bloopers_cobalt_strike_commands.yaml) |
| Operator Bloopers Cobalt Strike Modules | 🟠 high | 75 | `T1059.003` | [`operator_bloopers_cobalt_strike_modules.yaml`](./operator_bloopers_cobalt_strike_modules.yaml) |
| Outlook EnableUnsafeClientMailRules Setting Enabled | 🟠 high | 75 | `T1059`, `T1202` | [`outlook_enableunsafeclientmailrules_setting_enabled.yaml`](./outlook_enableunsafeclientmailrules_setting_enabled.yaml) |
| PaperCut MF/NG Exploitation Related Indicators | 🟠 high | 75 | — | [`papercut_mf_ng_exploitation_related_indicators.yaml`](./papercut_mf_ng_exploitation_related_indicators.yaml) |
| PaperCut MF/NG Potential Exploitation | 🟠 high | 75 | — | [`papercut_mf_ng_potential_exploitation.yaml`](./papercut_mf_ng_potential_exploitation.yaml) |
| Peach Sandstorm APT Process Activity Indicators | 🟠 high | 75 | — | [`peach_sandstorm_apt_process_activity_indicators.yaml`](./peach_sandstorm_apt_process_activity_indicators.yaml) |
| Phishing Pattern ISO in Archive | 🟠 high | 75 | `T1566` | [`phishing_pattern_iso_in_archive.yaml`](./phishing_pattern_iso_in_archive.yaml) |
| Pikabot Fake DLL Extension Execution Via Rundll32.EXE | 🟠 high | 75 | — | [`pikabot_fake_dll_extension_execution_via_rundll32_exe.yaml`](./pikabot_fake_dll_extension_execution_via_rundll32_exe.yaml) |
| Ping Hex IP | 🟠 high | 75 | `T1140`, `T1027` | [`ping_hex_ip.yaml`](./ping_hex_ip.yaml) |
| Pingback Backdoor Activity | 🟠 high | 75 | `T1574.001` | [`pingback_backdoor_activity.yaml`](./pingback_backdoor_activity.yaml) |
| Possible Privilege Escalation via Weak Service Permissions | 🟠 high | 75 | `T1574.011` | [`possible_privilege_escalation_via_weak_service_permissions.yaml`](./possible_privilege_escalation_via_weak_service_permissions.yaml) |
| Potential ACTINIUM Persistence Activity | 🟠 high | 75 | `T1053`, `T1053.005` | [`potential_actinium_persistence_activity.yaml`](./potential_actinium_persistence_activity.yaml) |
| Potential Adplus.EXE Abuse | 🟠 high | 75 | `T1003.001` | [`potential_adplus_exe_abuse.yaml`](./potential_adplus_exe_abuse.yaml) |
| Potential AMSI Bypass Via .NET Reflection | 🟠 high | 75 | `T1685` | [`potential_amsi_bypass_via_net_reflection.yaml`](./potential_amsi_bypass_via_net_reflection.yaml) |
| Potential APT FIN7 Reconnaissance/POWERTRASH Related Activity | 🟠 high | 75 | — | [`potential_apt_fin7_reconnaissance_powertrash_related_activity.yaml`](./potential_apt_fin7_reconnaissance_powertrash_related_activity.yaml) |
| Potential APT Mustang Panda Activity Against Australian Gov | 🟠 high | 75 | — | [`potential_apt_mustang_panda_activity_against_australian_gov.yaml`](./potential_apt_mustang_panda_activity_against_australian_gov.yaml) |
| Potential APT10 Cloud Hopper Activity | 🟠 high | 75 | `T1059.005` | [`potential_apt10_cloud_hopper_activity.yaml`](./potential_apt10_cloud_hopper_activity.yaml) |
| Potential Arbitrary Code Execution Via Node.EXE | 🟠 high | 75 | `T1127` | [`potential_arbitrary_code_execution_via_node_exe.yaml`](./potential_arbitrary_code_execution_via_node_exe.yaml) |
| Potential Arbitrary Command Execution Using Msdt.EXE | 🟠 high | 75 | `T1202` | [`potential_arbitrary_command_execution_using_msdt_exe.yaml`](./potential_arbitrary_command_execution_using_msdt_exe.yaml) |
| Potential Arbitrary File Download Using Office Application | 🟠 high | 75 | `T1202` | [`potential_arbitrary_file_download_using_office_application.yaml`](./potential_arbitrary_file_download_using_office_application.yaml) |
| Potential Atlassian Confluence CVE-2021-26084 Exploitation Attempt | 🟠 high | 75 | `T1190`, `T1059` | [`potential_atlassian_confluence_cve_2021_26084_exploitation_attempt.yaml`](./potential_atlassian_confluence_cve_2021_26084_exploitation_attempt.yaml) |
| Potential Baby Shark Malware Activity | 🟠 high | 75 | `T1012`, `T1059.003`, `T1059.001`… | [`potential_baby_shark_malware_activity.yaml`](./potential_baby_shark_malware_activity.yaml) |
| Potential BearLPE Exploitation | 🟠 high | 75 | `T1053.005` | [`potential_bearlpe_exploitation.yaml`](./potential_bearlpe_exploitation.yaml) |
| Potential BlackByte Ransomware Activity | 🟠 high | 75 | `T1485`, `T1498`, `T1059.001`… | [`potential_blackbyte_ransomware_activity.yaml`](./potential_blackbyte_ransomware_activity.yaml) |
| Potential CobaltStrike Process Patterns | 🟠 high | 75 | `T1059` | [`potential_cobaltstrike_process_patterns.yaml`](./potential_cobaltstrike_process_patterns.yaml) |
| Potential CommandLine Obfuscation Using Unicode Characters From Suspicious Image | 🟠 high | 75 | `T1027` | [`potential_commandline_obfuscation_using_unicode_characters_from_suspicious_image.yaml`](./potential_commandline_obfuscation_using_unicode_characters_from_suspicious_image.yaml) |
| Potential CommandLine Path Traversal Via Cmd.EXE | 🟠 high | 75 | `T1059.003` | [`potential_commandline_path_traversal_via_cmd_exe.yaml`](./potential_commandline_path_traversal_via_cmd_exe.yaml) |
| Potential Compromised 3CXDesktopApp Execution | 🟠 high | 75 | `T1218` | [`potential_compromised_3cxdesktopapp_execution.yaml`](./potential_compromised_3cxdesktopapp_execution.yaml) |
| Potential Compromised 3CXDesktopApp Update Activity | 🟠 high | 75 | `T1218` | [`potential_compromised_3cxdesktopapp_update_activity.yaml`](./potential_compromised_3cxdesktopapp_update_activity.yaml) |
| Potential Conti Ransomware Database Dumping Activity Via SQLCmd | 🟠 high | 75 | `T1005` | [`potential_conti_ransomware_database_dumping_activity_via_sqlcmd.yaml`](./potential_conti_ransomware_database_dumping_activity_via_sqlcmd.yaml) |
| Potential Credential Dumping Attempt Using New NetworkProvider - CLI | 🟠 high | 75 | `T1003` | [`potential_credential_dumping_attempt_using_new_networkprovider_cli.yaml`](./potential_credential_dumping_attempt_using_new_networkprovider_cli.yaml) |
| Potential Credential Dumping Via WER | 🟠 high | 75 | `T1003.001` | [`potential_credential_dumping_via_wer.yaml`](./potential_credential_dumping_via_wer.yaml) |
| Potential Crypto Mining Activity | 🟠 high | 75 | `T1496` | [`potential_crypto_mining_activity.yaml`](./potential_crypto_mining_activity.yaml) |
| Potential CVE-2021-26857 Exploitation Attempt | 🟠 high | 75 | `T1203` | [`potential_cve_2021_26857_exploitation_attempt.yaml`](./potential_cve_2021_26857_exploitation_attempt.yaml) |
| Potential CVE-2021-40444 Exploitation Attempt | 🟠 high | 75 | `T1059` | [`potential_cve_2021_40444_exploitation_attempt.yaml`](./potential_cve_2021_40444_exploitation_attempt.yaml) |
| Potential CVE-2021-44228 Exploitation Attempt - VMware Horizon | 🟠 high | 75 | `T1190` | [`potential_cve_2021_44228_exploitation_attempt_vmware_horizon.yaml`](./potential_cve_2021_44228_exploitation_attempt_vmware_horizon.yaml) |
| Potential CVE-2022-26809 Exploitation Attempt | 🟠 high | 75 | `T1190`, `T1569.002` | [`potential_cve_2022_26809_exploitation_attempt.yaml`](./potential_cve_2022_26809_exploitation_attempt.yaml) |
| Potential CVE-2022-29072 Exploitation Attempt | 🟠 high | 75 | — | [`potential_cve_2022_29072_exploitation_attempt.yaml`](./potential_cve_2022_29072_exploitation_attempt.yaml) |
| Potential CVE-2023-21554 QueueJumper Exploitation | 🟠 high | 75 | — | [`potential_cve_2023_21554_queuejumper_exploitation.yaml`](./potential_cve_2023_21554_queuejumper_exploitation.yaml) |
| Potential CVE-2023-36874 Exploitation - Fake Wermgr Execution | 🟠 high | 75 | — | [`potential_cve_2023_36874_exploitation_fake_wermgr_execution.yaml`](./potential_cve_2023_36874_exploitation_fake_wermgr_execution.yaml) |
| Potential CVE-2026-33829 Exploitation - Windows Snipping Tool Remote File Path URI | 🟠 high | 75 | `T1187` | [`potential_cve_2026_33829_exploitation_windows_snipping_tool_remote_file_path_uri.yaml`](./potential_cve_2026_33829_exploitation_windows_snipping_tool_remote_file_path_uri.yaml) |
| Potential Data Exfiltration Activity Via CommandLine Tools | 🟠 high | 75 | `T1059.001` | [`potential_data_exfiltration_activity_via_commandline_tools.yaml`](./potential_data_exfiltration_activity_via_commandline_tools.yaml) |
| Potential Data Stealing Via Chromium Headless Debugging | 🟠 high | 75 | `T1185`, `T1564.003` | [`potential_data_stealing_via_chromium_headless_debugging.yaml`](./potential_data_stealing_via_chromium_headless_debugging.yaml) |
| Potential Defense Evasion Via Rename Of Highly Relevant Binaries | 🟠 high | 75 | `T1036.003` | [`potential_defense_evasion_via_rename_of_highly_relevant_binaries.yaml`](./potential_defense_evasion_via_rename_of_highly_relevant_binaries.yaml) |
| Potential Defense Evasion Via Right-to-Left Override | 🟠 high | 75 | `T1036.002` | [`potential_defense_evasion_via_right_to_left_override.yaml`](./potential_defense_evasion_via_right_to_left_override.yaml) |
| Potential Devil Bait Malware Reconnaissance | 🟠 high | 75 | `T1218` | [`potential_devil_bait_malware_reconnaissance.yaml`](./potential_devil_bait_malware_reconnaissance.yaml) |
| Potential Emotet Activity | 🟠 high | 75 | `T1059.001`, `T1027` | [`potential_emotet_activity.yaml`](./potential_emotet_activity.yaml) |
| Potential EmpireMonkey Activity | 🟠 high | 75 | `T1218.010` | [`potential_empiremonkey_activity.yaml`](./potential_empiremonkey_activity.yaml) |
| Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp | 🟠 high | 75 | `T1021.003` | [`potential_excel_exe_dcom_lateral_movement_via_activatemicrosoftapp.yaml`](./potential_excel_exe_dcom_lateral_movement_via_activatemicrosoftapp.yaml) |
| Potential Exploitation Attempt From Office Application | 🟠 high | 75 | — | [`potential_exploitation_attempt_from_office_application.yaml`](./potential_exploitation_attempt_from_office_application.yaml) |
| Potential Exploitation Attempt Of Undocumented WindowsServer RCE | 🟠 high | 75 | `T1190` | [`potential_exploitation_attempt_of_undocumented_windowsserver_rce.yaml`](./potential_exploitation_attempt_of_undocumented_windowsserver_rce.yaml) |
| Potential Exploitation of CrushFTP RCE Vulnerability (CVE-2025-54309) | 🟠 high | 75 | `T1059.001`, `T1059.003`, `T1068`… | [`potential_exploitation_of_crushftp_rce_vulnerability_cve_2025_54309.yaml`](./potential_exploitation_of_crushftp_rce_vulnerability_cve_2025_54309.yaml) |
| Potential Exploitation of CVE-2024-37085 - Suspicious Creation Of ESX Admins Group | 🟠 high | 75 | — | [`potential_exploitation_of_cve_2024_37085_suspicious_creation_of_esx_admins_group.yaml`](./potential_exploitation_of_cve_2024_37085_suspicious_creation_of_esx_admins_group.yaml) |
| Potential Exploitation of GoAnywhere MFT Vulnerability | 🟠 high | 75 | `T1190`, `T1059.001`, `T1133` | [`potential_exploitation_of_goanywhere_mft_vulnerability.yaml`](./potential_exploitation_of_goanywhere_mft_vulnerability.yaml) |
| Potential Exploitation of RCE Vulnerability CVE-2025-33053 | 🟠 high | 75 | `T1218`, `T1105` | [`potential_exploitation_of_rce_vulnerability_cve_2025_33053.yaml`](./potential_exploitation_of_rce_vulnerability_cve_2025_33053.yaml) |
| Potential File Overwrite Via Sysinternals SDelete | 🟠 high | 75 | `T1485` | [`potential_file_overwrite_via_sysinternals_sdelete.yaml`](./potential_file_overwrite_via_sysinternals_sdelete.yaml) |
| Potential Goofy Guineapig Backdoor Activity | 🟠 high | 75 | — | [`potential_goofy_guineapig_backdoor_activity.yaml`](./potential_goofy_guineapig_backdoor_activity.yaml) |
| Potential Goofy Guineapig GoolgeUpdate Process Anomaly | 🟠 high | 75 | — | [`potential_goofy_guineapig_goolgeupdate_process_anomaly.yaml`](./potential_goofy_guineapig_goolgeupdate_process_anomaly.yaml) |
| Potential Ke3chang/TidePool Malware Activity | 🟠 high | 75 | `T1685` | [`potential_ke3chang_tidepool_malware_activity.yaml`](./potential_ke3chang_tidepool_malware_activity.yaml) |
| Potential LethalHTA Technique Execution | 🟠 high | 75 | `T1218.005` | [`potential_lethalhta_technique_execution.yaml`](./potential_lethalhta_technique_execution.yaml) |
| Potential LSASS Process Dump Via Procdump | 🟠 high | 75 | `T1036`, `T1003.001` | [`potential_lsass_process_dump_via_procdump.yaml`](./potential_lsass_process_dump_via_procdump.yaml) |
| Potential Manage-bde.wsf Abuse To Proxy Execution | 🟠 high | 75 | `T1216` | [`potential_manage_bde_wsf_abuse_to_proxy_execution.yaml`](./potential_manage_bde_wsf_abuse_to_proxy_execution.yaml) |
| Potential Meterpreter/CobaltStrike Activity | 🟠 high | 75 | `T1134.001`, `T1134.002` | [`potential_meterpreter_cobaltstrike_activity.yaml`](./potential_meterpreter_cobaltstrike_activity.yaml) |
| Potential Mpclient.DLL Sideloading Via Defender Binaries | 🟠 high | 75 | `T1574.001` | [`potential_mpclient_dll_sideloading_via_defender_binaries.yaml`](./potential_mpclient_dll_sideloading_via_defender_binaries.yaml) |
| Potential MsiExec Masquerading | 🟠 high | 75 | `T1036.005` | [`potential_msiexec_masquerading.yaml`](./potential_msiexec_masquerading.yaml) |
| Potential MSTSC Shadowing Activity | 🟠 high | 75 | `T1563.002` | [`potential_mstsc_shadowing_activity.yaml`](./potential_mstsc_shadowing_activity.yaml) |
| Potential MuddyWater APT Activity | 🟠 high | 75 | — | [`potential_muddywater_apt_activity.yaml`](./potential_muddywater_apt_activity.yaml) |
| Potential Notepad++ CVE-2025-49144 Exploitation | 🟠 high | 75 | `T1574.008` | [`potential_notepad_cve_2025_49144_exploitation.yaml`](./potential_notepad_cve_2025_49144_exploitation.yaml) |
| Potential NTLM Coercion Via Certutil.EXE | 🟠 high | 75 | `T1218` | [`potential_ntlm_coercion_via_certutil_exe.yaml`](./potential_ntlm_coercion_via_certutil_exe.yaml) |
| Potential Persistence Via Logon Scripts - CommandLine | 🟠 high | 75 | `T1037.001` | [`potential_persistence_via_logon_scripts_commandline.yaml`](./potential_persistence_via_logon_scripts_commandline.yaml) |
| Potential Persistence Via Powershell Search Order Hijacking - Task | 🟠 high | 75 | `T1053.005`, `T1059.001` | [`potential_persistence_via_powershell_search_order_hijacking_task.yaml`](./potential_persistence_via_powershell_search_order_hijacking_task.yaml) |
| Potential Pikabot Discovery Activity | 🟠 high | 75 | `T1016`, `T1049`, `T1087` | [`potential_pikabot_discovery_activity.yaml`](./potential_pikabot_discovery_activity.yaml) |
| Potential Pikabot Hollowing Activity | 🟠 high | 75 | `T1055.012` | [`potential_pikabot_hollowing_activity.yaml`](./potential_pikabot_hollowing_activity.yaml) |
| Potential PlugX Activity | 🟠 high | 75 | `T1574.001` | [`potential_plugx_activity.yaml`](./potential_plugx_activity.yaml) |
| Potential PowerShell Command Line Obfuscation | 🟠 high | 75 | `T1027`, `T1059.001` | [`potential_powershell_command_line_obfuscation.yaml`](./potential_powershell_command_line_obfuscation.yaml) |
| Potential PowerShell Execution Policy Tampering - ProcCreation | 🟠 high | 75 | — | [`potential_powershell_execution_policy_tampering_proccreation.yaml`](./potential_powershell_execution_policy_tampering_proccreation.yaml) |
| Potential PowerShell Execution Via DLL | 🟠 high | 75 | `T1218.011` | [`potential_powershell_execution_via_dll.yaml`](./potential_powershell_execution_via_dll.yaml) |
| Potential PowerShell Obfuscation Via Reversed Commands | 🟠 high | 75 | `T1027`, `T1059.001` | [`potential_powershell_obfuscation_via_reversed_commands.yaml`](./potential_powershell_obfuscation_via_reversed_commands.yaml) |
| Potential PowerShell Obfuscation Via WCHAR/CHAR | 🟠 high | 75 | `T1059.001`, `T1027` | [`potential_powershell_obfuscation_via_wchar_char.yaml`](./potential_powershell_obfuscation_via_wchar_char.yaml) |
| Potential Powershell ReverseShell Connection | 🟠 high | 75 | `T1059.001` | [`potential_powershell_reverseshell_connection.yaml`](./potential_powershell_reverseshell_connection.yaml) |
| Potential Privilege Escalation Using Symlink Between Osk and Cmd | 🟠 high | 75 | `T1546.008` | [`potential_privilege_escalation_using_symlink_between_osk_and_cmd.yaml`](./potential_privilege_escalation_using_symlink_between_osk_and_cmd.yaml) |
| Potential Privilege Escalation via Service Permissions Weakness | 🟠 high | 75 | `T1574.011` | [`potential_privilege_escalation_via_service_permissions_weakness.yaml`](./potential_privilege_escalation_via_service_permissions_weakness.yaml) |
| Potential Process Injection Via Msra.EXE | 🟠 high | 75 | `T1055` | [`potential_process_injection_via_msra_exe.yaml`](./potential_process_injection_via_msra_exe.yaml) |
| Potential Provisioning Registry Key Abuse For Binary Proxy Execution | 🟠 high | 75 | `T1218` | [`potential_provisioning_registry_key_abuse_for_binary_proxy_execution.yaml`](./potential_provisioning_registry_key_abuse_for_binary_proxy_execution.yaml) |
| Potential PsExec Remote Execution | 🟠 high | 75 | `T1587.001` | [`potential_psexec_remote_execution.yaml`](./potential_psexec_remote_execution.yaml) |
| Potential Qakbot Rundll32 Execution | 🟠 high | 75 | — | [`potential_qakbot_rundll32_execution.yaml`](./potential_qakbot_rundll32_execution.yaml) |
| Potential Raspberry Robin CPL Execution Activity | 🟠 high | 75 | `T1218.011` | [`potential_raspberry_robin_cpl_execution_activity.yaml`](./potential_raspberry_robin_cpl_execution_activity.yaml) |
| Potential Raspberry Robin Dot Ending File | 🟠 high | 75 | — | [`potential_raspberry_robin_dot_ending_file.yaml`](./potential_raspberry_robin_dot_ending_file.yaml) |
| Potential RDP Tunneling Via Plink | 🟠 high | 75 | `T1572` | [`potential_rdp_tunneling_via_plink.yaml`](./potential_rdp_tunneling_via_plink.yaml) |
| Potential RDP Tunneling Via SSH | 🟠 high | 75 | `T1572` | [`potential_rdp_tunneling_via_ssh.yaml`](./potential_rdp_tunneling_via_ssh.yaml) |
| Potential Recon Activity Using DriverQuery.EXE | 🟠 high | 75 | — | [`potential_recon_activity_using_driverquery_exe.yaml`](./potential_recon_activity_using_driverquery_exe.yaml) |
| Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE | 🟠 high | 75 | `T1003.005` | [`potential_reconnaissance_for_cached_credentials_via_cmdkey_exe.yaml`](./potential_reconnaissance_for_cached_credentials_via_cmdkey_exe.yaml) |
| Potential Remote SquiblyTwo Technique Execution | 🟠 high | 75 | `T1047`, `T1220`, `T1059.005`… | [`potential_remote_squiblytwo_technique_execution.yaml`](./potential_remote_squiblytwo_technique_execution.yaml) |
| Potential Renamed Rundll32 Execution | 🟠 high | 75 | — | [`potential_renamed_rundll32_execution.yaml`](./potential_renamed_rundll32_execution.yaml) |
| Potential Ryuk Ransomware Activity | 🟠 high | 75 | `T1547.001` | [`potential_ryuk_ransomware_activity.yaml`](./potential_ryuk_ransomware_activity.yaml) |
| Potential SharePoint ToolShell CVE-2025-53770 Exploitation Indicators | 🟠 high | 75 | `T1190` | [`potential_sharepoint_toolshell_cve_2025_53770_exploitation_indicators.yaml`](./potential_sharepoint_toolshell_cve_2025_53770_exploitation_indicators.yaml) |
| Potential Signing Bypass Via Windows Developer Features | 🟠 high | 75 | — | [`potential_signing_bypass_via_windows_developer_features.yaml`](./potential_signing_bypass_via_windows_developer_features.yaml) |
| Potential SNAKE Malware Installation Binary Indicator | 🟠 high | 75 | — | [`potential_snake_malware_installation_binary_indicator.yaml`](./potential_snake_malware_installation_binary_indicator.yaml) |
| Potential SNAKE Malware Installation CLI Arguments Indicator | 🟠 high | 75 | — | [`potential_snake_malware_installation_cli_arguments_indicator.yaml`](./potential_snake_malware_installation_cli_arguments_indicator.yaml) |
| Potential SNAKE Malware Persistence Service Execution | 🟠 high | 75 | — | [`potential_snake_malware_persistence_service_execution.yaml`](./potential_snake_malware_persistence_service_execution.yaml) |
| Potential Snatch Ransomware Activity | 🟠 high | 75 | `T1204` | [`potential_snatch_ransomware_activity.yaml`](./potential_snatch_ransomware_activity.yaml) |
| Potential SSH Tunnel Persistence Install Using A Scheduled Task | 🟠 high | 75 | `T1053.005` | [`potential_ssh_tunnel_persistence_install_using_a_scheduled_task.yaml`](./potential_ssh_tunnel_persistence_install_using_a_scheduled_task.yaml) |
| Potential Suspicious Child Process Of 3CXDesktopApp | 🟠 high | 75 | `T1218` | [`potential_suspicious_child_process_of_3cxdesktopapp.yaml`](./potential_suspicious_child_process_of_3cxdesktopapp.yaml) |
| Potential Suspicious Mofcomp Execution | 🟠 high | 75 | `T1218` | [`potential_suspicious_mofcomp_execution.yaml`](./potential_suspicious_mofcomp_execution.yaml) |
| Potential SysInternals ProcDump Evasion | 🟠 high | 75 | `T1036`, `T1003.001` | [`potential_sysinternals_procdump_evasion.yaml`](./potential_sysinternals_procdump_evasion.yaml) |
| Potential Tampering With RDP Related Registry Keys Via Reg.EXE | 🟠 high | 75 | `T1021.001`, `T1112` | [`potential_tampering_with_rdp_related_registry_keys_via_reg_exe.yaml`](./potential_tampering_with_rdp_related_registry_keys_via_reg_exe.yaml) |
| Potential Tampering With Security Products Via WMIC | 🟠 high | 75 | `T1685` | [`potential_tampering_with_security_products_via_wmic.yaml`](./potential_tampering_with_security_products_via_wmic.yaml) |
| Potential WinAPI Calls Via CommandLine | 🟠 high | 75 | `T1106` | [`potential_winapi_calls_via_commandline.yaml`](./potential_winapi_calls_via_commandline.yaml) |
| Potential Windows Defender AV Bypass Via Dump64.EXE Rename | 🟠 high | 75 | `T1003.001` | [`potential_windows_defender_av_bypass_via_dump64_exe_rename.yaml`](./potential_windows_defender_av_bypass_via_dump64_exe_rename.yaml) |
| Potential Windows Defender Tampering Via Wmic.EXE | 🟠 high | 75 | `T1047`, `T1685` | [`potential_windows_defender_tampering_via_wmic_exe.yaml`](./potential_windows_defender_tampering_via_wmic_exe.yaml) |
| Potentially Suspicious ASP.NET Compilation Via AspNetCompiler | 🟠 high | 75 | `T1127` | [`potentially_suspicious_asp_net_compilation_via_aspnetcompiler.yaml`](./potentially_suspicious_asp_net_compilation_via_aspnetcompiler.yaml) |
| Potentially Suspicious Call To Win32_NTEventlogFile Class | 🟠 high | 75 | — | [`potentially_suspicious_call_to_win32_nteventlogfile_class.yaml`](./potentially_suspicious_call_to_win32_nteventlogfile_class.yaml) |
| Potentially Suspicious Child Process Of Regsvr32 | 🟠 high | 75 | `T1218.010` | [`potentially_suspicious_child_process_of_regsvr32.yaml`](./potentially_suspicious_child_process_of_regsvr32.yaml) |
| Potentially Suspicious Child Processes Spawned by ConHost | 🟠 high | 75 | `T1202`, `T1218` | [`potentially_suspicious_child_processes_spawned_by_conhost.yaml`](./potentially_suspicious_child_processes_spawned_by_conhost.yaml) |
| Potentially Suspicious DLL Registered Via Odbcconf.EXE | 🟠 high | 75 | `T1218.008` | [`potentially_suspicious_dll_registered_via_odbcconf_exe.yaml`](./potentially_suspicious_dll_registered_via_odbcconf_exe.yaml) |
| Potentially Suspicious Event Viewer Child Process | 🟠 high | 75 | `T1548.002` | [`potentially_suspicious_event_viewer_child_process.yaml`](./potentially_suspicious_event_viewer_child_process.yaml) |
| Potentially Suspicious Execution From Parent Process In Public Folder | 🟠 high | 75 | `T1564`, `T1059` | [`potentially_suspicious_execution_from_parent_process_in_public_folder.yaml`](./potentially_suspicious_execution_from_parent_process_in_public_folder.yaml) |
| Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE | 🟠 high | 75 | — | [`potentially_suspicious_file_download_from_file_sharing_domain_via_powershell_exe.yaml`](./potentially_suspicious_file_download_from_file_sharing_domain_via_powershell_exe.yaml) |
| Potentially Suspicious GoogleUpdate Child Process | 🟠 high | 75 | — | [`potentially_suspicious_googleupdate_child_process.yaml`](./potentially_suspicious_googleupdate_child_process.yaml) |
| Potentially Suspicious Office Document Executed From Trusted Location | 🟠 high | 75 | `T1202` | [`potentially_suspicious_office_document_executed_from_trusted_location.yaml`](./potentially_suspicious_office_document_executed_from_trusted_location.yaml) |
| Potentially Suspicious Regsvr32 HTTP IP Pattern | 🟠 high | 75 | `T1218.010` | [`potentially_suspicious_regsvr32_http_ip_pattern.yaml`](./potentially_suspicious_regsvr32_http_ip_pattern.yaml) |
| PowerShell Base64 Encoded FromBase64String Cmdlet | 🟠 high | 75 | `T1140`, `T1059.001` | [`powershell_base64_encoded_frombase64string_cmdlet.yaml`](./powershell_base64_encoded_frombase64string_cmdlet.yaml) |
| PowerShell Base64 Encoded IEX Cmdlet | 🟠 high | 75 | `T1059.001` | [`powershell_base64_encoded_iex_cmdlet.yaml`](./powershell_base64_encoded_iex_cmdlet.yaml) |
| PowerShell Base64 Encoded Invoke Keyword | 🟠 high | 75 | `T1059.001`, `T1027` | [`powershell_base64_encoded_invoke_keyword.yaml`](./powershell_base64_encoded_invoke_keyword.yaml) |
| Powershell Base64 Encoded MpPreference Cmdlet | 🟠 high | 75 | `T1685` | [`powershell_base64_encoded_mppreference_cmdlet.yaml`](./powershell_base64_encoded_mppreference_cmdlet.yaml) |
| PowerShell Base64 Encoded Reflective Assembly Load | 🟠 high | 75 | `T1059.001`, `T1027`, `T1620` | [`powershell_base64_encoded_reflective_assembly_load.yaml`](./powershell_base64_encoded_reflective_assembly_load.yaml) |
| PowerShell Base64 Encoded WMI Classes | 🟠 high | 75 | `T1059.001`, `T1027` | [`powershell_base64_encoded_wmi_classes.yaml`](./powershell_base64_encoded_wmi_classes.yaml) |
| PowerShell Defender Threat Severity Default Action Set to 'Allow' or 'NoAction' | 🟠 high | 75 | `T1685` | [`powershell_defender_threat_severity_default_action_set_to_allow_or_noaction.yaml`](./powershell_defender_threat_severity_default_action_set_to_allow_or_noaction.yaml) |
| PowerShell Download and Execution Cradles | 🟠 high | 75 | `T1059` | [`powershell_download_and_execution_cradles.yaml`](./powershell_download_and_execution_cradles.yaml) |
| PowerShell Execution With Potential Decryption Capabilities | 🟠 high | 75 | — | [`powershell_execution_with_potential_decryption_capabilities.yaml`](./powershell_execution_with_potential_decryption_capabilities.yaml) |
| PowerShell Get-Process LSASS | 🟠 high | 75 | `T1552.004` | [`powershell_get_process_lsass.yaml`](./powershell_get_process_lsass.yaml) |
| PowerShell SAM Copy | 🟠 high | 75 | `T1003.002` | [`powershell_sam_copy.yaml`](./powershell_sam_copy.yaml) |
| PowerShell Script Change Permission Via Set-Acl | 🟠 high | 75 | — | [`powershell_script_change_permission_via_set_acl.yaml`](./powershell_script_change_permission_via_set_acl.yaml) |
| PowerShell Set-Acl On Windows Folder | 🟠 high | 75 | — | [`powershell_set_acl_on_windows_folder.yaml`](./powershell_set_acl_on_windows_folder.yaml) |
| PowerShell Web Access Feature Enabled Via DISM | 🟠 high | 75 | `T1548.002` | [`powershell_web_access_feature_enabled_via_dism.yaml`](./powershell_web_access_feature_enabled_via_dism.yaml) |
| PPL Tampering Via WerFaultSecure | 🟠 high | 75 | `T1685`, `T1003.001` | [`ppl_tampering_via_werfaultsecure.yaml`](./ppl_tampering_via_werfaultsecure.yaml) |
| PrintBrm ZIP Creation of Extraction | 🟠 high | 75 | `T1105`, `T1564.004` | [`printbrm_zip_creation_of_extraction.yaml`](./printbrm_zip_creation_of_extraction.yaml) |
| Privilege Escalation via Named Pipe Impersonation | 🟠 high | 75 | `T1021` | [`privilege_escalation_via_named_pipe_impersonation.yaml`](./privilege_escalation_via_named_pipe_impersonation.yaml) |
| Process Access via TrolleyExpress Exclusion | 🟠 high | 75 | `T1218.011`, `T1003.001` | [`process_access_via_trolleyexpress_exclusion.yaml`](./process_access_via_trolleyexpress_exclusion.yaml) |
| Process Execution From A Potentially Suspicious Folder | 🟠 high | 75 | `T1036` | [`process_execution_from_a_potentially_suspicious_folder.yaml`](./process_execution_from_a_potentially_suspicious_folder.yaml) |
| Process Memory Dump Via Comsvcs.DLL | 🟠 high | 75 | `T1036`, `T1003.001` | [`process_memory_dump_via_comsvcs_dll.yaml`](./process_memory_dump_via_comsvcs_dll.yaml) |
| Process Memory Dump via RdrLeakDiag.EXE | 🟠 high | 75 | `T1003.001` | [`process_memory_dump_via_rdrleakdiag_exe.yaml`](./process_memory_dump_via_rdrleakdiag_exe.yaml) |
| Proxy Execution Via Wuauclt.EXE | 🟠 high | 75 | `T1218` | [`proxy_execution_via_wuauclt_exe.yaml`](./proxy_execution_via_wuauclt_exe.yaml) |
| Ps.exe Renamed SysInternals Tool | 🟠 high | 75 | `T1036.003` | [`ps_exe_renamed_sysinternals_tool.yaml`](./ps_exe_renamed_sysinternals_tool.yaml) |
| PsExec Service Child Process Execution as LOCAL SYSTEM | 🟠 high | 75 | — | [`psexec_service_child_process_execution_as_local_system.yaml`](./psexec_service_child_process_execution_as_local_system.yaml) |
| PUA - 3Proxy Execution | 🟠 high | 75 | `T1572` | [`pua_3proxy_execution.yaml`](./pua_3proxy_execution.yaml) |
| PUA - AdFind Suspicious Execution | 🟠 high | 75 | `T1018`, `T1087.002`, `T1482`… | [`pua_adfind_suspicious_execution.yaml`](./pua_adfind_suspicious_execution.yaml) |
| PUA - AdvancedRun Suspicious Execution | 🟠 high | 75 | `T1134.002` | [`pua_advancedrun_suspicious_execution.yaml`](./pua_advancedrun_suspicious_execution.yaml) |
| PUA - Chisel Tunneling Tool Execution | 🟠 high | 75 | `T1090.001` | [`pua_chisel_tunneling_tool_execution.yaml`](./pua_chisel_tunneling_tool_execution.yaml) |
| PUA - CleanWipe Execution | 🟠 high | 75 | `T1685` | [`pua_cleanwipe_execution.yaml`](./pua_cleanwipe_execution.yaml) |
| PUA - Crassus Execution | 🟠 high | 75 | `T1590.001` | [`pua_crassus_execution.yaml`](./pua_crassus_execution.yaml) |
| PUA - CsExec Execution | 🟠 high | 75 | `T1587.001`, `T1569.002` | [`pua_csexec_execution.yaml`](./pua_csexec_execution.yaml) |
| PUA - DefenderCheck Execution | 🟠 high | 75 | `T1027.005` | [`pua_defendercheck_execution.yaml`](./pua_defendercheck_execution.yaml) |
| PUA - DIT Snapshot Viewer | 🟠 high | 75 | `T1003.003` | [`pua_dit_snapshot_viewer.yaml`](./pua_dit_snapshot_viewer.yaml) |
| PUA - Fast Reverse Proxy (FRP) Execution | 🟠 high | 75 | `T1090` | [`pua_fast_reverse_proxy_frp_execution.yaml`](./pua_fast_reverse_proxy_frp_execution.yaml) |
| PUA - Kernel Driver Utility (KDU) Execution | 🟠 high | 75 | `T1543.003` | [`pua_kernel_driver_utility_kdu_execution.yaml`](./pua_kernel_driver_utility_kdu_execution.yaml) |
| PUA - Memory Dump Mount Via MemProcFS | 🟠 high | 75 | `T1003`, `T1003.001`, `T1003.004`… | [`pua_memory_dump_mount_via_memprocfs.yaml`](./pua_memory_dump_mount_via_memprocfs.yaml) |
| PUA - Netcat Suspicious Execution | 🟠 high | 75 | `T1095` | [`pua_netcat_suspicious_execution.yaml`](./pua_netcat_suspicious_execution.yaml) |
| PUA - Ngrok Execution | 🟠 high | 75 | `T1572` | [`pua_ngrok_execution.yaml`](./pua_ngrok_execution.yaml) |
| PUA - Nimgrab Execution | 🟠 high | 75 | `T1105` | [`pua_nimgrab_execution.yaml`](./pua_nimgrab_execution.yaml) |
| PUA - NirCmd Execution As LOCAL SYSTEM | 🟠 high | 75 | `T1569.002` | [`pua_nircmd_execution_as_local_system.yaml`](./pua_nircmd_execution_as_local_system.yaml) |
| PUA - NPS Tunneling Tool Execution | 🟠 high | 75 | `T1090` | [`pua_nps_tunneling_tool_execution.yaml`](./pua_nps_tunneling_tool_execution.yaml) |
| PUA - NSudo Execution | 🟠 high | 75 | `T1569.002` | [`pua_nsudo_execution.yaml`](./pua_nsudo_execution.yaml) |
| PUA - PingCastle Execution From Potentially Suspicious Parent | 🟠 high | 75 | `T1595` | [`pua_pingcastle_execution_from_potentially_suspicious_parent.yaml`](./pua_pingcastle_execution_from_potentially_suspicious_parent.yaml) |
| PUA - Rclone Execution | 🟠 high | 75 | `T1567.002` | [`pua_rclone_execution.yaml`](./pua_rclone_execution.yaml) |
| PUA - Restic Backup Tool Execution | 🟠 high | 75 | `T1048`, `T1567.002` | [`pua_restic_backup_tool_execution.yaml`](./pua_restic_backup_tool_execution.yaml) |
| PUA - RunXCmd Execution | 🟠 high | 75 | `T1569.002` | [`pua_runxcmd_execution.yaml`](./pua_runxcmd_execution.yaml) |
| PUA - Seatbelt Execution | 🟠 high | 75 | `T1526`, `T1087`, `T1083` | [`pua_seatbelt_execution.yaml`](./pua_seatbelt_execution.yaml) |
| PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | 🟠 high | 75 | `T1087.002` | [`pua_suspicious_activedirectory_enumeration_via_adfind_exe.yaml`](./pua_suspicious_activedirectory_enumeration_via_adfind_exe.yaml) |
| PUA - Wsudo Suspicious Execution | 🟠 high | 75 | `T1059` | [`pua_wsudo_suspicious_execution.yaml`](./pua_wsudo_suspicious_execution.yaml) |
| PUA- IOX Tunneling Tool Execution | 🟠 high | 75 | `T1090` | [`pua_iox_tunneling_tool_execution.yaml`](./pua_iox_tunneling_tool_execution.yaml) |
| Python Function Execution Security Warning Disabled In Excel | 🟠 high | 75 | `T1685` | [`python_function_execution_security_warning_disabled_in_excel.yaml`](./python_function_execution_security_warning_disabled_in_excel.yaml) |
| Python One-Liners with Base64 Decoding | 🟠 high | 75 | `T1059.006`, `T1027.010` | [`python_one_liners_with_base64_decoding.yaml`](./python_one_liners_with_base64_decoding.yaml) |
| Python Spawning Pretty TTY on Windows | 🟠 high | 75 | `T1059` | [`python_spawning_pretty_tty_on_windows.yaml`](./python_spawning_pretty_tty_on_windows.yaml) |
| Qakbot Regsvr32 Calc Pattern | 🟠 high | 75 | — | [`qakbot_regsvr32_calc_pattern.yaml`](./qakbot_regsvr32_calc_pattern.yaml) |
| Qakbot Uninstaller Execution | 🟠 high | 75 | — | [`qakbot_uninstaller_execution.yaml`](./qakbot_uninstaller_execution.yaml) |
| Raccine Uninstall | 🟠 high | 75 | `T1685` | [`raccine_uninstall.yaml`](./raccine_uninstall.yaml) |
| Rar Usage with Password and Compression Level | 🟠 high | 75 | `T1560.001` | [`rar_usage_with_password_and_compression_level.yaml`](./rar_usage_with_password_and_compression_level.yaml) |
| Raspberry Robin Initial Execution From External Drive | 🟠 high | 75 | `T1059.001` | [`raspberry_robin_initial_execution_from_external_drive.yaml`](./raspberry_robin_initial_execution_from_external_drive.yaml) |
| Raspberry Robin Subsequent Execution of Commands | 🟠 high | 75 | `T1059.001` | [`raspberry_robin_subsequent_execution_of_commands.yaml`](./raspberry_robin_subsequent_execution_of_commands.yaml) |
| RDP Connection Allowed Via Netsh.EXE | 🟠 high | 75 | `T1686.003` | [`rdp_connection_allowed_via_netsh_exe.yaml`](./rdp_connection_allowed_via_netsh_exe.yaml) |
| RDP Port Forwarding Rule Added Via Netsh.EXE | 🟠 high | 75 | `T1090` | [`rdp_port_forwarding_rule_added_via_netsh_exe.yaml`](./rdp_port_forwarding_rule_added_via_netsh_exe.yaml) |
| RedSun - Conhost.exe Spawned by TieringEngineService.exe | 🟠 high | 75 | `T1134.002`, `T1036.005` | [`redsun_conhost_exe_spawned_by_tieringengineservice_exe.yaml`](./redsun_conhost_exe_spawned_by_tieringengineservice_exe.yaml) |
| Reg Add Suspicious Paths | 🟠 high | 75 | `T1112`, `T1685` | [`reg_add_suspicious_paths.yaml`](./reg_add_suspicious_paths.yaml) |
| Regedit as Trusted Installer | 🟠 high | 75 | `T1548` | [`regedit_as_trusted_installer.yaml`](./regedit_as_trusted_installer.yaml) |
| Registry Export of Third-Party Credentials | 🟠 high | 75 | `T1552.002` | [`registry_export_of_third_party_credentials.yaml`](./registry_export_of_third_party_credentials.yaml) |
| Regsvr32 DLL Execution With Suspicious File Extension | 🟠 high | 75 | `T1218.010` | [`regsvr32_dll_execution_with_suspicious_file_extension.yaml`](./regsvr32_dll_execution_with_suspicious_file_extension.yaml) |
| Regsvr32 Execution From Highly Suspicious Location | 🟠 high | 75 | `T1218.010` | [`regsvr32_execution_from_highly_suspicious_location.yaml`](./regsvr32_execution_from_highly_suspicious_location.yaml) |
| Remote Access Tool - Anydesk Execution From Suspicious Folder | 🟠 high | 75 | `T1219.002` | [`remote_access_tool_anydesk_execution_from_suspicious_folder.yaml`](./remote_access_tool_anydesk_execution_from_suspicious_folder.yaml) |
| Remote Access Tool - AnyDesk Silent Installation | 🟠 high | 75 | `T1219.002` | [`remote_access_tool_anydesk_silent_installation.yaml`](./remote_access_tool_anydesk_silent_installation.yaml) |
| Remote Access Tool - Renamed MeshAgent Execution - Windows | 🟠 high | 75 | `T1219.002`, `T1036.003` | [`remote_access_tool_renamed_meshagent_execution_windows.yaml`](./remote_access_tool_renamed_meshagent_execution_windows.yaml) |
| Remote Access Tool - ScreenConnect Server Web Shell Execution | 🟠 high | 75 | `T1190` | [`remote_access_tool_screenconnect_server_web_shell_execution.yaml`](./remote_access_tool_screenconnect_server_web_shell_execution.yaml) |
| Remote CHM File Download/Execution Via HH.EXE | 🟠 high | 75 | `T1218.001` | [`remote_chm_file_download_execution_via_hh_exe.yaml`](./remote_chm_file_download_execution_via_hh_exe.yaml) |
| Remote XSL Execution Via Msxsl.EXE | 🟠 high | 75 | `T1220` | [`remote_xsl_execution_via_msxsl_exe.yaml`](./remote_xsl_execution_via_msxsl_exe.yaml) |
| RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses | 🟠 high | 75 | `T1218` | [`remotefxvgpudisablement_abuse_via_atomictestharnesses.yaml`](./remotefxvgpudisablement_abuse_via_atomictestharnesses.yaml) |
| Remotely Hosted HTA File Executed Via Mshta.EXE | 🟠 high | 75 | `T1218.005` | [`remotely_hosted_hta_file_executed_via_mshta_exe.yaml`](./remotely_hosted_hta_file_executed_via_mshta_exe.yaml) |
| Renamed AdFind Execution | 🟠 high | 75 | `T1018`, `T1087.002`, `T1482`… | [`renamed_adfind_execution.yaml`](./renamed_adfind_execution.yaml) |
| Renamed AutoIt Execution | 🟠 high | 75 | `T1027` | [`renamed_autoit_execution.yaml`](./renamed_autoit_execution.yaml) |
| Renamed BrowserCore.EXE Execution | 🟠 high | 75 | `T1528`, `T1036.003` | [`renamed_browsercore_exe_execution.yaml`](./renamed_browsercore_exe_execution.yaml) |
| Renamed Cloudflared.EXE Execution | 🟠 high | 75 | `T1090.001` | [`renamed_cloudflared_exe_execution.yaml`](./renamed_cloudflared_exe_execution.yaml) |
| Renamed CreateDump Utility Execution | 🟠 high | 75 | `T1036`, `T1003.001` | [`renamed_createdump_utility_execution.yaml`](./renamed_createdump_utility_execution.yaml) |
| Renamed Gpg.EXE Execution | 🟠 high | 75 | `T1486` | [`renamed_gpg_exe_execution.yaml`](./renamed_gpg_exe_execution.yaml) |
| Renamed Jusched.EXE Execution | 🟠 high | 75 | `T1036.003` | [`renamed_jusched_exe_execution.yaml`](./renamed_jusched_exe_execution.yaml) |
| Renamed Mavinject.EXE Execution | 🟠 high | 75 | `T1055.001`, `T1218.013` | [`renamed_mavinject_exe_execution.yaml`](./renamed_mavinject_exe_execution.yaml) |
| Renamed MegaSync Execution | 🟠 high | 75 | `T1218` | [`renamed_megasync_execution.yaml`](./renamed_megasync_execution.yaml) |
| Renamed Msdt.EXE Execution | 🟠 high | 75 | `T1036.003` | [`renamed_msdt_exe_execution.yaml`](./renamed_msdt_exe_execution.yaml) |
| Renamed NetSupport RAT Execution | 🟠 high | 75 | — | [`renamed_netsupport_rat_execution.yaml`](./renamed_netsupport_rat_execution.yaml) |
| Renamed NirCmd.EXE Execution | 🟠 high | 75 | `T1059`, `T1202` | [`renamed_nircmd_exe_execution.yaml`](./renamed_nircmd_exe_execution.yaml) |
| Renamed Office Binary Execution | 🟠 high | 75 | `T1036.003` | [`renamed_office_binary_execution.yaml`](./renamed_office_binary_execution.yaml) |
| Renamed PAExec Execution | 🟠 high | 75 | `T1202` | [`renamed_paexec_execution.yaml`](./renamed_paexec_execution.yaml) |
| Renamed PingCastle Binary Execution | 🟠 high | 75 | `T1059`, `T1202` | [`renamed_pingcastle_binary_execution.yaml`](./renamed_pingcastle_binary_execution.yaml) |
| Renamed Plink Execution | 🟠 high | 75 | `T1036` | [`renamed_plink_execution.yaml`](./renamed_plink_execution.yaml) |
| Renamed ProcDump Execution | 🟠 high | 75 | `T1036.003` | [`renamed_procdump_execution.yaml`](./renamed_procdump_execution.yaml) |
| Renamed PsExec Service Execution | 🟠 high | 75 | — | [`renamed_psexec_service_execution.yaml`](./renamed_psexec_service_execution.yaml) |
| Renamed Schtasks Execution | 🟠 high | 75 | `T1036.003`, `T1053.005` | [`renamed_schtasks_execution.yaml`](./renamed_schtasks_execution.yaml) |
| Renamed SysInternals DebugView Execution | 🟠 high | 75 | `T1588.002` | [`renamed_sysinternals_debugview_execution.yaml`](./renamed_sysinternals_debugview_execution.yaml) |
| Renamed Sysinternals Sdelete Execution | 🟠 high | 75 | `T1485` | [`renamed_sysinternals_sdelete_execution.yaml`](./renamed_sysinternals_sdelete_execution.yaml) |
| Renamed Visual Studio Code Tunnel Execution | 🟠 high | 75 | `T1071.001`, `T1219` | [`renamed_visual_studio_code_tunnel_execution.yaml`](./renamed_visual_studio_code_tunnel_execution.yaml) |
| Renamed Vmnat.exe Execution | 🟠 high | 75 | `T1574.001` | [`renamed_vmnat_exe_execution.yaml`](./renamed_vmnat_exe_execution.yaml) |
| Renamed ZOHO Dctask64 Execution | 🟠 high | 75 | `T1036`, `T1055.001`, `T1202`… | [`renamed_zoho_dctask64_execution.yaml`](./renamed_zoho_dctask64_execution.yaml) |
| RestrictedAdminMode Registry Value Tampering - ProcCreation | 🟠 high | 75 | `T1112` | [`restrictedadminmode_registry_value_tampering_proccreation.yaml`](./restrictedadminmode_registry_value_tampering_proccreation.yaml) |
| Root Certificate Installed From Susp Locations | 🟠 high | 75 | `T1553.004` | [`root_certificate_installed_from_susp_locations.yaml`](./root_certificate_installed_from_susp_locations.yaml) |
| Run PowerShell Script from ADS | 🟠 high | 75 | `T1564.004` | [`run_powershell_script_from_ads.yaml`](./run_powershell_script_from_ads.yaml) |
| Run PowerShell Script from Redirected Input Stream | 🟠 high | 75 | `T1059` | [`run_powershell_script_from_redirected_input_stream.yaml`](./run_powershell_script_from_redirected_input_stream.yaml) |
| Rundll32 Execution Without CommandLine Parameters | 🟠 high | 75 | `T1202` | [`rundll32_execution_without_commandline_parameters.yaml`](./rundll32_execution_without_commandline_parameters.yaml) |
| Rundll32 Execution Without Parameters | 🟠 high | 75 | `T1021.002`, `T1570`, `T1569.002` | [`rundll32_execution_without_parameters.yaml`](./rundll32_execution_without_parameters.yaml) |
| Rundll32 Registered COM Objects | 🟠 high | 75 | `T1546.015` | [`rundll32_registered_com_objects.yaml`](./rundll32_registered_com_objects.yaml) |
| RunDLL32 Spawning Explorer | 🟠 high | 75 | `T1218.011` | [`rundll32_spawning_explorer.yaml`](./rundll32_spawning_explorer.yaml) |
| Rundll32 UNC Path Execution | 🟠 high | 75 | `T1021.002`, `T1218.011` | [`rundll32_unc_path_execution.yaml`](./rundll32_unc_path_execution.yaml) |
| RunMRU Registry Key Deletion | 🟠 high | 75 | `T1070.003` | [`runmru_registry_key_deletion.yaml`](./runmru_registry_key_deletion.yaml) |
| SafeBoot Registry Key Deleted Via Reg.EXE | 🟠 high | 75 | `T1685` | [`safeboot_registry_key_deleted_via_reg_exe.yaml`](./safeboot_registry_key_deleted_via_reg_exe.yaml) |
| Scheduled Task Creation Masquerading as System Processes | 🟠 high | 75 | `T1053.005`, `T1036.004`, `T1036.005` | [`scheduled_task_creation_masquerading_as_system_processes.yaml`](./scheduled_task_creation_masquerading_as_system_processes.yaml) |
| Scheduled Task Executing Encoded Payload from Registry | 🟠 high | 75 | `T1053.005`, `T1059.001` | [`scheduled_task_executing_encoded_payload_from_registry.yaml`](./scheduled_task_executing_encoded_payload_from_registry.yaml) |
| Schtasks Creation Or Modification With SYSTEM Privileges | 🟠 high | 75 | `T1053.005` | [`schtasks_creation_or_modification_with_system_privileges.yaml`](./schtasks_creation_or_modification_with_system_privileges.yaml) |
| Schtasks From Suspicious Folders | 🟠 high | 75 | `T1053.005` | [`schtasks_from_suspicious_folders.yaml`](./schtasks_from_suspicious_folders.yaml) |
| Script Event Consumer Spawning Process | 🟠 high | 75 | `T1047` | [`script_event_consumer_spawning_process.yaml`](./script_event_consumer_spawning_process.yaml) |
| Script Interpreter Execution From Suspicious Folder | 🟠 high | 75 | `T1059` | [`script_interpreter_execution_from_suspicious_folder.yaml`](./script_interpreter_execution_from_suspicious_folder.yaml) |
| Script Interpreter Spawning Credential Scanner - Windows | 🟠 high | 75 | `T1552`, `T1005`, `T1059.007` | [`script_interpreter_spawning_credential_scanner_windows.yaml`](./script_interpreter_spawning_credential_scanner_windows.yaml) |
| Sdiagnhost Calling Suspicious Child Process | 🟠 high | 75 | `T1036`, `T1218` | [`sdiagnhost_calling_suspicious_child_process.yaml`](./sdiagnhost_calling_suspicious_child_process.yaml) |
| Security Event Logging Disabled via MiniNt Registry Key - Process | 🟠 high | 75 | `T1685.001`, `T1112` | [`security_event_logging_disabled_via_minint_registry_key_process.yaml`](./security_event_logging_disabled_via_minint_registry_key_process.yaml) |
| Security Privileges Enumeration Via Whoami.EXE | 🟠 high | 75 | `T1033` | [`security_privileges_enumeration_via_whoami_exe.yaml`](./security_privileges_enumeration_via_whoami_exe.yaml) |
| Security Service Disabled Via Reg.EXE | 🟠 high | 75 | `T1685` | [`security_service_disabled_via_reg_exe.yaml`](./security_service_disabled_via_reg_exe.yaml) |
| Self Extracting Package Creation Via Iexpress.EXE From Potentially Suspicious Location | 🟠 high | 75 | `T1218` | [`self_extracting_package_creation_via_iexpress_exe_from_potentially_suspicious_location.yaml`](./self_extracting_package_creation_via_iexpress_exe_from_potentially_suspicious_location.yaml) |
| Sensitive File Access Via Volume Shadow Copy Backup | 🟠 high | 75 | `T1490` | [`sensitive_file_access_via_volume_shadow_copy_backup.yaml`](./sensitive_file_access_via_volume_shadow_copy_backup.yaml) |
| Sensitive File Dump Via Print.EXE | 🟠 high | 75 | `T1003.003`, `T1003.002`, `T1218` | [`sensitive_file_dump_via_print_exe.yaml`](./sensitive_file_dump_via_print_exe.yaml) |
| Sensitive File Dump Via Wbadmin.EXE | 🟠 high | 75 | `T1003.003` | [`sensitive_file_dump_via_wbadmin_exe.yaml`](./sensitive_file_dump_via_wbadmin_exe.yaml) |
| Sensitive File Recovery From Backup Via Wbadmin.EXE | 🟠 high | 75 | `T1003.003` | [`sensitive_file_recovery_from_backup_via_wbadmin_exe.yaml`](./sensitive_file_recovery_from_backup_via_wbadmin_exe.yaml) |
| Serpent Backdoor Payload Execution Via Scheduled Task | 🟠 high | 75 | `T1053.005`, `T1059.006` | [`serpent_backdoor_payload_execution_via_scheduled_task.yaml`](./serpent_backdoor_payload_execution_via_scheduled_task.yaml) |
| Service DACL Abuse To Hide Services Via Sc.EXE | 🟠 high | 75 | `T1574.011` | [`service_dacl_abuse_to_hide_services_via_sc_exe.yaml`](./service_dacl_abuse_to_hide_services_via_sc_exe.yaml) |
| Service Registry Key Deleted Via Reg.EXE | 🟠 high | 75 | `T1685` | [`service_registry_key_deleted_via_reg_exe.yaml`](./service_registry_key_deleted_via_reg_exe.yaml) |
| Set Suspicious Files as System Files Using Attrib.EXE | 🟠 high | 75 | `T1564.001` | [`set_suspicious_files_as_system_files_using_attrib_exe.yaml`](./set_suspicious_files_as_system_files_using_attrib_exe.yaml) |
| Shadow Copies Deletion Using Operating Systems Utilities | 🟠 high | 75 | `T1070`, `T1490` | [`shadow_copies_deletion_using_operating_systems_utilities.yaml`](./shadow_copies_deletion_using_operating_systems_utilities.yaml) |
| Shai-Hulud Malicious Bun Execution | 🟠 high | 75 | `T1195.002`, `T1203` | [`shai_hulud_malicious_bun_execution.yaml`](./shai_hulud_malicious_bun_execution.yaml) |
| Shai-Hulud Malware Indicators - Windows | 🟠 high | 75 | `T1059` | [`shai_hulud_malware_indicators_windows.yaml`](./shai_hulud_malware_indicators_windows.yaml) |
| Shell32 DLL Execution in Suspicious Directory | 🟠 high | 75 | `T1218.011` | [`shell32_dll_execution_in_suspicious_directory.yaml`](./shell32_dll_execution_in_suspicious_directory.yaml) |
| ShimCache Flush | 🟠 high | 75 | `T1112` | [`shimcache_flush.yaml`](./shimcache_flush.yaml) |
| Small Sieve Malware CommandLine Indicator | 🟠 high | 75 | `T1574.001` | [`small_sieve_malware_commandline_indicator.yaml`](./small_sieve_malware_commandline_indicator.yaml) |
| Sofacy Trojan Loader Activity | 🟠 high | 75 | `T1059.003`, `T1218.011` | [`sofacy_trojan_loader_activity.yaml`](./sofacy_trojan_loader_activity.yaml) |
| SOURGUM Actor Behaviours | 🟠 high | 75 | `T1546`, `T1546.015` | [`sourgum_actor_behaviours.yaml`](./sourgum_actor_behaviours.yaml) |
| SQLite Chromium Profile Data DB Access | 🟠 high | 75 | `T1539`, `T1555.003`, `T1005` | [`sqlite_chromium_profile_data_db_access.yaml`](./sqlite_chromium_profile_data_db_access.yaml) |
| SQLite Firefox Profile Data DB Access | 🟠 high | 75 | `T1539`, `T1005` | [`sqlite_firefox_profile_data_db_access.yaml`](./sqlite_firefox_profile_data_db_access.yaml) |
| Suspect Svchost Activity | 🟠 high | 75 | `T1055` | [`suspect_svchost_activity.yaml`](./suspect_svchost_activity.yaml) |
| Suspicious Active Directory Database Snapshot Via ADExplorer | 🟠 high | 75 | `T1087.002`, `T1069.002`, `T1482` | [`suspicious_active_directory_database_snapshot_via_adexplorer.yaml`](./suspicious_active_directory_database_snapshot_via_adexplorer.yaml) |
| Suspicious AddinUtil.EXE CommandLine Execution | 🟠 high | 75 | `T1218` | [`suspicious_addinutil_exe_commandline_execution.yaml`](./suspicious_addinutil_exe_commandline_execution.yaml) |
| Suspicious Advpack Call Via Rundll32.EXE | 🟠 high | 75 | — | [`suspicious_advpack_call_via_rundll32_exe.yaml`](./suspicious_advpack_call_via_rundll32_exe.yaml) |
| Suspicious AgentExecutor PowerShell Execution | 🟠 high | 75 | `T1218` | [`suspicious_agentexecutor_powershell_execution.yaml`](./suspicious_agentexecutor_powershell_execution.yaml) |
| Suspicious ArcSOC.exe Child Process | 🟠 high | 75 | `T1059`, `T1203` | [`suspicious_arcsoc_exe_child_process.yaml`](./suspicious_arcsoc_exe_child_process.yaml) |
| Suspicious Autorun Registry Modified via WMI | 🟠 high | 75 | `T1547.001`, `T1047` | [`suspicious_autorun_registry_modified_via_wmi.yaml`](./suspicious_autorun_registry_modified_via_wmi.yaml) |
| Suspicious Binary In User Directory Spawned From Office Application | 🟠 high | 75 | `T1204.002` | [`suspicious_binary_in_user_directory_spawned_from_office_application.yaml`](./suspicious_binary_in_user_directory_spawned_from_office_application.yaml) |
| Suspicious BitLocker Access Agent Update Utility Execution | 🟠 high | 75 | `T1218`, `T1021.003` | [`suspicious_bitlocker_access_agent_update_utility_execution.yaml`](./suspicious_bitlocker_access_agent_update_utility_execution.yaml) |
| Suspicious Calculator Usage | 🟠 high | 75 | `T1036` | [`suspicious_calculator_usage.yaml`](./suspicious_calculator_usage.yaml) |
| Suspicious CertReq Command to Download | 🟠 high | 75 | `T1105` | [`suspicious_certreq_command_to_download.yaml`](./suspicious_certreq_command_to_download.yaml) |
| Suspicious Child Process Created as System | 🟠 high | 75 | `T1134.002` | [`suspicious_child_process_created_as_system.yaml`](./suspicious_child_process_created_as_system.yaml) |
| Suspicious Child Process of AspNetCompiler | 🟠 high | 75 | `T1127` | [`suspicious_child_process_of_aspnetcompiler.yaml`](./suspicious_child_process_of_aspnetcompiler.yaml) |
| Suspicious Child Process Of BgInfo.EXE | 🟠 high | 75 | `T1059.005`, `T1218`, `T1202` | [`suspicious_child_process_of_bginfo_exe.yaml`](./suspicious_child_process_of_bginfo_exe.yaml) |
| Suspicious Child Process Of Manage Engine ServiceDesk | 🟠 high | 75 | `T1102` | [`suspicious_child_process_of_manage_engine_servicedesk.yaml`](./suspicious_child_process_of_manage_engine_servicedesk.yaml) |
| Suspicious Child Process of Notepad++ Updater - GUP.Exe | 🟠 high | 75 | `T1195.002`, `T1557` | [`suspicious_child_process_of_notepad_updater_gup_exe.yaml`](./suspicious_child_process_of_notepad_updater_gup_exe.yaml) |
| Suspicious Child Process of SolarWinds WebHelpDesk | 🟠 high | 75 | `T1190` | [`suspicious_child_process_of_solarwinds_webhelpdesk.yaml`](./suspicious_child_process_of_solarwinds_webhelpdesk.yaml) |
| Suspicious Child Process Of SQL Server | 🟠 high | 75 | `T1505.003`, `T1190` | [`suspicious_child_process_of_sql_server.yaml`](./suspicious_child_process_of_sql_server.yaml) |
| Suspicious Child Process Of Wermgr.EXE | 🟠 high | 75 | `T1055`, `T1036` | [`suspicious_child_process_of_wermgr_exe.yaml`](./suspicious_child_process_of_wermgr_exe.yaml) |
| Suspicious Chromium Browser Instance Executed With Custom Extension | 🟠 high | 75 | `T1176.001` | [`suspicious_chromium_browser_instance_executed_with_custom_extension.yaml`](./suspicious_chromium_browser_instance_executed_with_custom_extension.yaml) |
| Suspicious ClickFix/FileFix Execution Pattern | 🟠 high | 75 | `T1204.001`, `T1204.004` | [`suspicious_clickfix_filefix_execution_pattern.yaml`](./suspicious_clickfix_filefix_execution_pattern.yaml) |
| Suspicious Command Patterns In Scheduled Task Creation | 🟠 high | 75 | `T1053.005` | [`suspicious_command_patterns_in_scheduled_task_creation.yaml`](./suspicious_command_patterns_in_scheduled_task_creation.yaml) |
| Suspicious Control Panel DLL Load | 🟠 high | 75 | `T1218.011` | [`suspicious_control_panel_dll_load.yaml`](./suspicious_control_panel_dll_load.yaml) |
| Suspicious Curl.EXE Download | 🟠 high | 75 | `T1105` | [`suspicious_curl_exe_download.yaml`](./suspicious_curl_exe_download.yaml) |
| Suspicious CustomShellHost Execution | 🟠 high | 75 | `T1216` | [`suspicious_customshellhost_execution.yaml`](./suspicious_customshellhost_execution.yaml) |
| Suspicious Debugger Registration Cmdline | 🟠 high | 75 | `T1546.008` | [`suspicious_debugger_registration_cmdline.yaml`](./suspicious_debugger_registration_cmdline.yaml) |
| Suspicious Desktopimgdownldr Command | 🟠 high | 75 | `T1105` | [`suspicious_desktopimgdownldr_command.yaml`](./suspicious_desktopimgdownldr_command.yaml) |
| Suspicious DLL Loaded via CertOC.EXE | 🟠 high | 75 | `T1218` | [`suspicious_dll_loaded_via_certoc_exe.yaml`](./suspicious_dll_loaded_via_certoc_exe.yaml) |
| Suspicious Double Extension File Execution | 🟠 high | 75 | `T1566.001` | [`suspicious_double_extension_file_execution.yaml`](./suspicious_double_extension_file_execution.yaml) |
| Suspicious Download From Direct IP Via Bitsadmin | 🟠 high | 75 | `T1197`, `T1036.003` | [`suspicious_download_from_direct_ip_via_bitsadmin.yaml`](./suspicious_download_from_direct_ip_via_bitsadmin.yaml) |
| Suspicious Download From File-Sharing Website Via Bitsadmin | 🟠 high | 75 | `T1197`, `T1036.003`, `T1105` | [`suspicious_download_from_file_sharing_website_via_bitsadmin.yaml`](./suspicious_download_from_file_sharing_website_via_bitsadmin.yaml) |
| Suspicious Download from Office Domain | 🟠 high | 75 | `T1105`, `T1608` | [`suspicious_download_from_office_domain.yaml`](./suspicious_download_from_office_domain.yaml) |
| Suspicious Driver/DLL Installation Via Odbcconf.EXE | 🟠 high | 75 | `T1218.008` | [`suspicious_driver_dll_installation_via_odbcconf_exe.yaml`](./suspicious_driver_dll_installation_via_odbcconf_exe.yaml) |
| Suspicious DumpMinitool Execution | 🟠 high | 75 | `T1036`, `T1003.001` | [`suspicious_dumpminitool_execution.yaml`](./suspicious_dumpminitool_execution.yaml) |
| Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call | 🟠 high | 75 | `T1059.001`, `T1027` | [`suspicious_encoded_and_obfuscated_reflection_assembly_load_function_call.yaml`](./suspicious_encoded_and_obfuscated_reflection_assembly_load_function_call.yaml) |
| Suspicious Encoded PowerShell Command Line | 🟠 high | 75 | `T1059.001` | [`suspicious_encoded_powershell_command_line.yaml`](./suspicious_encoded_powershell_command_line.yaml) |
| Suspicious Eventlog Clearing or Configuration Change Activity | 🟠 high | 75 | `T1685.005`, `T1685.001` | [`suspicious_eventlog_clearing_or_configuration_change_activity.yaml`](./suspicious_eventlog_clearing_or_configuration_change_activity.yaml) |
| Suspicious Execution From Outlook Temporary Folder | 🟠 high | 75 | `T1566.001` | [`suspicious_execution_from_outlook_temporary_folder.yaml`](./suspicious_execution_from_outlook_temporary_folder.yaml) |
| Suspicious Execution Location Of Wermgr.EXE | 🟠 high | 75 | — | [`suspicious_execution_location_of_wermgr_exe.yaml`](./suspicious_execution_location_of_wermgr_exe.yaml) |
| Suspicious Explorer Process with Whitespace Padding - ClickFix/FileFix | 🟠 high | 75 | `T1204.004`, `T1027.010` | [`suspicious_explorer_process_with_whitespace_padding_clickfix_filefix.yaml`](./suspicious_explorer_process_with_whitespace_padding_clickfix_filefix.yaml) |
| Suspicious File Download From File Sharing Domain Via Curl.EXE | 🟠 high | 75 | — | [`suspicious_file_download_from_file_sharing_domain_via_curl_exe.yaml`](./suspicious_file_download_from_file_sharing_domain_via_curl_exe.yaml) |
| Suspicious File Download From File Sharing Domain Via Wget.EXE | 🟠 high | 75 | — | [`suspicious_file_download_from_file_sharing_domain_via_wget_exe.yaml`](./suspicious_file_download_from_file_sharing_domain_via_wget_exe.yaml) |
| Suspicious File Download From IP Via Curl.EXE | 🟠 high | 75 | — | [`suspicious_file_download_from_ip_via_curl_exe.yaml`](./suspicious_file_download_from_ip_via_curl_exe.yaml) |
| Suspicious File Download From IP Via Wget.EXE | 🟠 high | 75 | — | [`suspicious_file_download_from_ip_via_wget_exe.yaml`](./suspicious_file_download_from_ip_via_wget_exe.yaml) |
| Suspicious File Download From IP Via Wget.EXE - Paths | 🟠 high | 75 | — | [`suspicious_file_download_from_ip_via_wget_exe_paths.yaml`](./suspicious_file_download_from_ip_via_wget_exe_paths.yaml) |
| Suspicious File Downloaded From Direct IP Via Certutil.EXE | 🟠 high | 75 | `T1027`, `T1105` | [`suspicious_file_downloaded_from_direct_ip_via_certutil_exe.yaml`](./suspicious_file_downloaded_from_direct_ip_via_certutil_exe.yaml) |
| Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE | 🟠 high | 75 | `T1027`, `T1105` | [`suspicious_file_downloaded_from_file_sharing_website_via_certutil_exe.yaml`](./suspicious_file_downloaded_from_file_sharing_website_via_certutil_exe.yaml) |
| Suspicious File Encoded To Base64 Via Certutil.EXE | 🟠 high | 75 | `T1027` | [`suspicious_file_encoded_to_base64_via_certutil_exe.yaml`](./suspicious_file_encoded_to_base64_via_certutil_exe.yaml) |
| Suspicious File Execution From Internet Hosted WebDav Share | 🟠 high | 75 | `T1059.001` | [`suspicious_file_execution_from_internet_hosted_webdav_share.yaml`](./suspicious_file_execution_from_internet_hosted_webdav_share.yaml) |
| Suspicious FileFix Execution Pattern | 🟠 high | 75 | `T1204.004` | [`suspicious_filefix_execution_pattern.yaml`](./suspicious_filefix_execution_pattern.yaml) |
| Suspicious Greedy Compression Using Rar.EXE | 🟠 high | 75 | `T1059` | [`suspicious_greedy_compression_using_rar_exe.yaml`](./suspicious_greedy_compression_using_rar_exe.yaml) |
| Suspicious GrpConv Execution | 🟠 high | 75 | `T1547` | [`suspicious_grpconv_execution.yaml`](./suspicious_grpconv_execution.yaml) |
| Suspicious GUP Usage | 🟠 high | 75 | `T1574.001` | [`suspicious_gup_usage.yaml`](./suspicious_gup_usage.yaml) |
| Suspicious HH.EXE Execution | 🟠 high | 75 | `T1047`, `T1059.001`, `T1059.003`… | [`suspicious_hh_exe_execution.yaml`](./suspicious_hh_exe_execution.yaml) |
| Suspicious HWP Sub Processes | 🟠 high | 75 | `T1566.001`, `T1203`, `T1059.003` | [`suspicious_hwp_sub_processes.yaml`](./suspicious_hwp_sub_processes.yaml) |
| Suspicious IIS Module Registration | 🟠 high | 75 | `T1505.004` | [`suspicious_iis_module_registration.yaml`](./suspicious_iis_module_registration.yaml) |
| Suspicious Invoke-WebRequest Execution | 🟠 high | 75 | `T1105` | [`suspicious_invoke_webrequest_execution.yaml`](./suspicious_invoke_webrequest_execution.yaml) |
| Suspicious JavaScript Execution Via Mshta.EXE | 🟠 high | 75 | `T1218.005` | [`suspicious_javascript_execution_via_mshta_exe.yaml`](./suspicious_javascript_execution_via_mshta_exe.yaml) |
| Suspicious Kerberos Ticket Request via CLI | 🟠 high | 75 | `T1558.003` | [`suspicious_kerberos_ticket_request_via_cli.yaml`](./suspicious_kerberos_ticket_request_via_cli.yaml) |
| Suspicious Kernel Dump Using Dtrace | 🟠 high | 75 | `T1082` | [`suspicious_kernel_dump_using_dtrace.yaml`](./suspicious_kernel_dump_using_dtrace.yaml) |
| Suspicious Key Manager Access | 🟠 high | 75 | `T1555.004` | [`suspicious_key_manager_access.yaml`](./suspicious_key_manager_access.yaml) |
| Suspicious Manipulation Of Default Accounts Via Net.EXE | 🟠 high | 75 | `T1560.001` | [`suspicious_manipulation_of_default_accounts_via_net_exe.yaml`](./suspicious_manipulation_of_default_accounts_via_net_exe.yaml) |
| Suspicious Microsoft Office Child Process | 🟠 high | 75 | `T1047`, `T1204.002`, `T1218.010` | [`suspicious_microsoft_office_child_process.yaml`](./suspicious_microsoft_office_child_process.yaml) |
| Suspicious Microsoft OneNote Child Process | 🟠 high | 75 | `T1566`, `T1566.001` | [`suspicious_microsoft_onenote_child_process.yaml`](./suspicious_microsoft_onenote_child_process.yaml) |
| Suspicious Modification Of Scheduled Tasks | 🟠 high | 75 | `T1053.005` | [`suspicious_modification_of_scheduled_tasks.yaml`](./suspicious_modification_of_scheduled_tasks.yaml) |
| Suspicious MSDT Parent Process | 🟠 high | 75 | `T1036`, `T1218` | [`suspicious_msdt_parent_process.yaml`](./suspicious_msdt_parent_process.yaml) |
| Suspicious MSHTA Child Process | 🟠 high | 75 | `T1218.005` | [`suspicious_mshta_child_process.yaml`](./suspicious_mshta_child_process.yaml) |
| Suspicious Mshta.EXE Execution Patterns | 🟠 high | 75 | `T1106` | [`suspicious_mshta_exe_execution_patterns.yaml`](./suspicious_mshta_exe_execution_patterns.yaml) |
| Suspicious Mstsc.EXE Execution With Local RDP File | 🟠 high | 75 | `T1219.002` | [`suspicious_mstsc_exe_execution_with_local_rdp_file.yaml`](./suspicious_mstsc_exe_execution_with_local_rdp_file.yaml) |
| Suspicious New Service Creation | 🟠 high | 75 | `T1543.003` | [`suspicious_new_service_creation.yaml`](./suspicious_new_service_creation.yaml) |
| Suspicious NTLM Authentication on the Printer Spooler Service | 🟠 high | 75 | `T1212` | [`suspicious_ntlm_authentication_on_the_printer_spooler_service.yaml`](./suspicious_ntlm_authentication_on_the_printer_spooler_service.yaml) |
| Suspicious Obfuscated PowerShell Code | 🟠 high | 75 | — | [`suspicious_obfuscated_powershell_code.yaml`](./suspicious_obfuscated_powershell_code.yaml) |
| Suspicious Outlook Child Process | 🟠 high | 75 | `T1204.002` | [`suspicious_outlook_child_process.yaml`](./suspicious_outlook_child_process.yaml) |
| Suspicious Parent Double Extension File Execution | 🟠 high | 75 | `T1036.007` | [`suspicious_parent_double_extension_file_execution.yaml`](./suspicious_parent_double_extension_file_execution.yaml) |
| Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | 🟠 high | 75 | `T1059` | [`suspicious_persistence_via_vmwaretoolboxcmd_exe_vm_state_change_script.yaml`](./suspicious_persistence_via_vmwaretoolboxcmd_exe_vm_state_change_script.yaml) |
| Suspicious Ping/Del Command Combination | 🟠 high | 75 | `T1070.004` | [`suspicious_ping_del_command_combination.yaml`](./suspicious_ping_del_command_combination.yaml) |
| Suspicious Plink Port Forwarding | 🟠 high | 75 | `T1572`, `T1021.001` | [`suspicious_plink_port_forwarding.yaml`](./suspicious_plink_port_forwarding.yaml) |
| Suspicious PowerShell Download and Execute Pattern | 🟠 high | 75 | `T1059.001` | [`suspicious_powershell_download_and_execute_pattern.yaml`](./suspicious_powershell_download_and_execute_pattern.yaml) |
| Suspicious PowerShell Encoded Command Patterns | 🟠 high | 75 | `T1059.001` | [`suspicious_powershell_encoded_command_patterns.yaml`](./suspicious_powershell_encoded_command_patterns.yaml) |
| Suspicious PowerShell IEX Execution Patterns | 🟠 high | 75 | `T1059.001` | [`suspicious_powershell_iex_execution_patterns.yaml`](./suspicious_powershell_iex_execution_patterns.yaml) |
| Suspicious PowerShell Parameter Substring | 🟠 high | 75 | `T1059.001` | [`suspicious_powershell_parameter_substring.yaml`](./suspicious_powershell_parameter_substring.yaml) |
| Suspicious PowerShell Parent Process | 🟠 high | 75 | `T1059.001` | [`suspicious_powershell_parent_process.yaml`](./suspicious_powershell_parent_process.yaml) |
| Suspicious PrinterPorts Creation (CVE-2020-1048) | 🟠 high | 75 | `T1059.001` | [`suspicious_printerports_creation_cve_2020_1048.yaml`](./suspicious_printerports_creation_cve_2020_1048.yaml) |
| Suspicious Process By Web Server Process | 🟠 high | 75 | `T1505.003`, `T1190` | [`suspicious_process_by_web_server_process.yaml`](./suspicious_process_by_web_server_process.yaml) |
| Suspicious Process Created Via Wmic.EXE | 🟠 high | 75 | `T1047` | [`suspicious_process_created_via_wmic_exe.yaml`](./suspicious_process_created_via_wmic_exe.yaml) |
| Suspicious Process Execution From Fake Recycle.Bin Folder | 🟠 high | 75 | — | [`suspicious_process_execution_from_fake_recycle_bin_folder.yaml`](./suspicious_process_execution_from_fake_recycle_bin_folder.yaml) |
| Suspicious Process Masquerading As SvcHost.EXE | 🟠 high | 75 | `T1036.005` | [`suspicious_process_masquerading_as_svchost_exe.yaml`](./suspicious_process_masquerading_as_svchost_exe.yaml) |
| Suspicious Process Parents | 🟠 high | 75 | `T1036` | [`suspicious_process_parents.yaml`](./suspicious_process_parents.yaml) |
| Suspicious Process Patterns NTDS.DIT Exfil | 🟠 high | 75 | `T1003.003` | [`suspicious_process_patterns_ntds_dit_exfil.yaml`](./suspicious_process_patterns_ntds_dit_exfil.yaml) |
| Suspicious Process Spawned by CentreStack Portal AppPool | 🟠 high | 75 | `T1059.003`, `T1505.003` | [`suspicious_process_spawned_by_centrestack_portal_apppool.yaml`](./suspicious_process_spawned_by_centrestack_portal_apppool.yaml) |
| Suspicious Processes Spawned by Java.EXE | 🟠 high | 75 | — | [`suspicious_processes_spawned_by_java_exe.yaml`](./suspicious_processes_spawned_by_java_exe.yaml) |
| Suspicious Processes Spawned by WinRM | 🟠 high | 75 | `T1190` | [`suspicious_processes_spawned_by_winrm.yaml`](./suspicious_processes_spawned_by_winrm.yaml) |
| Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE | 🟠 high | 75 | `T1686.003` | [`suspicious_program_location_whitelisted_in_firewall_via_netsh_exe.yaml`](./suspicious_program_location_whitelisted_in_firewall_via_netsh_exe.yaml) |
| Suspicious Program Names | 🟠 high | 75 | `T1059` | [`suspicious_program_names.yaml`](./suspicious_program_names.yaml) |
| Suspicious Provlaunch.EXE Child Process | 🟠 high | 75 | `T1218` | [`suspicious_provlaunch_exe_child_process.yaml`](./suspicious_provlaunch_exe_child_process.yaml) |
| Suspicious RazerInstaller Explorer Subprocess | 🟠 high | 75 | `T1553` | [`suspicious_razerinstaller_explorer_subprocess.yaml`](./suspicious_razerinstaller_explorer_subprocess.yaml) |
| Suspicious RDP Redirect Using TSCON | 🟠 high | 75 | `T1563.002`, `T1021.001` | [`suspicious_rdp_redirect_using_tscon.yaml`](./suspicious_rdp_redirect_using_tscon.yaml) |
| Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS | 🟠 high | 75 | `T1615`, `T1059.005` | [`suspicious_reconnaissance_activity_via_gathernetworkinfo_vbs.yaml`](./suspicious_reconnaissance_activity_via_gathernetworkinfo_vbs.yaml) |
| Suspicious Redirection to Local Admin Share | 🟠 high | 75 | `T1048` | [`suspicious_redirection_to_local_admin_share.yaml`](./suspicious_redirection_to_local_admin_share.yaml) |
| Suspicious Reg Add BitLocker | 🟠 high | 75 | `T1486` | [`suspicious_reg_add_bitlocker.yaml`](./suspicious_reg_add_bitlocker.yaml) |
| Suspicious Registry Modification From ADS Via Regini.EXE | 🟠 high | 75 | `T1112` | [`suspicious_registry_modification_from_ads_via_regini_exe.yaml`](./suspicious_registry_modification_from_ads_via_regini_exe.yaml) |
| Suspicious Regsvr32 Execution From Remote Share | 🟠 high | 75 | `T1218.010` | [`suspicious_regsvr32_execution_from_remote_share.yaml`](./suspicious_regsvr32_execution_from_remote_share.yaml) |
| Suspicious Remote Child Process From Outlook | 🟠 high | 75 | `T1059`, `T1202` | [`suspicious_remote_child_process_from_outlook.yaml`](./suspicious_remote_child_process_from_outlook.yaml) |
| Suspicious Response File Execution Via Odbcconf.EXE | 🟠 high | 75 | `T1218.008` | [`suspicious_response_file_execution_via_odbcconf_exe.yaml`](./suspicious_response_file_execution_via_odbcconf_exe.yaml) |
| Suspicious Rundll32 Activity Invoking Sys File | 🟠 high | 75 | `T1218.011` | [`suspicious_rundll32_activity_invoking_sys_file.yaml`](./suspicious_rundll32_activity_invoking_sys_file.yaml) |
| Suspicious Rundll32 Execution With Image Extension | 🟠 high | 75 | `T1218.011` | [`suspicious_rundll32_execution_with_image_extension.yaml`](./suspicious_rundll32_execution_with_image_extension.yaml) |
| Suspicious Rundll32 Invoking Inline VBScript | 🟠 high | 75 | `T1055` | [`suspicious_rundll32_invoking_inline_vbscript.yaml`](./suspicious_rundll32_invoking_inline_vbscript.yaml) |
| Suspicious Scheduled Task Creation Involving Temp Folder | 🟠 high | 75 | `T1053.005` | [`suspicious_scheduled_task_creation_involving_temp_folder.yaml`](./suspicious_scheduled_task_creation_involving_temp_folder.yaml) |
| Suspicious Schtasks Execution AppData Folder | 🟠 high | 75 | `T1053.005`, `T1059.001` | [`suspicious_schtasks_execution_appdata_folder.yaml`](./suspicious_schtasks_execution_appdata_folder.yaml) |
| Suspicious Schtasks Schedule Types | 🟠 high | 75 | `T1053.005` | [`suspicious_schtasks_schedule_types.yaml`](./suspicious_schtasks_schedule_types.yaml) |
| Suspicious Serv-U Process Pattern | 🟠 high | 75 | `T1555` | [`suspicious_serv_u_process_pattern.yaml`](./suspicious_serv_u_process_pattern.yaml) |
| Suspicious Service Binary Directory | 🟠 high | 75 | `T1202` | [`suspicious_service_binary_directory.yaml`](./suspicious_service_binary_directory.yaml) |
| Suspicious Service DACL Modification Via Set-Service Cmdlet | 🟠 high | 75 | `T1543.003` | [`suspicious_service_dacl_modification_via_set_service_cmdlet.yaml`](./suspicious_service_dacl_modification_via_set_service_cmdlet.yaml) |
| Suspicious Service Path Modification | 🟠 high | 75 | `T1543.003` | [`suspicious_service_path_modification.yaml`](./suspicious_service_path_modification.yaml) |
| Suspicious ShellExec_RunDLL Call Via Ordinal | 🟠 high | 75 | `T1218.011` | [`suspicious_shellexec_rundll_call_via_ordinal.yaml`](./suspicious_shellexec_rundll_call_via_ordinal.yaml) |
| Suspicious Shells Spawn by Java Utility Keytool | 🟠 high | 75 | — | [`suspicious_shells_spawn_by_java_utility_keytool.yaml`](./suspicious_shells_spawn_by_java_utility_keytool.yaml) |
| Suspicious Speech Runtime Binary Child Process | 🟠 high | 75 | `T1021.003`, `T1218` | [`suspicious_speech_runtime_binary_child_process.yaml`](./suspicious_speech_runtime_binary_child_process.yaml) |
| Suspicious Splwow64 Without Params | 🟠 high | 75 | `T1202` | [`suspicious_splwow64_without_params.yaml`](./suspicious_splwow64_without_params.yaml) |
| Suspicious Spool Service Child Process | 🟠 high | 75 | `T1203`, `T1068` | [`suspicious_spool_service_child_process.yaml`](./suspicious_spool_service_child_process.yaml) |
| Suspicious Sysmon as Execution Parent | 🟠 high | 75 | `T1068` | [`suspicious_sysmon_as_execution_parent.yaml`](./suspicious_sysmon_as_execution_parent.yaml) |
| Suspicious SYSTEM User Process Creation | 🟠 high | 75 | `T1134`, `T1003`, `T1027` | [`suspicious_system_user_process_creation.yaml`](./suspicious_system_user_process_creation.yaml) |
| Suspicious TSCON Start as SYSTEM | 🟠 high | 75 | `T1219.002` | [`suspicious_tscon_start_as_system.yaml`](./suspicious_tscon_start_as_system.yaml) |
| Suspicious UltraVNC Execution | 🟠 high | 75 | `T1021.005` | [`suspicious_ultravnc_execution.yaml`](./suspicious_ultravnc_execution.yaml) |
| Suspicious Uninstall of Windows Defender Feature via PowerShell | 🟠 high | 75 | `T1685` | [`suspicious_uninstall_of_windows_defender_feature_via_powershell.yaml`](./suspicious_uninstall_of_windows_defender_feature_via_powershell.yaml) |
| Suspicious Usage Of ShellExec_RunDLL | 🟠 high | 75 | — | [`suspicious_usage_of_shellexec_rundll.yaml`](./suspicious_usage_of_shellexec_rundll.yaml) |
| Suspicious Use of CSharp Interactive Console | 🟠 high | 75 | `T1127` | [`suspicious_use_of_csharp_interactive_console.yaml`](./suspicious_use_of_csharp_interactive_console.yaml) |
| Suspicious VBScript UN2452 Pattern | 🟠 high | 75 | `T1547.001` | [`suspicious_vbscript_un2452_pattern.yaml`](./suspicious_vbscript_un2452_pattern.yaml) |
| Suspicious Velociraptor Child Process | 🟠 high | 75 | `T1219` | [`suspicious_velociraptor_child_process.yaml`](./suspicious_velociraptor_child_process.yaml) |
| Suspicious WebDav Client Execution Via Rundll32.EXE | 🟠 high | 75 | `T1048.003` | [`suspicious_webdav_client_execution_via_rundll32_exe.yaml`](./suspicious_webdav_client_execution_via_rundll32_exe.yaml) |
| Suspicious Windows Defender Registry Key Tampering Via Reg.EXE | 🟠 high | 75 | `T1685` | [`suspicious_windows_defender_registry_key_tampering_via_reg_exe.yaml`](./suspicious_windows_defender_registry_key_tampering_via_reg_exe.yaml) |
| Suspicious Windows Trace ETW Session Tamper Via Logman.EXE | 🟠 high | 75 | `T1685`, `T1685.005` | [`suspicious_windows_trace_etw_session_tamper_via_logman_exe.yaml`](./suspicious_windows_trace_etw_session_tamper_via_logman_exe.yaml) |
| Suspicious Windows Update Agent Empty Cmdline | 🟠 high | 75 | `T1036` | [`suspicious_windows_update_agent_empty_cmdline.yaml`](./suspicious_windows_update_agent_empty_cmdline.yaml) |
| Suspicious WMIC Execution Via Office Process | 🟠 high | 75 | `T1204.002`, `T1047`, `T1218.010` | [`suspicious_wmic_execution_via_office_process.yaml`](./suspicious_wmic_execution_via_office_process.yaml) |
| Suspicious WmiPrvSE Child Process | 🟠 high | 75 | `T1047`, `T1204.002`, `T1218.010` | [`suspicious_wmiprvse_child_process.yaml`](./suspicious_wmiprvse_child_process.yaml) |
| Sysinternals PsSuspend Suspicious Execution | 🟠 high | 75 | `T1685` | [`sysinternals_pssuspend_suspicious_execution.yaml`](./sysinternals_pssuspend_suspicious_execution.yaml) |
| Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE | 🟠 high | 75 | `T1518.001` | [`sysmon_discovery_via_default_driver_altitude_using_findstr_exe.yaml`](./sysmon_discovery_via_default_driver_altitude_using_findstr_exe.yaml) |
| Sysmon Driver Unloaded Via Fltmc.EXE | 🟠 high | 75 | `T1070`, `T1685`, `T1685.001` | [`sysmon_driver_unloaded_via_fltmc_exe.yaml`](./sysmon_driver_unloaded_via_fltmc_exe.yaml) |
| System File Execution Location Anomaly | 🟠 high | 75 | `T1036` | [`system_file_execution_location_anomaly.yaml`](./system_file_execution_location_anomaly.yaml) |
| System Restore Registry Modification via CommandLine | 🟠 high | 75 | `T1490` | [`system_restore_registry_modification_via_commandline.yaml`](./system_restore_registry_modification_via_commandline.yaml) |
| TAIDOOR RAT DLL Load | 🟠 high | 75 | `T1055.001` | [`taidoor_rat_dll_load.yaml`](./taidoor_rat_dll_load.yaml) |
| Tamper Windows Defender Remove-MpPreference | 🟠 high | 75 | `T1685` | [`tamper_windows_defender_remove_mppreference.yaml`](./tamper_windows_defender_remove_mppreference.yaml) |
| TanStack Supply-Chain Attack Execution Indicators - Windows | 🟠 high | 75 | `T1059.007`, `T1204.002` | [`tanstack_supply_chain_attack_execution_indicators_windows.yaml`](./tanstack_supply_chain_attack_execution_indicators_windows.yaml) |
| Taskkill Symantec Endpoint Protection | 🟠 high | 75 | `T1685` | [`taskkill_symantec_endpoint_protection.yaml`](./taskkill_symantec_endpoint_protection.yaml) |
| Taskmgr as LOCAL_SYSTEM | 🟠 high | 75 | `T1036` | [`taskmgr_as_local_system.yaml`](./taskmgr_as_local_system.yaml) |
| Tasks Folder Evasion | 🟠 high | 75 | `T1574.001` | [`tasks_folder_evasion.yaml`](./tasks_folder_evasion.yaml) |
| Terminal Service Process Spawn | 🟠 high | 75 | `T1190`, `T1210` | [`terminal_service_process_spawn.yaml`](./terminal_service_process_spawn.yaml) |
| Time Travel Debugging Utility Usage | 🟠 high | 75 | `T1218`, `T1003.001` | [`time_travel_debugging_utility_usage.yaml`](./time_travel_debugging_utility_usage.yaml) |
| Tor Client/Browser Execution | 🟠 high | 75 | `T1090.003` | [`tor_client_browser_execution.yaml`](./tor_client_browser_execution.yaml) |
| Trickbot Malware Activity | 🟠 high | 75 | `T1559` | [`trickbot_malware_activity.yaml`](./trickbot_malware_activity.yaml) |
| TropicTrooper Campaign November 2018 | 🟠 high | 75 | `T1059.001` | [`tropictrooper_campaign_november_2018.yaml`](./tropictrooper_campaign_november_2018.yaml) |
| UAC Bypass Abusing Winsat Path Parsing - Process | 🟠 high | 75 | `T1548.002` | [`uac_bypass_abusing_winsat_path_parsing_process.yaml`](./uac_bypass_abusing_winsat_path_parsing_process.yaml) |
| UAC Bypass Tools Using ComputerDefaults | 🟠 high | 75 | `T1548.002` | [`uac_bypass_tools_using_computerdefaults.yaml`](./uac_bypass_tools_using_computerdefaults.yaml) |
| UAC Bypass Using ChangePK and SLUI | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_changepk_and_slui.yaml`](./uac_bypass_using_changepk_and_slui.yaml) |
| UAC Bypass Using Consent and Comctl32 - Process | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_consent_and_comctl32_process.yaml`](./uac_bypass_using_consent_and_comctl32_process.yaml) |
| UAC Bypass Using Disk Cleanup | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_disk_cleanup.yaml`](./uac_bypass_using_disk_cleanup.yaml) |
| UAC Bypass Using DismHost | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_dismhost.yaml`](./uac_bypass_using_dismhost.yaml) |
| UAC Bypass Using Event Viewer RecentViews | 🟠 high | 75 | — | [`uac_bypass_using_event_viewer_recentviews.yaml`](./uac_bypass_using_event_viewer_recentviews.yaml) |
| UAC Bypass Using IDiagnostic Profile | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_idiagnostic_profile.yaml`](./uac_bypass_using_idiagnostic_profile.yaml) |
| UAC Bypass Using IEInstal - Process | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_ieinstal_process.yaml`](./uac_bypass_using_ieinstal_process.yaml) |
| UAC Bypass Using MSConfig Token Modification - Process | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_msconfig_token_modification_process.yaml`](./uac_bypass_using_msconfig_token_modification_process.yaml) |
| UAC Bypass Using NTFS Reparse Point - Process | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_ntfs_reparse_point_process.yaml`](./uac_bypass_using_ntfs_reparse_point_process.yaml) |
| UAC Bypass Using PkgMgr and DISM | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_pkgmgr_and_dism.yaml`](./uac_bypass_using_pkgmgr_and_dism.yaml) |
| UAC Bypass Using Windows Media Player - Process | 🟠 high | 75 | `T1548.002` | [`uac_bypass_using_windows_media_player_process.yaml`](./uac_bypass_using_windows_media_player_process.yaml) |
| UAC Bypass via ICMLuaUtil | 🟠 high | 75 | `T1548.002` | [`uac_bypass_via_icmluautil.yaml`](./uac_bypass_via_icmluautil.yaml) |
| UAC Bypass WSReset | 🟠 high | 75 | `T1548.002` | [`uac_bypass_wsreset.yaml`](./uac_bypass_wsreset.yaml) |
| UEFI Persistence Via Wpbbin - ProcessCreation | 🟠 high | 75 | `T1542.001` | [`uefi_persistence_via_wpbbin_processcreation.yaml`](./uefi_persistence_via_wpbbin_processcreation.yaml) |
| UNC2452 Process Creation Patterns | 🟠 high | 75 | `T1059.001` | [`unc2452_process_creation_patterns.yaml`](./unc2452_process_creation_patterns.yaml) |
| Uncommon Child Process Of Setres.EXE | 🟠 high | 75 | `T1218`, `T1202` | [`uncommon_child_process_of_setres_exe.yaml`](./uncommon_child_process_of_setres_exe.yaml) |
| Uncommon FileSystem Load Attempt By Format.com | 🟠 high | 75 | — | [`uncommon_filesystem_load_attempt_by_format_com.yaml`](./uncommon_filesystem_load_attempt_by_format_com.yaml) |
| Uncommon One Time Only Scheduled Task At 00:00 | 🟠 high | 75 | `T1053.005` | [`uncommon_one_time_only_scheduled_task_at_00_00.yaml`](./uncommon_one_time_only_scheduled_task_at_00_00.yaml) |
| Uncommon Userinit Child Process | 🟠 high | 75 | `T1037.001` | [`uncommon_userinit_child_process.yaml`](./uncommon_userinit_child_process.yaml) |
| Uninstall Crowdstrike Falcon Sensor | 🟠 high | 75 | `T1685` | [`uninstall_crowdstrike_falcon_sensor.yaml`](./uninstall_crowdstrike_falcon_sensor.yaml) |
| Uninstall Sysinternals Sysmon | 🟠 high | 75 | `T1685` | [`uninstall_sysinternals_sysmon.yaml`](./uninstall_sysinternals_sysmon.yaml) |
| Unusual Child Process of dns.exe | 🟠 high | 75 | `T1133` | [`unusual_child_process_of_dns_exe.yaml`](./unusual_child_process_of_dns_exe.yaml) |
| Ursnif Redirection Of Discovery Commands | 🟠 high | 75 | `T1059` | [`ursnif_redirection_of_discovery_commands.yaml`](./ursnif_redirection_of_discovery_commands.yaml) |
| Use of W32tm as Timer | 🟠 high | 75 | `T1124` | [`use_of_w32tm_as_timer.yaml`](./use_of_w32tm_as_timer.yaml) |
| User Added To Highly Privileged Group | 🟠 high | 75 | `T1098` | [`user_added_to_highly_privileged_group.yaml`](./user_added_to_highly_privileged_group.yaml) |
| User Added to Remote Desktop Users Group | 🟠 high | 75 | `T1133`, `T1136.001`, `T1021.001` | [`user_added_to_remote_desktop_users_group.yaml`](./user_added_to_remote_desktop_users_group.yaml) |
| User Shell Folders Registry Modification via CommandLine | 🟠 high | 75 | `T1547.001`, `T1112` | [`user_shell_folders_registry_modification_via_commandline.yaml`](./user_shell_folders_registry_modification_via_commandline.yaml) |
| Using SettingSyncHost.exe as LOLBin | 🟠 high | 75 | `T1574.008` | [`using_settingsynchost_exe_as_lolbin.yaml`](./using_settingsynchost_exe_as_lolbin.yaml) |
| VeeamBackup Database Credentials Dump Via Sqlcmd.EXE | 🟠 high | 75 | `T1005` | [`veeambackup_database_credentials_dump_via_sqlcmd_exe.yaml`](./veeambackup_database_credentials_dump_via_sqlcmd_exe.yaml) |
| Visual Basic Command Line Compiler Usage | 🟠 high | 75 | `T1027.004` | [`visual_basic_command_line_compiler_usage.yaml`](./visual_basic_command_line_compiler_usage.yaml) |
| VMToolsd Suspicious Child Process | 🟠 high | 75 | `T1059` | [`vmtoolsd_suspicious_child_process.yaml`](./vmtoolsd_suspicious_child_process.yaml) |
| VolumeShadowCopy Symlink Creation Via Mklink | 🟠 high | 75 | `T1003.002`, `T1003.003` | [`volumeshadowcopy_symlink_creation_via_mklink.yaml`](./volumeshadowcopy_symlink_creation_via_mklink.yaml) |
| Vulnerable Driver Blocklist Registry Tampering Via CommandLine | 🟠 high | 75 | `T1685` | [`vulnerable_driver_blocklist_registry_tampering_via_commandline.yaml`](./vulnerable_driver_blocklist_registry_tampering_via_commandline.yaml) |
| Wab Execution From Non Default Location | 🟠 high | 75 | — | [`wab_execution_from_non_default_location.yaml`](./wab_execution_from_non_default_location.yaml) |
| Wab/Wabmig Unusual Parent Or Child Processes | 🟠 high | 75 | — | [`wab_wabmig_unusual_parent_or_child_processes.yaml`](./wab_wabmig_unusual_parent_or_child_processes.yaml) |
| Webshell Detection With Command Line Keywords | 🟠 high | 75 | `T1505.003`, `T1018`, `T1033`… | [`webshell_detection_with_command_line_keywords.yaml`](./webshell_detection_with_command_line_keywords.yaml) |
| Webshell Hacking Activity Patterns | 🟠 high | 75 | `T1505.003`, `T1018`, `T1033`… | [`webshell_hacking_activity_patterns.yaml`](./webshell_hacking_activity_patterns.yaml) |
| Webshell Tool Reconnaissance Activity | 🟠 high | 75 | `T1505.003` | [`webshell_tool_reconnaissance_activity.yaml`](./webshell_tool_reconnaissance_activity.yaml) |
| WhoAmI as Parameter | 🟠 high | 75 | `T1033` | [`whoami_as_parameter.yaml`](./whoami_as_parameter.yaml) |
| Whoami.EXE Execution From Privileged Process | 🟠 high | 75 | `T1033` | [`whoami_exe_execution_from_privileged_process.yaml`](./whoami_exe_execution_from_privileged_process.yaml) |
| Windows Advanced Installer MSIX with AI_STUBS Execution | 🟠 high | 60 | `T1218`, `T1553.005`, `T1204.002` | [`windows_advanced_installer_msix_with_ai_stubs_execution.yaml`](./windows_advanced_installer_msix_with_ai_stubs_execution.yaml) |
| Windows Alternate DataStream - Process Execution | 🟠 high | 80 | `T1564.004` | [`windows_alternate_datastream_process_execution.yaml`](./windows_alternate_datastream_process_execution.yaml) |
| Windows AMSI Related Registry Tampering Via CommandLine | 🟠 high | 75 | `T1685` | [`windows_amsi_related_registry_tampering_via_commandline.yaml`](./windows_amsi_related_registry_tampering_via_commandline.yaml) |
| Windows Application Whitelisting Bypass Attempt via Rundll32 | 🟠 high | 80 | `T1218.011` | [`windows_application_whitelisting_bypass_attempt_via_rundll32.yaml`](./windows_application_whitelisting_bypass_attempt_via_rundll32.yaml) |
| Windows Audit Policy Auditing Option Disabled via Auditpol | 🟠 high | 60 | `T1562.002` | [`windows_audit_policy_auditing_option_disabled_via_auditpol.yaml`](./windows_audit_policy_auditing_option_disabled_via_auditpol.yaml) |
| Windows BCDEdit Prevent Automatic Repair Mode | 🟠 high | 50 | `T1490` | [`prevent_automatic_repair_mode_using_bcdedit.yaml`](./prevent_automatic_repair_mode_using_bcdedit.yaml) |
| Windows Binary Proxy Execution Mavinject DLL Injection | 🟠 high | 49 | `T1218.013` | [`windows_binary_proxy_execution_mavinject_dll_injection.yaml`](./windows_binary_proxy_execution_mavinject_dll_injection.yaml) |
| Windows BitLocker Suspicious Command Usage | 🟠 high | 60 | `T1486`, `T1490` | [`windows_bitlocker_suspicious_command_usage.yaml`](./windows_bitlocker_suspicious_command_usage.yaml) |
| Windows Certutil Root Certificate Addition | 🟠 high | 72 | `T1587.003` | [`windows_certutil_root_certificate_addition.yaml`](./windows_certutil_root_certificate_addition.yaml) |
| Windows Change File Association Command To Notepad | 🟠 high | 72 | `T1546.001` | [`windows_change_file_association_command_to_notepad.yaml`](./windows_change_file_association_command_to_notepad.yaml) |
| Windows Chromium Browser No Security Sandbox Process | 🟠 high | 60 | `T1497` | [`windows_chromium_browser_no_security_sandbox_process.yaml`](./windows_chromium_browser_no_security_sandbox_process.yaml) |
| Windows COM Hijacking InprocServer32 Modification | 🟠 high | 64 | `T1546.015` | [`windows_com_hijacking_inprocserver32_modification.yaml`](./windows_com_hijacking_inprocserver32_modification.yaml) |
| Windows Compatibility Telemetry Suspicious Child Process | 🟠 high | 72 | `T1546`, `T1053.005` | [`windows_compatibility_telemetry_suspicious_child_process.yaml`](./windows_compatibility_telemetry_suspicious_child_process.yaml) |
| Windows ConHost with Headless Argument | 🟠 high | 72 | `T1564.003`, `T1564.006` | [`windows_conhost_with_headless_argument.yaml`](./windows_conhost_with_headless_argument.yaml) |
| Windows Credential Dumping LSASS Memory Createdump | 🟠 high | 72 | `T1003.001` | [`windows_credential_dumping_lsass_memory_createdump.yaml`](./windows_credential_dumping_lsass_memory_createdump.yaml) |
| Windows Credential Guard Registry Tampering Via CommandLine | 🟠 high | 75 | `T1685` | [`windows_credential_guard_registry_tampering_via_commandline.yaml`](./windows_credential_guard_registry_tampering_via_commandline.yaml) |
| Windows Credential Target Information Structure in Commandline | 🟠 high | 72 | `T1557.001`, `T1187`, `T1071.004` | [`windows_credential_target_information_structure_in_commandline.yaml`](./windows_credential_target_information_structure_in_commandline.yaml) |
| Windows Curl Download to Suspicious Path | 🟠 high | 72 | `T1105` | [`windows_curl_download_to_suspicious_path.yaml`](./windows_curl_download_to_suspicious_path.yaml) |
| Windows Curl Upload to Remote Destination | 🟠 high | 72 | `T1105` | [`windows_curl_upload_to_remote_destination.yaml`](./windows_curl_upload_to_remote_destination.yaml) |
| Windows Defender ASR or Threat Configuration Tamper | 🟠 high | 64 | `T1562.001` | [`windows_defender_asr_or_threat_configuration_tamper.yaml`](./windows_defender_asr_or_threat_configuration_tamper.yaml) |
| Windows Defender Context Menu Removed | 🟠 high | 75 | `T1685` | [`windows_defender_context_menu_removed.yaml`](./windows_defender_context_menu_removed.yaml) |
| Windows Defender Definition Files Removed | 🟠 high | 75 | `T1685` | [`windows_defender_definition_files_removed.yaml`](./windows_defender_definition_files_removed.yaml) |
| Windows Defender Disabled Via SystemSettingsAdminFlows.EXE | 🟠 high | 75 | `T1685` | [`windows_defender_disabled_via_systemsettingsadminflows_exe.yaml`](./windows_defender_disabled_via_systemsettingsadminflows_exe.yaml) |
| Windows Disable HTTP Logging via AppCmd | 🟠 high | 64 | `T1505.004`, `T1562.002` | [`windows_disable_windows_event_logging_disable_http_logging.yaml`](./windows_disable_windows_event_logging_disable_http_logging.yaml) |
| Windows Disable or Stop Browser Process | 🟠 high | 64 | `T1562.001` | [`windows_disable_or_stop_browser_process.yaml`](./windows_disable_or_stop_browser_process.yaml) |
| Windows DiskCryptor Usage | 🟠 high | 72 | `T1486` | [`windows_diskcryptor_usage.yaml`](./windows_diskcryptor_usage.yaml) |
| Windows DISM Install PowerShell Web Access | 🟠 high | 72 | `T1548.002` | [`windows_dism_install_powershell_web_access.yaml`](./windows_dism_install_powershell_web_access.yaml) |
| Windows DLL Search Order Hijacking with iscsicpl | 🟠 high | 64 | `T1574.001` | [`windows_dll_search_order_hijacking_with_iscsicpl.yaml`](./windows_dll_search_order_hijacking_with_iscsicpl.yaml) |
| Windows ESX Admins Group Creation via Net | 🟠 high | 72 | `T1136.001`, `T1136.002` | [`windows_esx_admins_group_creation_via_net.yaml`](./windows_esx_admins_group_creation_via_net.yaml) |
| Windows EventLog Autologger Session Registry Modification Via CommandLine | 🟠 high | 75 | `T1685.001` | [`windows_eventlog_autologger_session_registry_modification_via_commandline.yaml`](./windows_eventlog_autologger_session_registry_modification_via_commandline.yaml) |
| Windows Eventlog Cleared Via Wevtutil | 🟠 high | 56 | `T1070.001` | [`windows_eventlog_cleared_via_wevtutil.yaml`](./windows_eventlog_cleared_via_wevtutil.yaml) |
| Windows Excessive Service Stop Attempt | 🟠 high | 80 | `T1489` | [`windows_excessive_service_stop_attempt.yaml`](./windows_excessive_service_stop_attempt.yaml) |
| Windows Execution of Microsoft MSC File In Suspicious Path | 🟠 high | 70 | `T1218.014` | [`windows_execution_of_microsoft_msc_file_in_suspicious_path.yaml`](./windows_execution_of_microsoft_msc_file_in_suspicious_path.yaml) |
| Windows File Download Via Certutil | 🟠 high | 64 | `T1105` | [`windows_file_download_via_certutil.yaml`](./windows_file_download_via_certutil.yaml) |
| Windows Files and Dirs Access Rights Modification Via Icacls | 🟠 high | 75 | `T1222.001` | [`windows_files_and_dirs_access_rights_modification_via_icacls.yaml`](./windows_files_and_dirs_access_rights_modification_via_icacls.yaml) |
| Windows Global Object Access Audit List Cleared Via Auditpol | 🟠 high | 64 | `T1562.002` | [`windows_global_object_access_audit_list_cleared_via_auditpol_alt.yaml`](./windows_global_object_access_audit_list_cleared_via_auditpol_alt.yaml) |
| Windows HTTP Network Communication From MSIExec | 🟠 high | 80 | `T1218.007` | [`windows_http_network_communication_from_msiexec.yaml`](./windows_http_network_communication_from_msiexec.yaml) |
| Windows IIS Components Add New Module | 🟠 high | 64 | `T1505.004` | [`windows_iis_components_add_new_module.yaml`](./windows_iis_components_add_new_module.yaml) |
| Windows Impair Defense Add Xml Applocker Rules | 🟠 high | 75 | `T1562.001` | [`windows_impair_defense_add_xml_applocker_rules.yaml`](./windows_impair_defense_add_xml_applocker_rules.yaml) |
| Windows Ingress Tool Transfer Using Explorer | 🟠 high | 70 | `T1105` | [`windows_ingress_tool_transfer_using_explorer.yaml`](./windows_ingress_tool_transfer_using_explorer.yaml) |
| Windows InstallUtil Remote Network Connection | 🟠 high | 75 | `T1218.004` | [`windows_installutil_remote_network_connection.yaml`](./windows_installutil_remote_network_connection.yaml) |
| Windows InstallUtil Uninstall Option | 🟠 high | 70 | `T1218.004` | [`windows_installutil_uninstall_option.yaml`](./windows_installutil_uninstall_option.yaml) |
| Windows Internet Hosted WebDav Share Mount Via Net.EXE | 🟠 high | 75 | `T1021.002` | [`windows_internet_hosted_webdav_share_mount_via_net_exe.yaml`](./windows_internet_hosted_webdav_share_mount_via_net_exe.yaml) |
| Windows Mimikatz PassTheTicket CommandLine Parameters | 🟠 high | 72 | `T1550.003` | [`mimikatz_passtheticket_commandline_parameters_alt.yaml`](./mimikatz_passtheticket_commandline_parameters_alt.yaml) |
| Windows Mmc LOLBAS Execution Process Spawn | 🟠 high | 54 | `T1021.003`, `T1218.014` | [`mmc_lolbas_execution_process_spawn.yaml`](./mmc_lolbas_execution_process_spawn.yaml) |
| Windows Modify System Firewall with Notable Process Path | 🟠 high | 64 | `T1562.004` | [`windows_modify_system_firewall_with_notable_process_path.yaml`](./windows_modify_system_firewall_with_notable_process_path.yaml) |
| Windows MOF Event Triggered Execution via WMI | 🟠 high | 64 | `T1546.003` | [`windows_mof_event_triggered_execution_via_wmi.yaml`](./windows_mof_event_triggered_execution_via_wmi.yaml) |
| Windows MSC EvilTwin Directory Path Manipulation | 🟠 high | 80 | `T1218`, `T1036.005`, `T1203` | [`windows_msc_eviltwin_directory_path_manipulation.yaml`](./windows_msc_eviltwin_directory_path_manipulation.yaml) |
| Windows ngrok Usage Observed | 🟠 high | 60 | `T1572`, `T1090`, `T1102` | [`windows_ngrok_usage_observed.yaml`](./windows_ngrok_usage_observed.yaml) |
| Windows NirSoft AdvancedRun | 🟠 high | 60 | `T1588.002` | [`windows_nirsoft_advancedrun.yaml`](./windows_nirsoft_advancedrun.yaml) |
| Windows PowerShell Disable Security Monitoring | 🟠 high | 50 | `T1562.001` | [`powershell_disable_security_monitoring_alt.yaml`](./powershell_disable_security_monitoring_alt.yaml) |
| Windows PowerShell Executed with Truncated Parameters | 🟠 high | 60 | `T1059.001`, `T1027` | [`windows_powershell_executed_with_truncated_parameters.yaml`](./windows_powershell_executed_with_truncated_parameters.yaml) |
| Windows PowerShell FakeCAPTCHA Clipboard Execution | 🟠 high | 72 | `T1059.001`, `T1204.001`, `T1059.003` | [`windows_powershell_fakecaptcha_clipboard_execution.yaml`](./windows_powershell_fakecaptcha_clipboard_execution.yaml) |
| Windows PowerShell Process Implementing Manual Base64 Decoder | 🟠 high | 65 | `T1027.010`, `T1059.001` | [`windows_powershell_process_implementing_manual_base64_decoder.yaml`](./windows_powershell_process_implementing_manual_base64_decoder.yaml) |
| Windows Process Deleting Its Process File Path | 🟠 high | 50 | `T1070` | [`process_deleting_its_process_file_path.yaml`](./process_deleting_its_process_file_path.yaml) |
| Windows Scheduled Task Created to Spawn Shell | 🟠 high | 63 | `T1053.005` | [`winevent_scheduled_task_created_to_spawn_shell.yaml`](./winevent_scheduled_task_created_to_spawn_shell.yaml) |
| Windows Scheduled Task Created Within Public Path | 🟠 high | 63 | `T1053.005` | [`winevent_scheduled_task_created_within_public_path.yaml`](./winevent_scheduled_task_created_within_public_path.yaml) |
| Windows Shell/Scripting Processes Spawning Suspicious Programs | 🟠 high | 75 | `T1059.005`, `T1059.001`, `T1218` | [`windows_shell_scripting_processes_spawning_suspicious_programs.yaml`](./windows_shell_scripting_processes_spawning_suspicious_programs.yaml) |
| Windows Suspicious Child Process from Node.js - React2Shell | 🟠 high | 75 | `T1059`, `T1190` | [`windows_suspicious_child_process_from_node_js_react2shell.yaml`](./windows_suspicious_child_process_from_node_js_react2shell.yaml) |
| Windows Winhlp32 Spawning a Process | 🟠 high | 72 | `T1055` | [`winhlp32_spawning_a_process.yaml`](./winhlp32_spawning_a_process.yaml) |
| Windows WinRAR Spawning Shell Application | 🟠 high | 72 | `T1105` | [`winrar_spawning_shell_application.yaml`](./winrar_spawning_shell_application.yaml) |
| Windows WinRM Spawning a Process | 🟠 high | 63 | `T1190` | [`winrm_spawning_a_process.yaml`](./winrm_spawning_a_process.yaml) |
| Winrs Local Command Execution | 🟠 high | 75 | `T1021.006`, `T1218` | [`winrs_local_command_execution.yaml`](./winrs_local_command_execution.yaml) |
| WSL Kali-Linux Usage | 🟠 high | 75 | `T1202` | [`wsl_kali_linux_usage.yaml`](./wsl_kali_linux_usage.yaml) |
| Wusa.EXE Executed By Parent Process Located In Suspicious Location | 🟠 high | 75 | — | [`wusa_exe_executed_by_parent_process_located_in_suspicious_location.yaml`](./wusa_exe_executed_by_parent_process_located_in_suspicious_location.yaml) |
| Xwizard.EXE Execution From Non-Default Location | 🟠 high | 75 | `T1574.001` | [`xwizard_exe_execution_from_non_default_location.yaml`](./xwizard_exe_execution_from_non_default_location.yaml) |
| 7Zip Compressing Dump Files | 🟡 medium | 50 | `T1560.001` | [`7zip_compressing_dump_files.yaml`](./7zip_compressing_dump_files.yaml) |
| Abusing Print Executable | 🟡 medium | 50 | `T1218` | [`abusing_print_executable.yaml`](./abusing_print_executable.yaml) |
| Active Directory Database Snapshot Via ADExplorer | 🟡 medium | 50 | `T1087.002`, `T1069.002`, `T1482` | [`active_directory_database_snapshot_via_adexplorer.yaml`](./active_directory_database_snapshot_via_adexplorer.yaml) |
| Active Directory Structure Export Via Csvde.EXE | 🟡 medium | 50 | `T1087.002` | [`active_directory_structure_export_via_csvde_exe.yaml`](./active_directory_structure_export_via_csvde_exe.yaml) |
| Active Directory Structure Export Via Ldifde.EXE | 🟡 medium | 50 | — | [`active_directory_structure_export_via_ldifde_exe.yaml`](./active_directory_structure_export_via_ldifde_exe.yaml) |
| Add New Download Source To Winget | 🟡 medium | 50 | `T1059` | [`add_new_download_source_to_winget.yaml`](./add_new_download_source_to_winget.yaml) |
| Add Potential Suspicious New Download Source To Winget | 🟡 medium | 50 | `T1059` | [`add_potential_suspicious_new_download_source_to_winget.yaml`](./add_potential_suspicious_new_download_source_to_winget.yaml) |
| Add Windows Capability Via PowerShell Cmdlet | 🟡 medium | 50 | — | [`add_windows_capability_via_powershell_cmdlet.yaml`](./add_windows_capability_via_powershell_cmdlet.yaml) |
| AddinUtil.EXE Execution From Uncommon Directory | 🟡 medium | 50 | `T1218` | [`addinutil_exe_execution_from_uncommon_directory.yaml`](./addinutil_exe_execution_from_uncommon_directory.yaml) |
| AgentExecutor PowerShell Execution | 🟡 medium | 50 | `T1218` | [`agentexecutor_powershell_execution.yaml`](./agentexecutor_powershell_execution.yaml) |
| Always Install Elevated MSI Spawned Cmd And Powershell | 🟡 medium | 50 | `T1548.002` | [`always_install_elevated_msi_spawned_cmd_and_powershell.yaml`](./always_install_elevated_msi_spawned_cmd_and_powershell.yaml) |
| Always Install Elevated Windows Installer | 🟡 medium | 50 | `T1548.002` | [`always_install_elevated_windows_installer.yaml`](./always_install_elevated_windows_installer.yaml) |
| Application Removed Via Wmic.EXE | 🟡 medium | 50 | `T1047` | [`application_removed_via_wmic_exe.yaml`](./application_removed_via_wmic_exe.yaml) |
| Application Termination Attempt via Wmic.EXE | 🟡 medium | 50 | `T1047` | [`application_termination_attempt_via_wmic_exe.yaml`](./application_termination_attempt_via_wmic_exe.yaml) |
| Arbitrary Binary Execution Using GUP Utility | 🟡 medium | 50 | — | [`arbitrary_binary_execution_using_gup_utility.yaml`](./arbitrary_binary_execution_using_gup_utility.yaml) |
| Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE | 🟡 medium | 50 | `T1218` | [`arbitrary_dll_or_csproj_code_execution_via_dotnet_exe.yaml`](./arbitrary_dll_or_csproj_code_execution_via_dotnet_exe.yaml) |
| Arbitrary File Download Via ConfigSecurityPolicy.EXE | 🟡 medium | 50 | `T1567` | [`arbitrary_file_download_via_configsecuritypolicy_exe.yaml`](./arbitrary_file_download_via_configsecuritypolicy_exe.yaml) |
| Arbitrary File Download Via GfxDownloadWrapper.EXE | 🟡 medium | 50 | `T1105` | [`arbitrary_file_download_via_gfxdownloadwrapper_exe.yaml`](./arbitrary_file_download_via_gfxdownloadwrapper_exe.yaml) |
| Arbitrary File Download Via MSEDGE_PROXY.EXE | 🟡 medium | 50 | `T1218` | [`arbitrary_file_download_via_msedge_proxy_exe.yaml`](./arbitrary_file_download_via_msedge_proxy_exe.yaml) |
| Arbitrary File Download Via MSOHTMED.EXE | 🟡 medium | 50 | `T1218` | [`arbitrary_file_download_via_msohtmed_exe.yaml`](./arbitrary_file_download_via_msohtmed_exe.yaml) |
| Arbitrary File Download Via MSPUB.EXE | 🟡 medium | 50 | `T1218` | [`arbitrary_file_download_via_mspub_exe.yaml`](./arbitrary_file_download_via_mspub_exe.yaml) |
| Arbitrary File Download Via PresentationHost.EXE | 🟡 medium | 50 | `T1218` | [`arbitrary_file_download_via_presentationhost_exe.yaml`](./arbitrary_file_download_via_presentationhost_exe.yaml) |
| Arbitrary File Download Via Squirrel.EXE | 🟡 medium | 50 | `T1218` | [`arbitrary_file_download_via_squirrel_exe.yaml`](./arbitrary_file_download_via_squirrel_exe.yaml) |
| Arbitrary MSI Download Via Devinit.EXE | 🟡 medium | 50 | `T1218` | [`arbitrary_msi_download_via_devinit_exe.yaml`](./arbitrary_msi_download_via_devinit_exe.yaml) |
| Arbitrary Shell Command Execution Via Settingcontent-Ms | 🟡 medium | 50 | `T1204`, `T1566.001` | [`arbitrary_shell_command_execution_via_settingcontent_ms.yaml`](./arbitrary_shell_command_execution_via_settingcontent_ms.yaml) |
| AspNetCompiler Execution | 🟡 medium | 50 | `T1127` | [`aspnetcompiler_execution.yaml`](./aspnetcompiler_execution.yaml) |
| Assembly Loading Via CL_LoadAssembly.ps1 | 🟡 medium | 50 | `T1216` | [`assembly_loading_via_cl_loadassembly_ps1.yaml`](./assembly_loading_via_cl_loadassembly_ps1.yaml) |
| Audio Capture via PowerShell | 🟡 medium | 50 | `T1123` | [`audio_capture_via_powershell.yaml`](./audio_capture_via_powershell.yaml) |
| Audio Capture via SoundRecorder | 🟡 medium | 50 | `T1123` | [`audio_capture_via_soundrecorder.yaml`](./audio_capture_via_soundrecorder.yaml) |
| Automated Collection Command Prompt | 🟡 medium | 50 | `T1119`, `T1552.001` | [`automated_collection_command_prompt.yaml`](./automated_collection_command_prompt.yaml) |
| AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl | 🟡 medium | 50 | `T1216` | [`awl_bypass_with_winrm_vbs_and_malicious_wsmpty_xsl_wsmtxt_xsl.yaml`](./awl_bypass_with_winrm_vbs_and_malicious_wsmpty_xsl_wsmtxt_xsl.yaml) |
| Binary Proxy Execution Via Dotnet-Trace.EXE | 🟡 medium | 50 | `T1218` | [`binary_proxy_execution_via_dotnet_trace_exe.yaml`](./binary_proxy_execution_via_dotnet_trace_exe.yaml) |
| Browser Started with Remote Debugging | 🟡 medium | 50 | `T1185` | [`browser_started_with_remote_debugging.yaml`](./browser_started_with_remote_debugging.yaml) |
| C# IL Code Compilation Via Ilasm.EXE | 🟡 medium | 50 | `T1127` | [`c_il_code_compilation_via_ilasm_exe.yaml`](./c_il_code_compilation_via_ilasm_exe.yaml) |
| Capture Credentials with Rpcping.exe | 🟡 medium | 50 | `T1003` | [`capture_credentials_with_rpcping_exe.yaml`](./capture_credentials_with_rpcping_exe.yaml) |
| Certificate Exported Via Certutil.EXE | 🟡 medium | 50 | `T1027` | [`certificate_exported_via_certutil_exe.yaml`](./certificate_exported_via_certutil_exe.yaml) |
| Certificate Exported Via PowerShell | 🟡 medium | 50 | `T1552.004`, `T1059.001` | [`certificate_exported_via_powershell.yaml`](./certificate_exported_via_powershell.yaml) |
| Change PowerShell Policies to an Insecure Level | 🟡 medium | 50 | `T1059.001` | [`change_powershell_policies_to_an_insecure_level.yaml`](./change_powershell_policies_to_an_insecure_level.yaml) |
| Changing Existing Service ImagePath Value Via Reg.EXE | 🟡 medium | 50 | `T1574.011` | [`changing_existing_service_imagepath_value_via_reg_exe.yaml`](./changing_existing_service_imagepath_value_via_reg_exe.yaml) |
| Chromium Browser Instance Executed With Custom Extension | 🟡 medium | 50 | `T1176.001` | [`chromium_browser_instance_executed_with_custom_extension.yaml`](./chromium_browser_instance_executed_with_custom_extension.yaml) |
| Cloudflared Portable Execution | 🟡 medium | 50 | `T1090.001` | [`cloudflared_portable_execution.yaml`](./cloudflared_portable_execution.yaml) |
| Cloudflared Quick Tunnel Execution | 🟡 medium | 50 | `T1090.001` | [`cloudflared_quick_tunnel_execution.yaml`](./cloudflared_quick_tunnel_execution.yaml) |
| Cloudflared Tunnel Connections Cleanup | 🟡 medium | 50 | `T1102`, `T1090`, `T1572` | [`cloudflared_tunnel_connections_cleanup.yaml`](./cloudflared_tunnel_connections_cleanup.yaml) |
| Cloudflared Tunnel Execution | 🟡 medium | 50 | `T1102`, `T1090`, `T1572` | [`cloudflared_tunnel_execution.yaml`](./cloudflared_tunnel_execution.yaml) |
| Cmd Launched with Hidden Start Flags to Suspicious Targets | 🟡 medium | 50 | `T1564.003` | [`cmd_launched_with_hidden_start_flags_to_suspicious_targets.yaml`](./cmd_launched_with_hidden_start_flags_to_suspicious_targets.yaml) |
| Code Execution via Pcwutl.dll | 🟡 medium | 50 | `T1218.011` | [`code_execution_via_pcwutl_dll.yaml`](./code_execution_via_pcwutl_dll.yaml) |
| CodePage Modification Via MODE.COM To Russian Language | 🟡 medium | 50 | `T1036` | [`codepage_modification_via_mode_com_to_russian_language.yaml`](./codepage_modification_via_mode_com_to_russian_language.yaml) |
| COM Object Execution via Xwizard.EXE | 🟡 medium | 50 | `T1218` | [`com_object_execution_via_xwizard_exe.yaml`](./com_object_execution_via_xwizard_exe.yaml) |
| Command Line Execution with Suspicious URL and AppData Strings | 🟡 medium | 50 | `T1059.003`, `T1059.001`, `T1105` | [`command_line_execution_with_suspicious_url_and_appdata_strings.yaml`](./command_line_execution_with_suspicious_url_and_appdata_strings.yaml) |
| Commvault QLogin with PublicSharingUser and GUID Password (CVE-2025-57788) | 🟡 medium | 50 | `T1078.001` | [`commvault_qlogin_with_publicsharinguser_and_guid_password_cve_2025_57788.yaml`](./commvault_qlogin_with_publicsharinguser_and_guid_password_cve_2025_57788.yaml) |
| Compress Data and Lock With Password for Exfiltration With 7-ZIP | 🟡 medium | 50 | `T1560.001` | [`compress_data_and_lock_with_password_for_exfiltration_with_7_zip.yaml`](./compress_data_and_lock_with_password_for_exfiltration_with_7_zip.yaml) |
| Compress Data and Lock With Password for Exfiltration With WINZIP | 🟡 medium | 50 | `T1560.001` | [`compress_data_and_lock_with_password_for_exfiltration_with_winzip.yaml`](./compress_data_and_lock_with_password_for_exfiltration_with_winzip.yaml) |
| Computer Discovery And Export Via Get-ADComputer Cmdlet | 🟡 medium | 50 | `T1033` | [`computer_discovery_and_export_via_get_adcomputer_cmdlet.yaml`](./computer_discovery_and_export_via_get_adcomputer_cmdlet.yaml) |
| Computer Password Change Via Ksetup.EXE | 🟡 medium | 50 | — | [`computer_password_change_via_ksetup_exe.yaml`](./computer_password_change_via_ksetup_exe.yaml) |
| Computer System Reconnaissance Via Wmic.EXE | 🟡 medium | 50 | `T1047` | [`computer_system_reconnaissance_via_wmic_exe.yaml`](./computer_system_reconnaissance_via_wmic_exe.yaml) |
| Conhost Spawned By Uncommon Parent Process | 🟡 medium | 50 | `T1059` | [`conhost_spawned_by_uncommon_parent_process.yaml`](./conhost_spawned_by_uncommon_parent_process.yaml) |
| Console CodePage Lookup Via CHCP | 🟡 medium | 50 | `T1614.001` | [`console_codepage_lookup_via_chcp.yaml`](./console_codepage_lookup_via_chcp.yaml) |
| ConvertTo-SecureString Cmdlet Usage Via CommandLine | 🟡 medium | 50 | `T1027`, `T1059.001` | [`convertto_securestring_cmdlet_usage_via_commandline.yaml`](./convertto_securestring_cmdlet_usage_via_commandline.yaml) |
| Copy From Or To Admin Share Or Sysvol Folder | 🟡 medium | 50 | `T1039`, `T1048`, `T1021.002` | [`copy_from_or_to_admin_share_or_sysvol_folder.yaml`](./copy_from_or_to_admin_share_or_sysvol_folder.yaml) |
| Cscript/Wscript Potentially Suspicious Child Process | 🟡 medium | 50 | — | [`cscript_wscript_potentially_suspicious_child_process.yaml`](./cscript_wscript_potentially_suspicious_child_process.yaml) |
| Curl Web Request With Potential Custom User-Agent | 🟡 medium | 50 | — | [`curl_web_request_with_potential_custom_user_agent.yaml`](./curl_web_request_with_potential_custom_user_agent.yaml) |
| CVE-2023-22518 Exploitation Attempt - Suspicious Confluence Child Process (Windows) | 🟡 medium | 50 | `T1059`, `T1190` | [`cve_2023_22518_exploitation_attempt_suspicious_confluence_child_process_windows.yaml`](./cve_2023_22518_exploitation_attempt_suspicious_confluence_child_process_windows.yaml) |
| Data Export From MSSQL Table Via BCP.EXE | 🟡 medium | 50 | `T1048` | [`data_export_from_mssql_table_via_bcp_exe.yaml`](./data_export_from_mssql_table_via_bcp_exe.yaml) |
| Defrag Deactivation | 🟡 medium | 50 | `T1053.005` | [`defrag_deactivation.yaml`](./defrag_deactivation.yaml) |
| Deleted Data Overwritten Via Cipher.EXE | 🟡 medium | 50 | `T1485` | [`deleted_data_overwritten_via_cipher_exe.yaml`](./deleted_data_overwritten_via_cipher_exe.yaml) |
| Detect Prohibited Applications Spawning cmd exe | 🟡 medium | 50 | `T1059.003` | [`detect_prohibited_applications_spawning_cmd_exe.yaml`](./detect_prohibited_applications_spawning_cmd_exe.yaml) |
| Detect PsExec With accepteula Flag | 🟡 medium | 50 | `T1021.002` | [`detect_psexec_with_accepteula_flag.yaml`](./detect_psexec_with_accepteula_flag.yaml) |
| Detect Remote Access Software Usage FileInfo | 🟡 medium | 40 | `T1219` | [`detect_remote_access_software_usage_fileinfo.yaml`](./detect_remote_access_software_usage_fileinfo.yaml) |
| Detect Renamed 7-Zip | 🟡 medium | 56 | `T1560.001` | [`detect_renamed_7_zip.yaml`](./detect_renamed_7_zip.yaml) |
| Detect Use of cmd exe to Launch Script Interpreters | 🟡 medium | 40 | `T1059.003` | [`detect_use_of_cmd_exe_to_launch_script_interpreters.yaml`](./detect_use_of_cmd_exe_to_launch_script_interpreters.yaml) |
| Detected Windows Software Discovery | 🟡 medium | 50 | `T1518` | [`detected_windows_software_discovery.yaml`](./detected_windows_software_discovery.yaml) |
| Detection of PowerShell Execution via Sqlps.exe | 🟡 medium | 50 | `T1059.001`, `T1127` | [`detection_of_powershell_execution_via_sqlps_exe.yaml`](./detection_of_powershell_execution_via_sqlps_exe.yaml) |
| Detection of Tools Built by NirSoft | 🟡 medium | 40 | `T1072` | [`detection_of_tools_built_by_nirsoft.yaml`](./detection_of_tools_built_by_nirsoft.yaml) |
| DeviceCredentialDeployment Execution | 🟡 medium | 50 | `T1218` | [`devicecredentialdeployment_execution.yaml`](./devicecredentialdeployment_execution.yaml) |
| Direct Autorun Keys Modification | 🟡 medium | 50 | `T1547.001` | [`direct_autorun_keys_modification.yaml`](./direct_autorun_keys_modification.yaml) |
| Disable Schedule Task | 🟡 medium | 40 | `T1562.001` | [`disable_schedule_task.yaml`](./disable_schedule_task.yaml) |
| Disabling Firewall with Netsh | 🟡 medium | 40 | `T1562.001`, `T1562.004` | [`disabling_firewall_with_netsh.yaml`](./disabling_firewall_with_netsh.yaml) |
| Diskshadow Script Mode - Execution From Potential Suspicious Location | 🟡 medium | 50 | `T1218` | [`diskshadow_script_mode_execution_from_potential_suspicious_location.yaml`](./diskshadow_script_mode_execution_from_potential_suspicious_location.yaml) |
| Diskshadow Script Mode - Uncommon Script Extension Execution | 🟡 medium | 50 | `T1218` | [`diskshadow_script_mode_uncommon_script_extension_execution.yaml`](./diskshadow_script_mode_uncommon_script_extension_execution.yaml) |
| Dism Remove Online Package | 🟡 medium | 50 | `T1685` | [`dism_remove_online_package.yaml`](./dism_remove_online_package.yaml) |
| DLL Execution via Rasautou.exe | 🟡 medium | 50 | `T1218` | [`dll_execution_via_rasautou_exe.yaml`](./dll_execution_via_rasautou_exe.yaml) |
| DLL Execution Via Register-cimprovider.exe | 🟡 medium | 50 | `T1574` | [`dll_execution_via_register_cimprovider_exe.yaml`](./dll_execution_via_register_cimprovider_exe.yaml) |
| DLL Loaded via CertOC.EXE | 🟡 medium | 50 | `T1218` | [`dll_loaded_via_certoc_exe.yaml`](./dll_loaded_via_certoc_exe.yaml) |
| DllUnregisterServer Function Call Via Msiexec.EXE | 🟡 medium | 50 | `T1218.007` | [`dllunregisterserver_function_call_via_msiexec_exe.yaml`](./dllunregisterserver_function_call_via_msiexec_exe.yaml) |
| DNS Exfiltration Using Nslookup App | 🟡 medium | 56 | `T1048`, `T1048.003`, `T1071.004` | [`dns_exfiltration_using_nslookup_app.yaml`](./dns_exfiltration_using_nslookup_app.yaml) |
| Domain Account Discovery with Dsquery | 🟡 medium | 40 | `T1087.002` | [`domain_account_discovery_with_dsquery.yaml`](./domain_account_discovery_with_dsquery.yaml) |
| Domain Controller Discovery with Wmic | 🟡 medium | 40 | `T1018`, `T1047` | [`domain_controller_discovery_with_wmic.yaml`](./domain_controller_discovery_with_wmic.yaml) |
| Domain Group Discovery With Dsquery | 🟡 medium | 40 | `T1069.002` | [`domain_group_discovery_with_dsquery.yaml`](./domain_group_discovery_with_dsquery.yaml) |
| Domain Trust Discovery Via Dsquery | 🟡 medium | 50 | `T1482` | [`domain_trust_discovery_via_dsquery.yaml`](./domain_trust_discovery_via_dsquery.yaml) |
| Driver/DLL Installation Via Odbcconf.EXE | 🟡 medium | 50 | `T1218.008` | [`driver_dll_installation_via_odbcconf_exe.yaml`](./driver_dll_installation_via_odbcconf_exe.yaml) |
| DriverQuery.EXE Execution | 🟡 medium | 50 | — | [`driverquery_exe_execution.yaml`](./driverquery_exe_execution.yaml) |
| Dropping Of Password Filter DLL | 🟡 medium | 50 | `T1556.002` | [`dropping_of_password_filter_dll.yaml`](./dropping_of_password_filter_dll.yaml) |
| Dumping Process via Sqldumper.exe | 🟡 medium | 50 | `T1003.001` | [`dumping_process_via_sqldumper_exe.yaml`](./dumping_process_via_sqldumper_exe.yaml) |
| DumpMinitool Execution | 🟡 medium | 50 | `T1036`, `T1003.001` | [`dumpminitool_execution.yaml`](./dumpminitool_execution.yaml) |
| Elevated System Shell Spawned From Uncommon Parent Location | 🟡 medium | 50 | `T1059` | [`elevated_system_shell_spawned_from_uncommon_parent_location.yaml`](./elevated_system_shell_spawned_from_uncommon_parent_location.yaml) |
| Enumerate All Information With Whoami.EXE | 🟡 medium | 50 | `T1033` | [`enumerate_all_information_with_whoami_exe.yaml`](./enumerate_all_information_with_whoami_exe.yaml) |
| Enumeration for 3rd Party Creds From CLI | 🟡 medium | 50 | `T1552.002` | [`enumeration_for_3rd_party_creds_from_cli.yaml`](./enumeration_for_3rd_party_creds_from_cli.yaml) |
| Enumeration for Credentials in Registry | 🟡 medium | 50 | `T1552.002` | [`enumeration_for_credentials_in_registry.yaml`](./enumeration_for_credentials_in_registry.yaml) |
| Esentutl Gather Credentials | 🟡 medium | 50 | `T1003`, `T1003.003` | [`esentutl_gather_credentials.yaml`](./esentutl_gather_credentials.yaml) |
| Esentutl Steals Browser Information | 🟡 medium | 50 | `T1005` | [`esentutl_steals_browser_information.yaml`](./esentutl_steals_browser_information.yaml) |
| Execute Code with Pester.bat | 🟡 medium | 50 | `T1059.001`, `T1216` | [`execute_code_with_pester_bat.yaml`](./execute_code_with_pester_bat.yaml) |
| Execute Code with Pester.bat as Parent | 🟡 medium | 50 | `T1059.001`, `T1216` | [`execute_code_with_pester_bat_as_parent.yaml`](./execute_code_with_pester_bat_as_parent.yaml) |
| Execute Files with Msdeploy.exe | 🟡 medium | 50 | `T1218` | [`execute_files_with_msdeploy_exe.yaml`](./execute_files_with_msdeploy_exe.yaml) |
| Execute From Alternate Data Streams | 🟡 medium | 50 | `T1564.004` | [`execute_from_alternate_data_streams.yaml`](./execute_from_alternate_data_streams.yaml) |
| Execution of Suspicious File Type Extension | 🟡 medium | 50 | — | [`execution_of_suspicious_file_type_extension.yaml`](./execution_of_suspicious_file_type_extension.yaml) |
| Exploit for CVE-2017-0261 | 🟡 medium | 50 | `T1203`, `T1204.002`, `T1566.001` | [`exploit_for_cve_2017_0261.yaml`](./exploit_for_cve_2017_0261.yaml) |
| Explorer Process Tree Break | 🟡 medium | 50 | `T1036` | [`explorer_process_tree_break.yaml`](./explorer_process_tree_break.yaml) |
| File Decryption Using Gpg4win | 🟡 medium | 50 | — | [`file_decryption_using_gpg4win.yaml`](./file_decryption_using_gpg4win.yaml) |
| File Download From Browser Process Via Inline URL | 🟡 medium | 50 | `T1105` | [`file_download_from_browser_process_via_inline_url.yaml`](./file_download_from_browser_process_via_inline_url.yaml) |
| File Download From IP URL Via Curl.EXE | 🟡 medium | 50 | — | [`file_download_from_ip_url_via_curl_exe.yaml`](./file_download_from_ip_url_via_curl_exe.yaml) |
| File Download Using ProtocolHandler.exe | 🟡 medium | 50 | `T1218` | [`file_download_using_protocolhandler_exe.yaml`](./file_download_using_protocolhandler_exe.yaml) |
| File Download Via Bitsadmin | 🟡 medium | 50 | `T1197`, `T1036.003`, `T1105` | [`file_download_via_bitsadmin.yaml`](./file_download_via_bitsadmin.yaml) |
| File Download via CertOC.EXE | 🟡 medium | 50 | `T1105` | [`file_download_via_certoc_exe.yaml`](./file_download_via_certoc_exe.yaml) |
| File Download Via InstallUtil.EXE | 🟡 medium | 50 | `T1218` | [`file_download_via_installutil_exe.yaml`](./file_download_via_installutil_exe.yaml) |
| File Encoded To Base64 Via Certutil.EXE | 🟡 medium | 50 | `T1027` | [`file_encoded_to_base64_via_certutil_exe.yaml`](./file_encoded_to_base64_via_certutil_exe.yaml) |
| File Encryption Using Gpg4win | 🟡 medium | 50 | — | [`file_encryption_using_gpg4win.yaml`](./file_encryption_using_gpg4win.yaml) |
| File Recovery From Backup Via Wbadmin.EXE | 🟡 medium | 50 | `T1490` | [`file_recovery_from_backup_via_wbadmin_exe.yaml`](./file_recovery_from_backup_via_wbadmin_exe.yaml) |
| Filter Driver Unloaded Via Fltmc.EXE | 🟡 medium | 50 | `T1070`, `T1685`, `T1685.001` | [`filter_driver_unloaded_via_fltmc_exe.yaml`](./filter_driver_unloaded_via_fltmc_exe.yaml) |
| Findstr Launching .lnk File | 🟡 medium | 50 | `T1036`, `T1202`, `T1027.003` | [`findstr_launching_lnk_file.yaml`](./findstr_launching_lnk_file.yaml) |
| Firewall Allowed Program Enable | 🟡 medium | 40 | `T1562.004` | [`firewall_allowed_program_enable.yaml`](./firewall_allowed_program_enable.yaml) |
| Firewall Disabled via Netsh.EXE | 🟡 medium | 50 | `T1686.003` | [`firewall_disabled_via_netsh_exe.yaml`](./firewall_disabled_via_netsh_exe.yaml) |
| Firewall Rule Deleted Via Netsh.EXE | 🟡 medium | 50 | `T1686.003` | [`firewall_rule_deleted_via_netsh_exe.yaml`](./firewall_rule_deleted_via_netsh_exe.yaml) |
| Firewall Rule Update Via Netsh.EXE | 🟡 medium | 50 | — | [`firewall_rule_update_via_netsh_exe.yaml`](./firewall_rule_update_via_netsh_exe.yaml) |
| Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet | 🟡 medium | 50 | `T1074.001` | [`folder_compress_to_potentially_suspicious_output_via_compress_archive_cmdlet.yaml`](./folder_compress_to_potentially_suspicious_output_via_compress_archive_cmdlet.yaml) |
| Forfiles Command Execution | 🟡 medium | 50 | `T1059` | [`forfiles_command_execution.yaml`](./forfiles_command_execution.yaml) |
| Get ADDefaultDomainPasswordPolicy with Powershell | 🟡 medium | 40 | `T1201` | [`get_addefaultdomainpasswordpolicy_with_powershell.yaml`](./get_addefaultdomainpasswordpolicy_with_powershell.yaml) |
| Get ADUser with PowerShell | 🟡 medium | 40 | `T1087.002` | [`get_aduser_with_powershell.yaml`](./get_aduser_with_powershell.yaml) |
| Get ADUserResultantPasswordPolicy with Powershell | 🟡 medium | 56 | `T1201` | [`get_aduserresultantpasswordpolicy_with_powershell.yaml`](./get_aduserresultantpasswordpolicy_with_powershell.yaml) |
| Get WMIObject Group Discovery | 🟡 medium | 40 | `T1069.001` | [`get_wmiobject_group_discovery.yaml`](./get_wmiobject_group_discovery.yaml) |
| GetAdComputer with PowerShell | 🟡 medium | 40 | `T1018` | [`getadcomputer_with_powershell.yaml`](./getadcomputer_with_powershell.yaml) |
| GetAdGroup with PowerShell | 🟡 medium | 40 | `T1069.002` | [`getadgroup_with_powershell.yaml`](./getadgroup_with_powershell.yaml) |
| GetCurrent User with PowerShell | 🟡 medium | 40 | `T1033` | [`getcurrent_user_with_powershell.yaml`](./getcurrent_user_with_powershell.yaml) |
| GetDomainController with PowerShell | 🟡 medium | 56 | `T1018` | [`getdomaincontroller_with_powershell.yaml`](./getdomaincontroller_with_powershell.yaml) |
| GetLocalUser with PowerShell | 🟡 medium | 40 | `T1087.001` | [`getlocaluser_with_powershell.yaml`](./getlocaluser_with_powershell.yaml) |
| GetNetTcpconnection with PowerShell | 🟡 medium | 40 | `T1049` | [`getnettcpconnection_with_powershell.yaml`](./getnettcpconnection_with_powershell.yaml) |
| GetWmiObject Ds Computer with PowerShell | 🟡 medium | 40 | `T1018` | [`getwmiobject_ds_computer_with_powershell.yaml`](./getwmiobject_ds_computer_with_powershell.yaml) |
| GetWmiObject Ds Group with PowerShell | 🟡 medium | 40 | `T1069.002` | [`getwmiobject_ds_group_with_powershell.yaml`](./getwmiobject_ds_group_with_powershell.yaml) |
| GetWmiObject DS User with PowerShell | 🟡 medium | 40 | `T1087.002` | [`getwmiobject_ds_user_with_powershell.yaml`](./getwmiobject_ds_user_with_powershell.yaml) |
| GetWmiObject User Account with PowerShell | 🟡 medium | 40 | `T1087.001` | [`getwmiobject_user_account_with_powershell.yaml`](./getwmiobject_user_account_with_powershell.yaml) |
| Github Self-Hosted Runner Execution | 🟡 medium | 50 | `T1102.002`, `T1071` | [`github_self_hosted_runner_execution.yaml`](./github_self_hosted_runner_execution.yaml) |
| Gpresult Display Group Policy Information | 🟡 medium | 50 | `T1615` | [`gpresult_display_group_policy_information.yaml`](./gpresult_display_group_policy_information.yaml) |
| Gpscript Execution | 🟡 medium | 50 | `T1218` | [`gpscript_execution.yaml`](./gpscript_execution.yaml) |
| Greedy File Deletion Using Del | 🟡 medium | 50 | `T1070.004` | [`greedy_file_deletion_using_del.yaml`](./greedy_file_deletion_using_del.yaml) |
| Group Membership Reconnaissance Via Whoami.EXE | 🟡 medium | 50 | `T1033` | [`group_membership_reconnaissance_via_whoami_exe.yaml`](./group_membership_reconnaissance_via_whoami_exe.yaml) |
| Gzip Archive Decode Via PowerShell | 🟡 medium | 50 | `T1132.001` | [`gzip_archive_decode_via_powershell.yaml`](./gzip_archive_decode_via_powershell.yaml) |
| HackTool - Impersonate Execution | 🟡 medium | 50 | `T1134.001`, `T1134.003` | [`hacktool_impersonate_execution.yaml`](./hacktool_impersonate_execution.yaml) |
| HackTool - Jlaive In-Memory Assembly Execution | 🟡 medium | 50 | `T1059.003` | [`hacktool_jlaive_in_memory_assembly_execution.yaml`](./hacktool_jlaive_in_memory_assembly_execution.yaml) |
| HackTool - LaZagne Execution | 🟡 medium | 50 | — | [`hacktool_lazagne_execution.yaml`](./hacktool_lazagne_execution.yaml) |
| HackTool - SharpLDAPmonitor Execution | 🟡 medium | 50 | — | [`hacktool_sharpldapmonitor_execution.yaml`](./hacktool_sharpldapmonitor_execution.yaml) |
| HackTool - WinRM Access Via Evil-WinRM | 🟡 medium | 50 | `T1021.006` | [`hacktool_winrm_access_via_evil_winrm.yaml`](./hacktool_winrm_access_via_evil_winrm.yaml) |
| Hardware Model Reconnaissance Via Wmic.EXE | 🟡 medium | 50 | `T1047` | [`hardware_model_reconnaissance_via_wmic_exe.yaml`](./hardware_model_reconnaissance_via_wmic_exe.yaml) |
| Harvesting Of Wifi Credentials Via Netsh.EXE | 🟡 medium | 50 | `T1040` | [`harvesting_of_wifi_credentials_via_netsh_exe.yaml`](./harvesting_of_wifi_credentials_via_netsh_exe.yaml) |
| Headless Browser Usage | 🟡 medium | 40 | `T1497`, `T1564.003` | [`headless_browser_usage.yaml`](./headless_browser_usage.yaml) |
| Hidden Powershell in Link File Pattern | 🟡 medium | 50 | `T1059.001` | [`hidden_powershell_in_link_file_pattern.yaml`](./hidden_powershell_in_link_file_pattern.yaml) |
| Hiding Files And Directories With Attrib exe | 🟡 medium | 56 | `T1222.001` | [`hiding_files_and_directories_with_attrib_exe.yaml`](./hiding_files_and_directories_with_attrib_exe.yaml) |
| Hiding Files with Attrib.exe | 🟡 medium | 50 | `T1564.001` | [`hiding_files_with_attrib_exe.yaml`](./hiding_files_with_attrib_exe.yaml) |
| Hiding User Account Via SpecialAccounts Registry Key - CommandLine | 🟡 medium | 50 | `T1564.002` | [`hiding_user_account_via_specialaccounts_registry_key_commandline.yaml`](./hiding_user_account_via_specialaccounts_registry_key_commandline.yaml) |
| Icacls Deny Command | 🟡 medium | 40 | `T1222` | [`icacls_deny_command.yaml`](./icacls_deny_command.yaml) |
| ICACLS Grant Command | 🟡 medium | 40 | `T1222` | [`icacls_grant_command.yaml`](./icacls_grant_command.yaml) |
| Ie4uinit Lolbin Use From Invalid Path | 🟡 medium | 50 | `T1218` | [`ie4uinit_lolbin_use_from_invalid_path.yaml`](./ie4uinit_lolbin_use_from_invalid_path.yaml) |
| IIS Native-Code Module Command Line Installation | 🟡 medium | 50 | `T1505.003` | [`iis_native_code_module_command_line_installation.yaml`](./iis_native_code_module_command_line_installation.yaml) |
| IIS WebServer Log Deletion via CommandLine Utilities | 🟡 medium | 50 | `T1070` | [`iis_webserver_log_deletion_via_commandline_utilities.yaml`](./iis_webserver_log_deletion_via_commandline_utilities.yaml) |
| Import LDAP Data Interchange Format File Via Ldifde.EXE | 🟡 medium | 50 | `T1218`, `T1105` | [`import_ldap_data_interchange_format_file_via_ldifde_exe.yaml`](./import_ldap_data_interchange_format_file_via_ldifde_exe.yaml) |
| Import PowerShell Modules From Suspicious Directories - ProcCreation | 🟡 medium | 50 | `T1059.001` | [`import_powershell_modules_from_suspicious_directories_proccreation.yaml`](./import_powershell_modules_from_suspicious_directories_proccreation.yaml) |
| Imports Registry Key From a File | 🟡 medium | 50 | `T1112` | [`imports_registry_key_from_a_file.yaml`](./imports_registry_key_from_a_file.yaml) |
| Indirect Command Execution From Script File Via Bash.EXE | 🟡 medium | 50 | `T1202` | [`indirect_command_execution_from_script_file_via_bash_exe.yaml`](./indirect_command_execution_from_script_file_via_bash_exe.yaml) |
| Indirect Command Execution via SFTP ProxyCommand | 🟡 medium | 50 | `T1202` | [`indirect_command_execution_via_sftp_proxycommand.yaml`](./indirect_command_execution_via_sftp_proxycommand.yaml) |
| Indirect Inline Command Execution Via Bash.EXE | 🟡 medium | 50 | `T1202` | [`indirect_inline_command_execution_via_bash_exe.yaml`](./indirect_inline_command_execution_via_bash_exe.yaml) |
| InfDefaultInstall.exe .inf Execution | 🟡 medium | 50 | `T1218` | [`infdefaultinstall_exe_inf_execution.yaml`](./infdefaultinstall_exe_inf_execution.yaml) |
| Insecure Proxy/DOH Transfer Via Curl.EXE | 🟡 medium | 50 | — | [`insecure_proxy_doh_transfer_via_curl_exe.yaml`](./insecure_proxy_doh_transfer_via_curl_exe.yaml) |
| Insecure Transfer Via Curl.EXE | 🟡 medium | 50 | — | [`insecure_transfer_via_curl_exe.yaml`](./insecure_transfer_via_curl_exe.yaml) |
| Install New Package Via Winget Local Manifest | 🟡 medium | 50 | `T1059` | [`install_new_package_via_winget_local_manifest.yaml`](./install_new_package_via_winget_local_manifest.yaml) |
| Invocation of Active Directory Diagnostic Tool (ntdsutil.exe) | 🟡 medium | 50 | `T1003.003` | [`invocation_of_active_directory_diagnostic_tool_ntdsutil_exe.yaml`](./invocation_of_active_directory_diagnostic_tool_ntdsutil_exe.yaml) |
| Invoke-Obfuscation COMPRESS OBFUSCATION | 🟡 medium | 50 | `T1027`, `T1059.001` | [`invoke_obfuscation_compress_obfuscation.yaml`](./invoke_obfuscation_compress_obfuscation.yaml) |
| Java Running with Remote Debugging | 🟡 medium | 50 | `T1203` | [`java_running_with_remote_debugging.yaml`](./java_running_with_remote_debugging.yaml) |
| Jscript Execution Using Cscript App | 🟡 medium | 50 | `T1059.007` | [`jscript_execution_using_cscript_app.yaml`](./jscript_execution_using_cscript_app.yaml) |
| Launch-VsDevShell.PS1 Proxy Execution | 🟡 medium | 50 | `T1216.001` | [`launch_vsdevshell_ps1_proxy_execution.yaml`](./launch_vsdevshell_ps1_proxy_execution.yaml) |
| Loaded Module Enumeration Via Tasklist.EXE | 🟡 medium | 50 | `T1003` | [`loaded_module_enumeration_via_tasklist_exe.yaml`](./loaded_module_enumeration_via_tasklist_exe.yaml) |
| Local Account Discovery With Wmic | 🟡 medium | 40 | `T1087.001` | [`local_account_discovery_with_wmic.yaml`](./local_account_discovery_with_wmic.yaml) |
| Local File Read Using Curl.EXE | 🟡 medium | 50 | — | [`local_file_read_using_curl_exe.yaml`](./local_file_read_using_curl_exe.yaml) |
| Logged-On User Password Change Via Ksetup.EXE | 🟡 medium | 50 | — | [`logged_on_user_password_change_via_ksetup_exe.yaml`](./logged_on_user_password_change_via_ksetup_exe.yaml) |
| LOLBAS Data Exfiltration by DataSvcUtil.exe | 🟡 medium | 50 | `T1567` | [`lolbas_data_exfiltration_by_datasvcutil_exe.yaml`](./lolbas_data_exfiltration_by_datasvcutil_exe.yaml) |
| LOLBIN Execution From Abnormal Drive | 🟡 medium | 50 | — | [`lolbin_execution_from_abnormal_drive.yaml`](./lolbin_execution_from_abnormal_drive.yaml) |
| Lolbin Runexehelper Use As Proxy | 🟡 medium | 50 | `T1218` | [`lolbin_runexehelper_use_as_proxy.yaml`](./lolbin_runexehelper_use_as_proxy.yaml) |
| Lolbin Unregmp2.exe Use As Proxy | 🟡 medium | 50 | `T1218` | [`lolbin_unregmp2_exe_use_as_proxy.yaml`](./lolbin_unregmp2_exe_use_as_proxy.yaml) |
| LSA PPL Protection Setting Modification via CommandLine | 🟡 medium | 50 | `T1689` | [`lsa_ppl_protection_setting_modification_via_commandline.yaml`](./lsa_ppl_protection_setting_modification_via_commandline.yaml) |
| Malicious PE Execution by Microsoft Visual Studio Debugger | 🟡 medium | 50 | `T1218` | [`malicious_pe_execution_by_microsoft_visual_studio_debugger.yaml`](./malicious_pe_execution_by_microsoft_visual_studio_debugger.yaml) |
| Malicious PowerShell Process - Encoded Command | 🟡 medium | 50 | `T1027` | [`malicious_powershell_process_encoded_command.yaml`](./malicious_powershell_process_encoded_command.yaml) |
| Modify Group Policy Settings | 🟡 medium | 50 | `T1484.001` | [`modify_group_policy_settings.yaml`](./modify_group_policy_settings.yaml) |
| Monitoring For Persistence Via BITS | 🟡 medium | 50 | `T1197` | [`monitoring_for_persistence_via_bits.yaml`](./monitoring_for_persistence_via_bits.yaml) |
| MSBuild Suspicious Spawned By Script Process | 🟡 medium | 50 | `T1127.001` | [`msbuild_suspicious_spawned_by_script_process.yaml`](./msbuild_suspicious_spawned_by_script_process.yaml) |
| MSExchange Transport Agent Installation | 🟡 medium | 50 | `T1505.002` | [`msexchange_transport_agent_installation.yaml`](./msexchange_transport_agent_installation.yaml) |
| Mshta spawning Rundll32 OR Regsvr32 Process | 🟡 medium | 50 | `T1218.005` | [`mshta_spawning_rundll32_or_regsvr32_process.yaml`](./mshta_spawning_rundll32_or_regsvr32_process.yaml) |
| Msiexec Quiet Installation | 🟡 medium | 50 | `T1218.007` | [`msiexec_quiet_installation.yaml`](./msiexec_quiet_installation.yaml) |
| MsiExec Web Install | 🟡 medium | 50 | `T1218.007`, `T1105` | [`msiexec_web_install.yaml`](./msiexec_web_install.yaml) |
| Msxsl.EXE Execution | 🟡 medium | 50 | `T1220` | [`msxsl_exe_execution.yaml`](./msxsl_exe_execution.yaml) |
| Netsh Allow Group Policy on Microsoft Defender Firewall | 🟡 medium | 50 | `T1686.003` | [`netsh_allow_group_policy_on_microsoft_defender_firewall.yaml`](./netsh_allow_group_policy_on_microsoft_defender_firewall.yaml) |
| Network Connection Discovery With Netstat | 🟡 medium | 40 | `T1049` | [`network_connection_discovery_with_netstat.yaml`](./network_connection_discovery_with_netstat.yaml) |
| New Agent Skills Installation Attempt Via Node.EXE | 🟡 medium | 50 | `T1059.007` | [`new_agent_skills_installation_attempt_via_node_exe.yaml`](./new_agent_skills_installation_attempt_via_node_exe.yaml) |
| New Capture Session Launched Via DXCap.EXE | 🟡 medium | 50 | `T1218` | [`new_capture_session_launched_via_dxcap_exe.yaml`](./new_capture_session_launched_via_dxcap_exe.yaml) |
| New DLL Registered Via Odbcconf.EXE | 🟡 medium | 50 | `T1218.008` | [`new_dll_registered_via_odbcconf_exe.yaml`](./new_dll_registered_via_odbcconf_exe.yaml) |
| New DMSA Service Account Created in Specific OUs | 🟡 medium | 50 | `T1078.002`, `T1098` | [`new_dmsa_service_account_created_in_specific_ous.yaml`](./new_dmsa_service_account_created_in_specific_ous.yaml) |
| New Firewall Rule Added Via Netsh.EXE | 🟡 medium | 50 | `T1686.003` | [`new_firewall_rule_added_via_netsh_exe.yaml`](./new_firewall_rule_added_via_netsh_exe.yaml) |
| New Generic Credentials Added Via Cmdkey.EXE | 🟡 medium | 50 | `T1003.005` | [`new_generic_credentials_added_via_cmdkey_exe.yaml`](./new_generic_credentials_added_via_cmdkey_exe.yaml) |
| New Kernel Driver Via SC.EXE | 🟡 medium | 50 | `T1543.003` | [`new_kernel_driver_via_sc_exe.yaml`](./new_kernel_driver_via_sc_exe.yaml) |
| New Network Trace Capture Started Via Netsh.EXE | 🟡 medium | 50 | `T1040` | [`new_network_trace_capture_started_via_netsh_exe.yaml`](./new_network_trace_capture_started_via_netsh_exe.yaml) |
| New Port Forwarding Rule Added Via Netsh.EXE | 🟡 medium | 50 | `T1090` | [`new_port_forwarding_rule_added_via_netsh_exe.yaml`](./new_port_forwarding_rule_added_via_netsh_exe.yaml) |
| New Remote Desktop Connection Initiated Via Mstsc.EXE | 🟡 medium | 50 | `T1021.001` | [`new_remote_desktop_connection_initiated_via_mstsc_exe.yaml`](./new_remote_desktop_connection_initiated_via_mstsc_exe.yaml) |
| New Root Certificate Installed Via CertMgr.EXE | 🟡 medium | 50 | `T1553.004` | [`new_root_certificate_installed_via_certmgr_exe.yaml`](./new_root_certificate_installed_via_certmgr_exe.yaml) |
| New Root Certificate Installed Via Certutil.EXE | 🟡 medium | 50 | `T1553.004` | [`new_root_certificate_installed_via_certutil_exe.yaml`](./new_root_certificate_installed_via_certutil_exe.yaml) |
| New User Created Via Net.EXE | 🟡 medium | 50 | `T1136.001` | [`new_user_created_via_net_exe.yaml`](./new_user_created_via_net_exe.yaml) |
| New Virtual Smart Card Created Via TpmVscMgr.EXE | 🟡 medium | 50 | — | [`new_virtual_smart_card_created_via_tpmvscmgr_exe.yaml`](./new_virtual_smart_card_created_via_tpmvscmgr_exe.yaml) |
| NLTest Domain Trust Discovery | 🟡 medium | 50 | `T1482` | [`nltest_domain_trust_discovery.yaml`](./nltest_domain_trust_discovery.yaml) |
| Node Process Executions | 🟡 medium | 50 | `T1127`, `T1059.007` | [`node_process_executions.yaml`](./node_process_executions.yaml) |
| Notepad with no Command Line Arguments | 🟡 medium | 50 | `T1055` | [`notepad_with_no_command_line_arguments.yaml`](./notepad_with_no_command_line_arguments.yaml) |
| Nslookup PowerShell Download Cradle - ProcessCreation | 🟡 medium | 50 | — | [`nslookup_powershell_download_cradle_processcreation.yaml`](./nslookup_powershell_download_cradle_processcreation.yaml) |
| OpenEDR Spawning Command Shell | 🟡 medium | 50 | `T1059.003`, `T1021.004`, `T1219` | [`openedr_spawning_command_shell.yaml`](./openedr_spawning_command_shell.yaml) |
| Password Provided In Command Line Of Net.EXE | 🟡 medium | 50 | `T1021.002`, `T1078` | [`password_provided_in_command_line_of_net_exe.yaml`](./password_provided_in_command_line_of_net_exe.yaml) |
| Password Set to Never Expire via WMI | 🟡 medium | 50 | `T1047`, `T1098` | [`password_set_to_never_expire_via_wmi.yaml`](./password_set_to_never_expire_via_wmi.yaml) |
| PDQ Deploy Remote Adminstartion Tool Execution | 🟡 medium | 50 | `T1072` | [`pdq_deploy_remote_adminstartion_tool_execution.yaml`](./pdq_deploy_remote_adminstartion_tool_execution.yaml) |
| Perl Inline Command Execution | 🟡 medium | 50 | `T1059` | [`perl_inline_command_execution.yaml`](./perl_inline_command_execution.yaml) |
| Permission Check Via Accesschk.EXE | 🟡 medium | 50 | `T1069.001` | [`permission_check_via_accesschk_exe.yaml`](./permission_check_via_accesschk_exe.yaml) |
| Permission Misconfiguration Reconnaissance Via Findstr.EXE | 🟡 medium | 50 | `T1552.006` | [`permission_misconfiguration_reconnaissance_via_findstr_exe.yaml`](./permission_misconfiguration_reconnaissance_via_findstr_exe.yaml) |
| Persistence Via TypedPaths - CommandLine | 🟡 medium | 50 | — | [`persistence_via_typedpaths_commandline.yaml`](./persistence_via_typedpaths_commandline.yaml) |
| Php Inline Command Execution | 🟡 medium | 50 | `T1059` | [`php_inline_command_execution.yaml`](./php_inline_command_execution.yaml) |
| PktMon.EXE Execution | 🟡 medium | 50 | `T1040` | [`pktmon_exe_execution.yaml`](./pktmon_exe_execution.yaml) |
| Port Forwarding Activity Via SSH.EXE | 🟡 medium | 50 | `T1572`, `T1021.001`, `T1021.004` | [`port_forwarding_activity_via_ssh_exe.yaml`](./port_forwarding_activity_via_ssh_exe.yaml) |
| Portable Gpg.EXE Execution | 🟡 medium | 50 | `T1486` | [`portable_gpg_exe_execution.yaml`](./portable_gpg_exe_execution.yaml) |
| Possible Browser Pass View Parameter | 🟡 medium | 50 | `T1555.003` | [`possible_browser_pass_view_parameter.yaml`](./possible_browser_pass_view_parameter.yaml) |
| Possible Lateral Movement PowerShell Spawn | 🟡 medium | 50 | `T1021.003`, `T1021.006`, `T1047`… | [`possible_lateral_movement_powershell_spawn.yaml`](./possible_lateral_movement_powershell_spawn.yaml) |
| Potential Active Directory Enumeration Using AD Module - ProcCreation | 🟡 medium | 50 | — | [`potential_active_directory_enumeration_using_ad_module_proccreation.yaml`](./potential_active_directory_enumeration_using_ad_module_proccreation.yaml) |
| Potential Amazon SSM Agent Hijacking | 🟡 medium | 50 | `T1219.002` | [`potential_amazon_ssm_agent_hijacking.yaml`](./potential_amazon_ssm_agent_hijacking.yaml) |
| Potential AMSI Bypass Using NULL Bits | 🟡 medium | 50 | `T1685` | [`potential_amsi_bypass_using_null_bits.yaml`](./potential_amsi_bypass_using_null_bits.yaml) |
| Potential Application Whitelisting Bypass via Dnx.EXE | 🟡 medium | 50 | `T1218`, `T1027.004` | [`potential_application_whitelisting_bypass_via_dnx_exe.yaml`](./potential_application_whitelisting_bypass_via_dnx_exe.yaml) |
| Potential APT FIN7 Exploitation Activity | 🟡 medium | 50 | `T1059.001`, `T1059.003` | [`potential_apt_fin7_exploitation_activity.yaml`](./potential_apt_fin7_exploitation_activity.yaml) |
| Potential APT-C-12 BlueMushroom DLL Load Activity Via Regsvr32 | 🟡 medium | 50 | `T1218.010` | [`potential_apt_c_12_bluemushroom_dll_load_activity_via_regsvr32.yaml`](./potential_apt_c_12_bluemushroom_dll_load_activity_via_regsvr32.yaml) |
| Potential Arbitrary Command Execution Via FTP.EXE | 🟡 medium | 50 | `T1059`, `T1202` | [`potential_arbitrary_command_execution_via_ftp_exe.yaml`](./potential_arbitrary_command_execution_via_ftp_exe.yaml) |
| Potential Arbitrary DLL Load Using Winword | 🟡 medium | 50 | `T1202` | [`potential_arbitrary_dll_load_using_winword.yaml`](./potential_arbitrary_dll_load_using_winword.yaml) |
| Potential Arbitrary File Download Via Cmdl32.EXE | 🟡 medium | 50 | `T1218`, `T1202` | [`potential_arbitrary_file_download_via_cmdl32_exe.yaml`](./potential_arbitrary_file_download_via_cmdl32_exe.yaml) |
| Potential Binary Proxy Execution Via Cdb.EXE | 🟡 medium | 50 | `T1106`, `T1218`, `T1127` | [`potential_binary_proxy_execution_via_cdb_exe.yaml`](./potential_binary_proxy_execution_via_cdb_exe.yaml) |
| Potential Binary Proxy Execution Via VSDiagnostics.EXE | 🟡 medium | 50 | `T1218` | [`potential_binary_proxy_execution_via_vsdiagnostics_exe.yaml`](./potential_binary_proxy_execution_via_vsdiagnostics_exe.yaml) |
| Potential Browser Data Stealing | 🟡 medium | 50 | `T1555.003` | [`potential_browser_data_stealing.yaml`](./potential_browser_data_stealing.yaml) |
| Potential COM Objects Download Cradles Usage - Process Creation | 🟡 medium | 50 | `T1105` | [`potential_com_objects_download_cradles_usage_process_creation.yaml`](./potential_com_objects_download_cradles_usage_process_creation.yaml) |
| Potential Command Line Path Traversal Evasion Attempt | 🟡 medium | 50 | `T1036` | [`potential_command_line_path_traversal_evasion_attempt.yaml`](./potential_command_line_path_traversal_evasion_attempt.yaml) |
| Potential Commandline Obfuscation Using Escape Characters | 🟡 medium | 50 | `T1140` | [`potential_commandline_obfuscation_using_escape_characters.yaml`](./potential_commandline_obfuscation_using_escape_characters.yaml) |
| Potential Configuration And Service Reconnaissance Via Reg.EXE | 🟡 medium | 50 | `T1012`, `T1007` | [`potential_configuration_and_service_reconnaissance_via_reg_exe.yaml`](./potential_configuration_and_service_reconnaissance_via_reg_exe.yaml) |
| Potential Cookies Session Hijacking | 🟡 medium | 50 | — | [`potential_cookies_session_hijacking.yaml`](./potential_cookies_session_hijacking.yaml) |
| Potential CVE-2022-22954 Exploitation Attempt - VMware Workspace ONE Access Remote Code Execution | 🟡 medium | 50 | `T1059.006`, `T1190` | [`potential_cve_2022_22954_exploitation_attempt_vmware_workspace_one_access_remote_code_execution.yaml`](./potential_cve_2022_22954_exploitation_attempt_vmware_workspace_one_access_remote_code_execution.yaml) |
| Potential Defense Evasion Via Binary Rename | 🟡 medium | 50 | `T1036.003` | [`potential_defense_evasion_via_binary_rename.yaml`](./potential_defense_evasion_via_binary_rename.yaml) |
| Potential Discovery Activity Via Dnscmd.EXE | 🟡 medium | 50 | — | [`potential_discovery_activity_via_dnscmd_exe.yaml`](./potential_discovery_activity_via_dnscmd_exe.yaml) |
| Potential DLL File Download Via PowerShell Invoke-WebRequest | 🟡 medium | 50 | `T1059.001`, `T1105` | [`potential_dll_file_download_via_powershell_invoke_webrequest.yaml`](./potential_dll_file_download_via_powershell_invoke_webrequest.yaml) |
| Potential DLL Injection Or Execution Using Tracker.exe | 🟡 medium | 50 | `T1055.001` | [`potential_dll_injection_or_execution_using_tracker_exe.yaml`](./potential_dll_injection_or_execution_using_tracker_exe.yaml) |
| Potential DLL Injection Via AccCheckConsole | 🟡 medium | 50 | — | [`potential_dll_injection_via_acccheckconsole.yaml`](./potential_dll_injection_via_acccheckconsole.yaml) |
| Potential DLL Sideloading Via DeviceEnroller.EXE | 🟡 medium | 50 | `T1574.001` | [`potential_dll_sideloading_via_deviceenroller_exe.yaml`](./potential_dll_sideloading_via_deviceenroller_exe.yaml) |
| Potential Dosfuscation Activity | 🟡 medium | 50 | `T1059` | [`potential_dosfuscation_activity.yaml`](./potential_dosfuscation_activity.yaml) |
| Potential Download/Upload Activity Using Type Command | 🟡 medium | 50 | `T1105` | [`potential_download_upload_activity_using_type_command.yaml`](./potential_download_upload_activity_using_type_command.yaml) |
| Potential Dropper Script Execution Via WScript/CScript/MSHTA | 🟡 medium | 50 | `T1059.005`, `T1059.007` | [`potential_dropper_script_execution_via_wscript_cscript_mshta.yaml`](./potential_dropper_script_execution_via_wscript_cscript_mshta.yaml) |
| Potential Fake Instance Of Hxtsr.EXE Executed | 🟡 medium | 50 | `T1036` | [`potential_fake_instance_of_hxtsr_exe_executed.yaml`](./potential_fake_instance_of_hxtsr_exe_executed.yaml) |
| Potential File Download Via MS-AppInstaller Protocol Handler | 🟡 medium | 50 | `T1218` | [`potential_file_download_via_ms_appinstaller_protocol_handler.yaml`](./potential_file_download_via_ms_appinstaller_protocol_handler.yaml) |
| Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream - CLI | 🟡 medium | 50 | `T1564.004` | [`potential_hidden_directory_creation_via_ntfs_index_allocation_stream_cli.yaml`](./potential_hidden_directory_creation_via_ntfs_index_allocation_stream_cli.yaml) |
| Potential Homoglyph Attack Using Lookalike Characters | 🟡 medium | 50 | `T1036`, `T1036.003` | [`potential_homoglyph_attack_using_lookalike_characters.yaml`](./potential_homoglyph_attack_using_lookalike_characters.yaml) |
| Potential KamiKakaBot Activity - Lure Document Execution | 🟡 medium | 50 | `T1059` | [`potential_kamikakabot_activity_lure_document_execution.yaml`](./potential_kamikakabot_activity_lure_document_execution.yaml) |
| Potential KamiKakaBot Activity - Shutdown Schedule Task Creation | 🟡 medium | 50 | — | [`potential_kamikakabot_activity_shutdown_schedule_task_creation.yaml`](./potential_kamikakabot_activity_shutdown_schedule_task_creation.yaml) |
| Potential Lateral Movement via Windows Remote Shell | 🟡 medium | 50 | `T1021.006` | [`potential_lateral_movement_via_windows_remote_shell.yaml`](./potential_lateral_movement_via_windows_remote_shell.yaml) |
| Potential Memory Dumping Activity Via LiveKD | 🟡 medium | 50 | — | [`potential_memory_dumping_activity_via_livekd.yaml`](./potential_memory_dumping_activity_via_livekd.yaml) |
| Potential Mftrace.EXE Abuse | 🟡 medium | 50 | `T1127` | [`potential_mftrace_exe_abuse.yaml`](./potential_mftrace_exe_abuse.yaml) |
| Potential MOVEit Transfer CVE-2023-34362 Exploitation - Dynamic Compilation Via Csc.EXE | 🟡 medium | 50 | `T1059` | [`potential_moveit_transfer_cve_2023_34362_exploitation_dynamic_compilation_via_csc_exe.yaml`](./potential_moveit_transfer_cve_2023_34362_exploitation_dynamic_compilation_via_csc_exe.yaml) |
| Potential Mpclient.DLL Sideloading Via OfflineScannerShell.EXE Execution | 🟡 medium | 50 | `T1218` | [`potential_mpclient_dll_sideloading_via_offlinescannershell_exe_execution.yaml`](./potential_mpclient_dll_sideloading_via_offlinescannershell_exe_execution.yaml) |
| Potential Network Sniffing Activity Using Network Tools | 🟡 medium | 50 | `T1040` | [`potential_network_sniffing_activity_using_network_tools.yaml`](./potential_network_sniffing_activity_using_network_tools.yaml) |
| Potential Obfuscated Ordinal Call Via Rundll32 | 🟡 medium | 50 | `T1027.010` | [`potential_obfuscated_ordinal_call_via_rundll32.yaml`](./potential_obfuscated_ordinal_call_via_rundll32.yaml) |
| Potential Password Spraying Attempt Using Dsacls.EXE | 🟡 medium | 50 | `T1218` | [`potential_password_spraying_attempt_using_dsacls_exe.yaml`](./potential_password_spraying_attempt_using_dsacls_exe.yaml) |
| Potential Persistence Attempt Via Existing Service Tampering | 🟡 medium | 50 | `T1543.003`, `T1574.011` | [`potential_persistence_attempt_via_existing_service_tampering.yaml`](./potential_persistence_attempt_via_existing_service_tampering.yaml) |
| Potential Persistence Attempt Via Run Keys Using Reg.EXE | 🟡 medium | 50 | `T1547.001` | [`potential_persistence_attempt_via_run_keys_using_reg_exe.yaml`](./potential_persistence_attempt_via_run_keys_using_reg_exe.yaml) |
| Potential Persistence Via Microsoft Compatibility Appraiser | 🟡 medium | 50 | `T1053.005` | [`potential_persistence_via_microsoft_compatibility_appraiser.yaml`](./potential_persistence_via_microsoft_compatibility_appraiser.yaml) |
| Potential Persistence Via Netsh Helper DLL | 🟡 medium | 50 | `T1546.007` | [`potential_persistence_via_netsh_helper_dll.yaml`](./potential_persistence_via_netsh_helper_dll.yaml) |
| Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | 🟡 medium | 50 | `T1059` | [`potential_persistence_via_vmwaretoolboxcmd_exe_vm_state_change_script.yaml`](./potential_persistence_via_vmwaretoolboxcmd_exe_vm_state_change_script.yaml) |
| Potential Pikabot Infection - Suspicious Command Combinations Via Cmd.EXE | 🟡 medium | 50 | `T1059.003`, `T1105`, `T1218` | [`potential_pikabot_infection_suspicious_command_combinations_via_cmd_exe.yaml`](./potential_pikabot_infection_suspicious_command_combinations_via_cmd_exe.yaml) |
| Potential PowerShell Console History Access Attempt via History File | 🟡 medium | 50 | `T1552.001` | [`potential_powershell_console_history_access_attempt_via_history_file.yaml`](./potential_powershell_console_history_access_attempt_via_history_file.yaml) |
| Potential PowerShell Downgrade Attack | 🟡 medium | 50 | `T1059.001` | [`potential_powershell_downgrade_attack.yaml`](./potential_powershell_downgrade_attack.yaml) |
| Potential Process Execution Proxy Via CL_Invocation.ps1 | 🟡 medium | 50 | `T1216` | [`potential_process_execution_proxy_via_cl_invocation_ps1.yaml`](./potential_process_execution_proxy_via_cl_invocation_ps1.yaml) |
| Potential Process Reconnaissance via Wmic.EXE | 🟡 medium | 50 | `T1047`, `T1057` | [`potential_process_reconnaissance_via_wmic_exe.yaml`](./potential_process_reconnaissance_via_wmic_exe.yaml) |
| Potential Product Class Reconnaissance Via Wmic.EXE | 🟡 medium | 50 | `T1047`, `T1082` | [`potential_product_class_reconnaissance_via_wmic_exe.yaml`](./potential_product_class_reconnaissance_via_wmic_exe.yaml) |
| Potential Product Reconnaissance Via Wmic.EXE | 🟡 medium | 50 | `T1047` | [`potential_product_reconnaissance_via_wmic_exe.yaml`](./potential_product_reconnaissance_via_wmic_exe.yaml) |
| Potential Provlaunch.EXE Binary Proxy Execution Abuse | 🟡 medium | 50 | `T1218` | [`potential_provlaunch_exe_binary_proxy_execution_abuse.yaml`](./potential_provlaunch_exe_binary_proxy_execution_abuse.yaml) |
| Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE | 🟡 medium | 50 | `T1070`, `T1542.003` | [`potential_ransomware_or_unauthorized_mbr_tampering_via_bcdedit_exe.yaml`](./potential_ransomware_or_unauthorized_mbr_tampering_via_bcdedit_exe.yaml) |
| Potential RDP Session Hijacking Activity | 🟡 medium | 50 | — | [`potential_rdp_session_hijacking_activity.yaml`](./potential_rdp_session_hijacking_activity.yaml) |
| Potential Recon Activity Via Nltest.EXE | 🟡 medium | 50 | `T1016`, `T1482` | [`potential_recon_activity_via_nltest_exe.yaml`](./potential_recon_activity_via_nltest_exe.yaml) |
| Potential Reconnaissance Activity Via GatherNetworkInfo.VBS | 🟡 medium | 50 | `T1615`, `T1059.005` | [`potential_reconnaissance_activity_via_gathernetworkinfo_vbs.yaml`](./potential_reconnaissance_activity_via_gathernetworkinfo_vbs.yaml) |
| Potential ReflectDebugger Content Execution Via WerFault.EXE | 🟡 medium | 50 | `T1036` | [`potential_reflectdebugger_content_execution_via_werfault_exe.yaml`](./potential_reflectdebugger_content_execution_via_werfault_exe.yaml) |
| Potential Register_App.Vbs LOLScript Abuse | 🟡 medium | 50 | `T1218` | [`potential_register_app_vbs_lolscript_abuse.yaml`](./potential_register_app_vbs_lolscript_abuse.yaml) |
| Potential Regsvr32 Commandline Flag Anomaly | 🟡 medium | 50 | `T1218.010` | [`potential_regsvr32_commandline_flag_anomaly.yaml`](./potential_regsvr32_commandline_flag_anomaly.yaml) |
| Potential Remote Desktop Tunneling | 🟡 medium | 50 | `T1021` | [`potential_remote_desktop_tunneling.yaml`](./potential_remote_desktop_tunneling.yaml) |
| Potential Script Proxy Execution Via CL_Mutexverifiers.ps1 | 🟡 medium | 50 | `T1216` | [`potential_script_proxy_execution_via_cl_mutexverifiers_ps1.yaml`](./potential_script_proxy_execution_via_cl_mutexverifiers_ps1.yaml) |
| Potential ShellDispatch.DLL Functionality Abuse | 🟡 medium | 50 | — | [`potential_shelldispatch_dll_functionality_abuse.yaml`](./potential_shelldispatch_dll_functionality_abuse.yaml) |
| Potential Shim Database Persistence via Sdbinst.EXE | 🟡 medium | 50 | `T1546.011` | [`potential_shim_database_persistence_via_sdbinst_exe.yaml`](./potential_shim_database_persistence_via_sdbinst_exe.yaml) |
| Potential SPN Enumeration Via Setspn.EXE | 🟡 medium | 50 | `T1558.003` | [`potential_spn_enumeration_via_setspn_exe.yaml`](./potential_spn_enumeration_via_setspn_exe.yaml) |
| Potential Suspicious Activity Using SeCEdit | 🟡 medium | 50 | `T1685.001`, `T1547.001`, `T1505.005`… | [`potential_suspicious_activity_using_secedit.yaml`](./potential_suspicious_activity_using_secedit.yaml) |
| Potential Suspicious Browser Launch From Document Reader Process | 🟡 medium | 50 | `T1204.002` | [`potential_suspicious_browser_launch_from_document_reader_process.yaml`](./potential_suspicious_browser_launch_from_document_reader_process.yaml) |
| Potential Suspicious Registry File Imported Via Reg.EXE | 🟡 medium | 50 | `T1112` | [`potential_suspicious_registry_file_imported_via_reg_exe.yaml`](./potential_suspicious_registry_file_imported_via_reg_exe.yaml) |
| Potential Suspicious Windows Feature Enabled - ProcCreation | 🟡 medium | 50 | — | [`potential_suspicious_windows_feature_enabled_proccreation.yaml`](./potential_suspicious_windows_feature_enabled_proccreation.yaml) |
| Potential UAC Bypass Via Sdclt.EXE | 🟡 medium | 50 | `T1548.002` | [`potential_uac_bypass_via_sdclt_exe.yaml`](./potential_uac_bypass_via_sdclt_exe.yaml) |
| Potential Unquoted Service Path Reconnaissance Via Wmic.EXE | 🟡 medium | 50 | `T1047` | [`potential_unquoted_service_path_reconnaissance_via_wmic_exe.yaml`](./potential_unquoted_service_path_reconnaissance_via_wmic_exe.yaml) |
| Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell | 🟡 medium | 50 | `T1047`, `T1059.001` | [`potential_wmi_lateral_movement_wmiprvse_spawned_powershell.yaml`](./potential_wmi_lateral_movement_wmiprvse_spawned_powershell.yaml) |
| Potentially Over Permissive Permissions Granted Using Dsacls.EXE | 🟡 medium | 50 | `T1218` | [`potentially_over_permissive_permissions_granted_using_dsacls_exe.yaml`](./potentially_over_permissive_permissions_granted_using_dsacls_exe.yaml) |
| Potentially Suspicious Cabinet File Expansion | 🟡 medium | 50 | `T1218` | [`potentially_suspicious_cabinet_file_expansion.yaml`](./potentially_suspicious_cabinet_file_expansion.yaml) |
| Potentially Suspicious Child Process Of ClickOnce Application | 🟡 medium | 50 | — | [`potentially_suspicious_child_process_of_clickonce_application.yaml`](./potentially_suspicious_child_process_of_clickonce_application.yaml) |
| Potentially Suspicious Child Process Of DiskShadow.EXE | 🟡 medium | 50 | `T1218` | [`potentially_suspicious_child_process_of_diskshadow_exe.yaml`](./potentially_suspicious_child_process_of_diskshadow_exe.yaml) |
| Potentially Suspicious Child Process of KeyScrambler.exe | 🟡 medium | 50 | `T1203`, `T1574.001` | [`potentially_suspicious_child_process_of_keyscrambler_exe.yaml`](./potentially_suspicious_child_process_of_keyscrambler_exe.yaml) |
| Potentially Suspicious Child Process Of VsCode | 🟡 medium | 50 | `T1218`, `T1202` | [`potentially_suspicious_child_process_of_vscode.yaml`](./potentially_suspicious_child_process_of_vscode.yaml) |
| Potentially Suspicious Child Process Of WinRAR.EXE | 🟡 medium | 50 | `T1203` | [`potentially_suspicious_child_process_of_winrar_exe.yaml`](./potentially_suspicious_child_process_of_winrar_exe.yaml) |
| Potentially Suspicious CMD Shell Output Redirect | 🟡 medium | 50 | `T1218` | [`potentially_suspicious_cmd_shell_output_redirect.yaml`](./potentially_suspicious_cmd_shell_output_redirect.yaml) |
| Potentially Suspicious Command Targeting Teams Sensitive Files | 🟡 medium | 50 | `T1528` | [`potentially_suspicious_command_targeting_teams_sensitive_files.yaml`](./potentially_suspicious_command_targeting_teams_sensitive_files.yaml) |
| Potentially Suspicious Desktop Background Change Using Reg.EXE | 🟡 medium | 50 | `T1112`, `T1491.001` | [`potentially_suspicious_desktop_background_change_using_reg_exe.yaml`](./potentially_suspicious_desktop_background_change_using_reg_exe.yaml) |
| Potentially Suspicious Electron Application CommandLine | 🟡 medium | 50 | — | [`potentially_suspicious_electron_application_commandline.yaml`](./potentially_suspicious_electron_application_commandline.yaml) |
| Potentially Suspicious EventLog Recon Activity Using Log Query Utilities | 🟡 medium | 50 | `T1552`, `T1087` | [`potentially_suspicious_eventlog_recon_activity_using_log_query_utilities.yaml`](./potentially_suspicious_eventlog_recon_activity_using_log_query_utilities.yaml) |
| Potentially Suspicious Execution Of PDQDeployRunner | 🟡 medium | 50 | — | [`potentially_suspicious_execution_of_pdqdeployrunner.yaml`](./potentially_suspicious_execution_of_pdqdeployrunner.yaml) |
| Potentially Suspicious Execution Of Regasm/Regsvcs From Uncommon Location | 🟡 medium | 50 | `T1218.009` | [`potentially_suspicious_execution_of_regasm_regsvcs_from_uncommon_location.yaml`](./potentially_suspicious_execution_of_regasm_regsvcs_from_uncommon_location.yaml) |
| Potentially Suspicious Execution Of Regasm/Regsvcs With Uncommon Extension | 🟡 medium | 50 | `T1218.009` | [`potentially_suspicious_execution_of_regasm_regsvcs_with_uncommon_extension.yaml`](./potentially_suspicious_execution_of_regasm_regsvcs_with_uncommon_extension.yaml) |
| Potentially Suspicious Inline JavaScript Execution via NodeJS Binary | 🟡 medium | 50 | `T1059.007` | [`potentially_suspicious_inline_javascript_execution_via_nodejs_binary.yaml`](./potentially_suspicious_inline_javascript_execution_via_nodejs_binary.yaml) |
| Potentially Suspicious JWT Token Search Via CLI | 🟡 medium | 50 | `T1528`, `T1552.001` | [`potentially_suspicious_jwt_token_search_via_cli.yaml`](./potentially_suspicious_jwt_token_search_via_cli.yaml) |
| Potentially Suspicious NTFS Symlink Behavior Modification | 🟡 medium | 50 | `T1059`, `T1222.001` | [`potentially_suspicious_ntfs_symlink_behavior_modification.yaml`](./potentially_suspicious_ntfs_symlink_behavior_modification.yaml) |
| Potentially Suspicious Ping/Copy Command Combination | 🟡 medium | 50 | `T1070.004` | [`potentially_suspicious_ping_copy_command_combination.yaml`](./potentially_suspicious_ping_copy_command_combination.yaml) |
| Potentially Suspicious Powershell Script Execution From Temp Folder | 🟡 medium | 50 | `T1059.001` | [`potentially_suspicious_powershell_script_execution_from_temp_folder.yaml`](./potentially_suspicious_powershell_script_execution_from_temp_folder.yaml) |
| Potentially Suspicious Regsvr32 HTTP/FTP Pattern | 🟡 medium | 50 | `T1218.010` | [`potentially_suspicious_regsvr32_http_ftp_pattern.yaml`](./potentially_suspicious_regsvr32_http_ftp_pattern.yaml) |
| Potentially Suspicious Rundll32 Activity | 🟡 medium | 50 | `T1218.011` | [`potentially_suspicious_rundll32_activity.yaml`](./potentially_suspicious_rundll32_activity.yaml) |
| Potentially Suspicious Rundll32.EXE Execution of UDL File | 🟡 medium | 50 | `T1218.011`, `T1071` | [`potentially_suspicious_rundll32_exe_execution_of_udl_file.yaml`](./potentially_suspicious_rundll32_exe_execution_of_udl_file.yaml) |
| Potentially Suspicious Usage Of Qemu | 🟡 medium | 50 | `T1090`, `T1572` | [`potentially_suspicious_usage_of_qemu.yaml`](./potentially_suspicious_usage_of_qemu.yaml) |
| Potentially Suspicious WebDAV LNK Execution | 🟡 medium | 50 | `T1059.001`, `T1204` | [`potentially_suspicious_webdav_lnk_execution.yaml`](./potentially_suspicious_webdav_lnk_execution.yaml) |
| Potentially Suspicious Windows App Activity | 🟡 medium | 50 | — | [`potentially_suspicious_windows_app_activity.yaml`](./potentially_suspicious_windows_app_activity.yaml) |
| Powershell Defender Exclusion | 🟡 medium | 50 | `T1685` | [`powershell_defender_exclusion.yaml`](./powershell_defender_exclusion.yaml) |
| Powershell Disable Security Monitoring | 🟡 medium | 50 | `T1562.001` | [`powershell_disable_security_monitoring.yaml`](./powershell_disable_security_monitoring.yaml) |
| PowerShell Download Pattern | 🟡 medium | 50 | `T1059.001` | [`powershell_download_pattern.yaml`](./powershell_download_pattern.yaml) |
| Powershell Executed From Headless ConHost Process | 🟡 medium | 50 | `T1059.001`, `T1059.003`, `T1564.003` | [`powershell_executed_from_headless_conhost_process.yaml`](./powershell_executed_from_headless_conhost_process.yaml) |
| PowerShell Get-Clipboard Cmdlet Via CLI | 🟡 medium | 50 | `T1115` | [`powershell_get_clipboard_cmdlet_via_cli.yaml`](./powershell_get_clipboard_cmdlet_via_cli.yaml) |
| Powershell Inline Execution From A File | 🟡 medium | 50 | `T1059.001` | [`powershell_inline_execution_from_a_file.yaml`](./powershell_inline_execution_from_a_file.yaml) |
| PowerShell MSI Install via WindowsInstaller COM From Remote Location | 🟡 medium | 50 | `T1059.001`, `T1218`, `T1105` | [`powershell_msi_install_via_windowsinstaller_com_from_remote_location.yaml`](./powershell_msi_install_via_windowsinstaller_com_from_remote_location.yaml) |
| PowerShell Script Run in AppData | 🟡 medium | 50 | `T1059.001` | [`powershell_script_run_in_appdata.yaml`](./powershell_script_run_in_appdata.yaml) |
| PowerShell Start-BitsTransfer | 🟡 medium | 50 | `T1197` | [`powershell_start_bitstransfer.yaml`](./powershell_start_bitstransfer.yaml) |
| Private Keys Reconnaissance Via CommandLine Tools | 🟡 medium | 50 | `T1552.004` | [`private_keys_reconnaissance_via_commandline_tools.yaml`](./private_keys_reconnaissance_via_commandline_tools.yaml) |
| Procdump Execution | 🟡 medium | 50 | `T1036`, `T1003.001` | [`procdump_execution.yaml`](./procdump_execution.yaml) |
| Process Creation Attempt via Wmic.EXE | 🟡 medium | 50 | `T1047` | [`process_creation_attempt_via_wmic_exe.yaml`](./process_creation_attempt_via_wmic_exe.yaml) |
| Process Creation Using Sysnative Folder | 🟡 medium | 50 | `T1055` | [`process_creation_using_sysnative_folder.yaml`](./process_creation_using_sysnative_folder.yaml) |
| Process Execution via WMI | 🟡 medium | 50 | `T1047` | [`process_execution_via_wmi.yaml`](./process_execution_via_wmi.yaml) |
| Process Kill Base On File Path | 🟡 medium | 50 | `T1562.001` | [`process_kill_base_on_file_path.yaml`](./process_kill_base_on_file_path.yaml) |
| Process Launched Without Image Name | 🟡 medium | 50 | — | [`process_launched_without_image_name.yaml`](./process_launched_without_image_name.yaml) |
| Process Memory Dump Via Dotnet-Dump | 🟡 medium | 50 | `T1218` | [`process_memory_dump_via_dotnet_dump.yaml`](./process_memory_dump_via_dotnet_dump.yaml) |
| Process Proxy Execution Via Squirrel.EXE | 🟡 medium | 50 | `T1218` | [`process_proxy_execution_via_squirrel_exe.yaml`](./process_proxy_execution_via_squirrel_exe.yaml) |
| Program Executed Using Proxy/Local Command Via SSH.EXE | 🟡 medium | 50 | `T1218` | [`program_executed_using_proxy_local_command_via_ssh_exe.yaml`](./program_executed_using_proxy_local_command_via_ssh_exe.yaml) |
| Proxy Execution via Vshadow | 🟡 medium | 50 | `T1202` | [`proxy_execution_via_vshadow.yaml`](./proxy_execution_via_vshadow.yaml) |
| Psexec Execution | 🟡 medium | 50 | `T1569`, `T1021` | [`psexec_execution.yaml`](./psexec_execution.yaml) |
| PsExec Service Execution | 🟡 medium | 50 | — | [`psexec_service_execution.yaml`](./psexec_service_execution.yaml) |
| PUA - AdFind.EXE Execution | 🟡 medium | 50 | `T1087.002` | [`pua_adfind_exe_execution.yaml`](./pua_adfind_exe_execution.yaml) |
| PUA - Advanced IP Scanner Execution | 🟡 medium | 50 | `T1046`, `T1135` | [`pua_advanced_ip_scanner_execution.yaml`](./pua_advanced_ip_scanner_execution.yaml) |
| PUA - Advanced Port Scanner Execution | 🟡 medium | 50 | `T1046`, `T1135` | [`pua_advanced_port_scanner_execution.yaml`](./pua_advanced_port_scanner_execution.yaml) |
| PUA - AdvancedRun Execution | 🟡 medium | 50 | `T1564.003`, `T1134.002`, `T1059.003` | [`pua_advancedrun_execution.yaml`](./pua_advancedrun_execution.yaml) |
| PUA - Mouse Lock Execution | 🟡 medium | 50 | `T1056.002` | [`pua_mouse_lock_execution.yaml`](./pua_mouse_lock_execution.yaml) |
| PUA - NimScan Execution | 🟡 medium | 50 | `T1046` | [`pua_nimscan_execution.yaml`](./pua_nimscan_execution.yaml) |
| PUA - NirCmd Execution | 🟡 medium | 50 | `T1569.002` | [`pua_nircmd_execution.yaml`](./pua_nircmd_execution.yaml) |
| PUA - Nmap/Zenmap Execution | 🟡 medium | 50 | `T1046` | [`pua_nmap_zenmap_execution.yaml`](./pua_nmap_zenmap_execution.yaml) |
| PUA - Potential PE Metadata Tamper Using Rcedit | 🟡 medium | 50 | `T1036.003`, `T1036`, `T1027.005`… | [`pua_potential_pe_metadata_tamper_using_rcedit.yaml`](./pua_potential_pe_metadata_tamper_using_rcedit.yaml) |
| PUA - Process Hacker Execution | 🟡 medium | 50 | `T1622`, `T1564`, `T1543` | [`pua_process_hacker_execution.yaml`](./pua_process_hacker_execution.yaml) |
| PUA - Radmin Viewer Utility Execution | 🟡 medium | 50 | `T1072` | [`pua_radmin_viewer_utility_execution.yaml`](./pua_radmin_viewer_utility_execution.yaml) |
| PUA - SoftPerfect Netscan Execution | 🟡 medium | 50 | `T1046` | [`pua_softperfect_netscan_execution.yaml`](./pua_softperfect_netscan_execution.yaml) |
| PUA - System Informer Execution | 🟡 medium | 50 | `T1082`, `T1564`, `T1543` | [`pua_system_informer_execution.yaml`](./pua_system_informer_execution.yaml) |
| PUA - TruffleHog Execution | 🟡 medium | 50 | `T1083`, `T1552.001` | [`pua_trufflehog_execution.yaml`](./pua_trufflehog_execution.yaml) |
| PUA - WebBrowserPassView Execution | 🟡 medium | 50 | `T1555.003` | [`pua_webbrowserpassview_execution.yaml`](./pua_webbrowserpassview_execution.yaml) |
| Pubprn.vbs Proxy Execution | 🟡 medium | 50 | `T1216.001` | [`pubprn_vbs_proxy_execution.yaml`](./pubprn_vbs_proxy_execution.yaml) |
| Python Inline Command Execution | 🟡 medium | 50 | `T1059` | [`python_inline_command_execution.yaml`](./python_inline_command_execution.yaml) |
| Query Usage To Exfil Data | 🟡 medium | 50 | — | [`query_usage_to_exfil_data.yaml`](./query_usage_to_exfil_data.yaml) |
| RDP Enable or Disable via Win32_TerminalServiceSetting WMI Class | 🟡 medium | 50 | `T1021.001`, `T1047` | [`rdp_enable_or_disable_via_win32_terminalservicesetting_wmi_class.yaml`](./rdp_enable_or_disable_via_win32_terminalservicesetting_wmi_class.yaml) |
| Read Contents From Stdin Via Cmd.EXE | 🟡 medium | 50 | `T1059.003` | [`read_contents_from_stdin_via_cmd_exe.yaml`](./read_contents_from_stdin_via_cmd_exe.yaml) |
| Rebuild Performance Counter Values Via Lodctr.EXE | 🟡 medium | 50 | — | [`rebuild_performance_counter_values_via_lodctr_exe.yaml`](./rebuild_performance_counter_values_via_lodctr_exe.yaml) |
| Recon Command Output Piped To Findstr.EXE | 🟡 medium | 50 | `T1057` | [`recon_command_output_piped_to_findstr_exe.yaml`](./recon_command_output_piped_to_findstr_exe.yaml) |
| Recon Information for Export with Command Prompt | 🟡 medium | 50 | `T1119` | [`recon_information_for_export_with_command_prompt.yaml`](./recon_information_for_export_with_command_prompt.yaml) |
| Recursive Delete of Directory In Batch CMD | 🟡 medium | 50 | `T1070.004` | [`recursive_delete_of_directory_in_batch_cmd.yaml`](./recursive_delete_of_directory_in_batch_cmd.yaml) |
| Reg exe Manipulating Windows Services Registry Keys | 🟡 medium | 50 | `T1574.011` | [`reg_exe_manipulating_windows_services_registry_keys.yaml`](./reg_exe_manipulating_windows_services_registry_keys.yaml) |
| REGISTER_APP.VBS Proxy Execution | 🟡 medium | 50 | `T1218` | [`register_app_vbs_proxy_execution.yaml`](./register_app_vbs_proxy_execution.yaml) |
| Registry Enumeration via WMI Stdregprov | 🟡 medium | 50 | `T1047`, `T1012` | [`registry_enumeration_via_wmi_stdregprov.yaml`](./registry_enumeration_via_wmi_stdregprov.yaml) |
| Registry Manipulation via WMI Stdregprov | 🟡 medium | 50 | `T1047`, `T1112` | [`registry_manipulation_via_wmi_stdregprov.yaml`](./registry_manipulation_via_wmi_stdregprov.yaml) |
| Registry Modification Attempt Via VBScript | 🟡 medium | 50 | `T1112`, `T1059.005` | [`registry_modification_attempt_via_vbscript.yaml`](./registry_modification_attempt_via_vbscript.yaml) |
| Registry Modification of MS-settings Protocol Handler | 🟡 medium | 50 | `T1548.002`, `T1546.001`, `T1112` | [`registry_modification_of_ms_settings_protocol_handler.yaml`](./registry_modification_of_ms_settings_protocol_handler.yaml) |
| Regsvr32 DLL Execution With Uncommon Extension | 🟡 medium | 50 | `T1574` | [`regsvr32_dll_execution_with_uncommon_extension.yaml`](./regsvr32_dll_execution_with_uncommon_extension.yaml) |
| Regsvr32 Execution From Potential Suspicious Location | 🟡 medium | 50 | `T1218.010` | [`regsvr32_execution_from_potential_suspicious_location.yaml`](./regsvr32_execution_from_potential_suspicious_location.yaml) |
| Remote Access Tool - AnyDesk Execution | 🟡 medium | 50 | `T1219.002` | [`remote_access_tool_anydesk_execution.yaml`](./remote_access_tool_anydesk_execution.yaml) |
| Remote Access Tool - AnyDesk Execution With Known Revoked Signing Certificate | 🟡 medium | 50 | — | [`remote_access_tool_anydesk_execution_with_known_revoked_signing_certificate.yaml`](./remote_access_tool_anydesk_execution_with_known_revoked_signing_certificate.yaml) |
| Remote Access Tool - AnyDesk Piped Password Via CLI | 🟡 medium | 50 | `T1219.002` | [`remote_access_tool_anydesk_piped_password_via_cli.yaml`](./remote_access_tool_anydesk_piped_password_via_cli.yaml) |
| Remote Access Tool - GoToAssist Execution | 🟡 medium | 50 | `T1219.002` | [`remote_access_tool_gotoassist_execution.yaml`](./remote_access_tool_gotoassist_execution.yaml) |
| Remote Access Tool - LogMeIn Execution | 🟡 medium | 50 | `T1219.002` | [`remote_access_tool_logmein_execution.yaml`](./remote_access_tool_logmein_execution.yaml) |
| Remote Access Tool - MeshAgent Command Execution via MeshCentral | 🟡 medium | 50 | `T1219.002` | [`remote_access_tool_meshagent_command_execution_via_meshcentral.yaml`](./remote_access_tool_meshagent_command_execution_via_meshcentral.yaml) |
| Remote Access Tool - NetSupport Execution | 🟡 medium | 50 | `T1219.002` | [`remote_access_tool_netsupport_execution.yaml`](./remote_access_tool_netsupport_execution.yaml) |
| Remote Access Tool - NetSupport Execution From Unusual Location | 🟡 medium | 50 | — | [`remote_access_tool_netsupport_execution_from_unusual_location.yaml`](./remote_access_tool_netsupport_execution_from_unusual_location.yaml) |
| Remote Access Tool - Potential MeshAgent Execution - Windows | 🟡 medium | 50 | `T1219.002` | [`remote_access_tool_potential_meshagent_execution_windows.yaml`](./remote_access_tool_potential_meshagent_execution_windows.yaml) |
| Remote Access Tool - RURAT Execution From Unusual Location | 🟡 medium | 50 | — | [`remote_access_tool_rurat_execution_from_unusual_location.yaml`](./remote_access_tool_rurat_execution_from_unusual_location.yaml) |
| Remote Access Tool - ScreenConnect Execution | 🟡 medium | 50 | `T1219.002` | [`remote_access_tool_screenconnect_execution.yaml`](./remote_access_tool_screenconnect_execution.yaml) |
| Remote Access Tool - ScreenConnect Installation Execution | 🟡 medium | 50 | `T1133` | [`remote_access_tool_screenconnect_installation_execution.yaml`](./remote_access_tool_screenconnect_installation_execution.yaml) |
| Remote Access Tool - ScreenConnect Potential Suspicious Remote Command Execution | 🟡 medium | 50 | `T1219.002` | [`remote_access_tool_screenconnect_potential_suspicious_remote_command_execution.yaml`](./remote_access_tool_screenconnect_potential_suspicious_remote_command_execution.yaml) |
| Remote Access Tool - Simple Help Execution | 🟡 medium | 50 | `T1219.002` | [`remote_access_tool_simple_help_execution.yaml`](./remote_access_tool_simple_help_execution.yaml) |
| Remote Access Tool - TacticalRMM Agent Registration to Potentially Attacker-Controlled Server | 🟡 medium | 50 | `T1219`, `T1105` | [`remote_access_tool_tacticalrmm_agent_registration_to_potentially_attacker_controlled_server.yaml`](./remote_access_tool_tacticalrmm_agent_registration_to_potentially_attacker_controlled_server.yaml) |
| Remote Access Tool - UltraViewer Execution | 🟡 medium | 50 | `T1219.002` | [`remote_access_tool_ultraviewer_execution.yaml`](./remote_access_tool_ultraviewer_execution.yaml) |
| Remote Code Execute via Winrm.vbs | 🟡 medium | 50 | `T1216` | [`remote_code_execute_via_winrm_vbs.yaml`](./remote_code_execute_via_winrm_vbs.yaml) |
| Remote File Download Via Desktopimgdownldr Utility | 🟡 medium | 50 | `T1105` | [`remote_file_download_via_desktopimgdownldr_utility.yaml`](./remote_file_download_via_desktopimgdownldr_utility.yaml) |
| Remote File Download Via Findstr.EXE | 🟡 medium | 50 | `T1218`, `T1564.004`, `T1552.001`… | [`remote_file_download_via_findstr_exe.yaml`](./remote_file_download_via_findstr_exe.yaml) |
| Remote PowerShell Session Host Process (WinRM) | 🟡 medium | 50 | `T1059.001`, `T1021.006` | [`remote_powershell_session_host_process_winrm.yaml`](./remote_powershell_session_host_process_winrm.yaml) |
| Renamed AutoHotkey.EXE Execution | 🟡 medium | 50 | — | [`renamed_autohotkey_exe_execution.yaml`](./renamed_autohotkey_exe_execution.yaml) |
| Renamed BOINC Client Execution | 🟡 medium | 50 | `T1553` | [`renamed_boinc_client_execution.yaml`](./renamed_boinc_client_execution.yaml) |
| Renamed CURL.EXE Execution | 🟡 medium | 50 | `T1059`, `T1202` | [`renamed_curl_exe_execution.yaml`](./renamed_curl_exe_execution.yaml) |
| Renamed FTP.EXE Execution | 🟡 medium | 50 | `T1059`, `T1202` | [`renamed_ftp_exe_execution.yaml`](./renamed_ftp_exe_execution.yaml) |
| Renamed Microsoft Teams Execution | 🟡 medium | 50 | — | [`renamed_microsoft_teams_execution.yaml`](./renamed_microsoft_teams_execution.yaml) |
| Renamed Remote Utilities RAT (RURAT) Execution | 🟡 medium | 50 | — | [`renamed_remote_utilities_rat_rurat_execution.yaml`](./renamed_remote_utilities_rat_rurat_execution.yaml) |
| Replace.exe Usage | 🟡 medium | 50 | `T1105` | [`replace_exe_usage.yaml`](./replace_exe_usage.yaml) |
| Response File Execution Via Odbcconf.EXE | 🟡 medium | 50 | `T1218.008` | [`response_file_execution_via_odbcconf_exe.yaml`](./response_file_execution_via_odbcconf_exe.yaml) |
| Rhadamanthys Stealer Module Launch Via Rundll32.EXE | 🟡 medium | 50 | `T1218.011` | [`rhadamanthys_stealer_module_launch_via_rundll32_exe.yaml`](./rhadamanthys_stealer_module_launch_via_rundll32_exe.yaml) |
| Ruby Inline Command Execution | 🟡 medium | 50 | `T1059` | [`ruby_inline_command_execution.yaml`](./ruby_inline_command_execution.yaml) |
| Rundll32 Execution With Uncommon DLL Extension | 🟡 medium | 50 | `T1218.011` | [`rundll32_execution_with_uncommon_dll_extension.yaml`](./rundll32_execution_with_uncommon_dll_extension.yaml) |
| Rundll32 InstallScreenSaver Execution | 🟡 medium | 50 | `T1218.011` | [`rundll32_installscreensaver_execution.yaml`](./rundll32_installscreensaver_execution.yaml) |
| Rundll32 Spawned Via Explorer.EXE | 🟡 medium | 50 | — | [`rundll32_spawned_via_explorer_exe.yaml`](./rundll32_spawned_via_explorer_exe.yaml) |
| Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE | 🟡 medium | 50 | `T1053.005` | [`schedule_task_creation_from_env_variable_or_potentially_suspicious_path_via_schtasks_exe.yaml`](./schedule_task_creation_from_env_variable_or_potentially_suspicious_path_via_schtasks_exe.yaml) |
| Scheduled Task Creation with Curl and PowerShell Execution Combo | 🟡 medium | 50 | `T1053.005`, `T1218`, `T1105` | [`scheduled_task_creation_with_curl_and_powershell_execution_combo.yaml`](./scheduled_task_creation_with_curl_and_powershell_execution_combo.yaml) |
| Scheduled Task Executing Payload from Registry | 🟡 medium | 50 | `T1053.005`, `T1059.001` | [`scheduled_task_executing_payload_from_registry.yaml`](./scheduled_task_executing_payload_from_registry.yaml) |
| Screen Capture Activity Via Psr.EXE | 🟡 medium | 50 | `T1113` | [`screen_capture_activity_via_psr_exe.yaml`](./screen_capture_activity_via_psr_exe.yaml) |
| Scripting/CommandLine Process Spawned Regsvr32 | 🟡 medium | 50 | `T1218.010` | [`scripting_commandline_process_spawned_regsvr32.yaml`](./scripting_commandline_process_spawned_regsvr32.yaml) |
| Sdclt Child Processes | 🟡 medium | 50 | `T1548.002` | [`sdclt_child_processes.yaml`](./sdclt_child_processes.yaml) |
| Security Tools Keyword Lookup Via Findstr.EXE | 🟡 medium | 50 | `T1518.001` | [`security_tools_keyword_lookup_via_findstr_exe.yaml`](./security_tools_keyword_lookup_via_findstr_exe.yaml) |
| Service Reconnaissance Via Wmic.EXE | 🟡 medium | 50 | `T1047` | [`service_reconnaissance_via_wmic_exe.yaml`](./service_reconnaissance_via_wmic_exe.yaml) |
| Service Security Descriptor Tampering Via Sc.EXE | 🟡 medium | 50 | `T1574.011` | [`service_security_descriptor_tampering_via_sc_exe.yaml`](./service_security_descriptor_tampering_via_sc_exe.yaml) |
| Service Started/Stopped Via Wmic.EXE | 🟡 medium | 50 | `T1047` | [`service_started_stopped_via_wmic_exe.yaml`](./service_started_stopped_via_wmic_exe.yaml) |
| Service Startup Type Change Via Wmic.EXE | 🟡 medium | 50 | `T1047`, `T1685` | [`service_startup_type_change_via_wmic_exe.yaml`](./service_startup_type_change_via_wmic_exe.yaml) |
| Service StartupType Change Via PowerShell Set-Service | 🟡 medium | 50 | `T1685` | [`service_startuptype_change_via_powershell_set_service.yaml`](./service_startuptype_change_via_powershell_set_service.yaml) |
| Service StartupType Change Via Sc.EXE | 🟡 medium | 50 | `T1685` | [`service_startuptype_change_via_sc_exe.yaml`](./service_startuptype_change_via_sc_exe.yaml) |
| Setup16.EXE Execution With Custom .Lst File | 🟡 medium | 50 | `T1574.005` | [`setup16_exe_execution_with_custom_lst_file.yaml`](./setup16_exe_execution_with_custom_lst_file.yaml) |
| Shadow Copies Creation Using Operating Systems Utilities | 🟡 medium | 50 | `T1003`, `T1003.002`, `T1003.003` | [`shadow_copies_creation_using_operating_systems_utilities.yaml`](./shadow_copies_creation_using_operating_systems_utilities.yaml) |
| Shell Process Spawned by Java.EXE | 🟡 medium | 50 | — | [`shell_process_spawned_by_java_exe.yaml`](./shell_process_spawned_by_java_exe.yaml) |
| SQL Client Tools PowerShell Session Detection | 🟡 medium | 50 | `T1059.001`, `T1127` | [`sql_client_tools_powershell_session_detection.yaml`](./sql_client_tools_powershell_session_detection.yaml) |
| Start of NT Virtual DOS Machine | 🟡 medium | 50 | — | [`start_of_nt_virtual_dos_machine.yaml`](./start_of_nt_virtual_dos_machine.yaml) |
| Suspicious Cabinet File Execution Via Msdt.EXE | 🟡 medium | 50 | `T1202` | [`suspicious_cabinet_file_execution_via_msdt_exe.yaml`](./suspicious_cabinet_file_execution_via_msdt_exe.yaml) |
| Suspicious Child Process of SAP NetWeaver | 🟡 medium | 50 | `T1190`, `T1059.003` | [`suspicious_child_process_of_sap_netweaver.yaml`](./suspicious_child_process_of_sap_netweaver.yaml) |
| Suspicious CodePage Switch Via CHCP | 🟡 medium | 50 | `T1036` | [`suspicious_codepage_switch_via_chcp.yaml`](./suspicious_codepage_switch_via_chcp.yaml) |
| Suspicious CrushFTP Child Process | 🟡 medium | 50 | `T1059.001`, `T1059.003`, `T1190` | [`suspicious_crushftp_child_process.yaml`](./suspicious_crushftp_child_process.yaml) |
| Suspicious Csi.exe Usage | 🟡 medium | 50 | `T1072`, `T1218` | [`suspicious_csi_exe_usage.yaml`](./suspicious_csi_exe_usage.yaml) |
| Suspicious Diantz Alternate Data Stream Execution | 🟡 medium | 50 | `T1564.004` | [`suspicious_diantz_alternate_data_stream_execution.yaml`](./suspicious_diantz_alternate_data_stream_execution.yaml) |
| Suspicious Diantz Download and Compress Into a CAB File | 🟡 medium | 50 | `T1105` | [`suspicious_diantz_download_and_compress_into_a_cab_file.yaml`](./suspicious_diantz_download_and_compress_into_a_cab_file.yaml) |
| Suspicious Download Via Certutil.EXE | 🟡 medium | 50 | `T1027`, `T1105` | [`suspicious_download_via_certutil_exe.yaml`](./suspicious_download_via_certutil_exe.yaml) |
| Suspicious Driver Install by pnputil.exe | 🟡 medium | 50 | `T1547` | [`suspicious_driver_install_by_pnputil_exe.yaml`](./suspicious_driver_install_by_pnputil_exe.yaml) |
| Suspicious Electron Application Child Processes | 🟡 medium | 50 | — | [`suspicious_electron_application_child_processes.yaml`](./suspicious_electron_application_child_processes.yaml) |
| Suspicious Execution of InstallUtil Without Log | 🟡 medium | 50 | — | [`suspicious_execution_of_installutil_without_log.yaml`](./suspicious_execution_of_installutil_without_log.yaml) |
| Suspicious Execution of Powershell with Base64 | 🟡 medium | 50 | `T1059.001` | [`suspicious_execution_of_powershell_with_base64.yaml`](./suspicious_execution_of_powershell_with_base64.yaml) |
| Suspicious Execution of Shutdown | 🟡 medium | 50 | `T1529` | [`suspicious_execution_of_shutdown.yaml`](./suspicious_execution_of_shutdown.yaml) |
| Suspicious Execution of Shutdown to Log Out | 🟡 medium | 50 | `T1529` | [`suspicious_execution_of_shutdown_to_log_out.yaml`](./suspicious_execution_of_shutdown_to_log_out.yaml) |
| Suspicious Extrac32 Alternate Data Stream Execution | 🟡 medium | 50 | `T1564.004` | [`suspicious_extrac32_alternate_data_stream_execution.yaml`](./suspicious_extrac32_alternate_data_stream_execution.yaml) |
| Suspicious Extrac32 Execution | 🟡 medium | 50 | `T1105` | [`suspicious_extrac32_execution.yaml`](./suspicious_extrac32_execution.yaml) |
| Suspicious File Characteristics Due to Missing Fields | 🟡 medium | 50 | `T1059.006` | [`suspicious_file_characteristics_due_to_missing_fields.yaml`](./suspicious_file_characteristics_due_to_missing_fields.yaml) |
| Suspicious FromBase64String Usage On Gzip Archive - Process Creation | 🟡 medium | 50 | `T1132.001` | [`suspicious_frombase64string_usage_on_gzip_archive_process_creation.yaml`](./suspicious_frombase64string_usage_on_gzip_archive_process_creation.yaml) |
| Suspicious Git Clone | 🟡 medium | 50 | `T1593.003` | [`suspicious_git_clone.yaml`](./suspicious_git_clone.yaml) |
| Suspicious Group And Account Reconnaissance Activity Using Net.EXE | 🟡 medium | 50 | `T1087.001`, `T1087.002` | [`suspicious_group_and_account_reconnaissance_activity_using_net_exe.yaml`](./suspicious_group_and_account_reconnaissance_activity_using_net_exe.yaml) |
| Suspicious IIS URL GlobalRules Rewrite Via AppCmd | 🟡 medium | 50 | — | [`suspicious_iis_url_globalrules_rewrite_via_appcmd.yaml`](./suspicious_iis_url_globalrules_rewrite_via_appcmd.yaml) |
| Suspicious Invoke-WebRequest Execution With DirectIP | 🟡 medium | 50 | `T1105` | [`suspicious_invoke_webrequest_execution_with_directip.yaml`](./suspicious_invoke_webrequest_execution_with_directip.yaml) |
| Suspicious Msbuild Execution By Uncommon Parent Process | 🟡 medium | 50 | — | [`suspicious_msbuild_execution_by_uncommon_parent_process.yaml`](./suspicious_msbuild_execution_by_uncommon_parent_process.yaml) |
| Suspicious MsiExec Embedding Parent | 🟡 medium | 50 | `T1218.007` | [`suspicious_msiexec_embedding_parent.yaml`](./suspicious_msiexec_embedding_parent.yaml) |
| Suspicious Msiexec Execute Arbitrary DLL | 🟡 medium | 50 | `T1218.007` | [`suspicious_msiexec_execute_arbitrary_dll.yaml`](./suspicious_msiexec_execute_arbitrary_dll.yaml) |
| Suspicious Msiexec Quiet Install From Remote Location | 🟡 medium | 50 | `T1218.007` | [`suspicious_msiexec_quiet_install_from_remote_location.yaml`](./suspicious_msiexec_quiet_install_from_remote_location.yaml) |
| Suspicious Powercfg Execution To Change Lock Screen Timeout | 🟡 medium | 50 | — | [`suspicious_powercfg_execution_to_change_lock_screen_timeout.yaml`](./suspicious_powercfg_execution_to_change_lock_screen_timeout.yaml) |
| Suspicious PowerShell Invocation From Script Engines | 🟡 medium | 50 | `T1059.001` | [`suspicious_powershell_invocation_from_script_engines.yaml`](./suspicious_powershell_invocation_from_script_engines.yaml) |
| Suspicious PowerShell Invocations - Specific - ProcessCreation | 🟡 medium | 50 | — | [`suspicious_powershell_invocations_specific_processcreation.yaml`](./suspicious_powershell_invocations_specific_processcreation.yaml) |
| Suspicious Process Start Locations | 🟡 medium | 50 | `T1036` | [`suspicious_process_start_locations.yaml`](./suspicious_process_start_locations.yaml) |
| Suspicious RASdial Activity | 🟡 medium | 50 | `T1059` | [`suspicious_rasdial_activity.yaml`](./suspicious_rasdial_activity.yaml) |
| Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet | 🟡 medium | 50 | `T1087.001` | [`suspicious_reconnaissance_activity_using_get_localgroupmember_cmdlet.yaml`](./suspicious_reconnaissance_activity_using_get_localgroupmember_cmdlet.yaml) |
| Suspicious Recursive Takeown | 🟡 medium | 50 | `T1222.001` | [`suspicious_recursive_takeown.yaml`](./suspicious_recursive_takeown.yaml) |
| Suspicious RunAs-Like Flag Combination | 🟡 medium | 50 | — | [`suspicious_runas_like_flag_combination.yaml`](./suspicious_runas_like_flag_combination.yaml) |
| Suspicious Rundll32 Setupapi.dll Activity | 🟡 medium | 50 | `T1218.011` | [`suspicious_rundll32_setupapi_dll_activity.yaml`](./suspicious_rundll32_setupapi_dll_activity.yaml) |
| Suspicious Runscripthelper.exe | 🟡 medium | 50 | `T1059`, `T1202` | [`suspicious_runscripthelper_exe.yaml`](./suspicious_runscripthelper_exe.yaml) |
| Suspicious Scan Loop Network | 🟡 medium | 50 | `T1059`, `T1018` | [`suspicious_scan_loop_network.yaml`](./suspicious_scan_loop_network.yaml) |
| Suspicious Scheduled Task Creation via Masqueraded XML File | 🟡 medium | 50 | `T1036.005`, `T1053.005` | [`suspicious_scheduled_task_creation_via_masqueraded_xml_file.yaml`](./suspicious_scheduled_task_creation_via_masqueraded_xml_file.yaml) |
| Suspicious Scheduled Task Name As GUID | 🟡 medium | 50 | `T1053.005` | [`suspicious_scheduled_task_name_as_guid.yaml`](./suspicious_scheduled_task_name_as_guid.yaml) |
| Suspicious Schtasks Schedule Type With High Privileges | 🟡 medium | 50 | `T1053.005` | [`suspicious_schtasks_schedule_type_with_high_privileges.yaml`](./suspicious_schtasks_schedule_type_with_high_privileges.yaml) |
| Suspicious ScreenSave Change by Reg.exe | 🟡 medium | 50 | `T1546.002` | [`suspicious_screensave_change_by_reg_exe.yaml`](./suspicious_screensave_change_by_reg_exe.yaml) |
| Suspicious SysAidServer Child | 🟡 medium | 50 | `T1210` | [`suspicious_sysaidserver_child.yaml`](./suspicious_sysaidserver_child.yaml) |
| Suspicious SYSVOL Domain Group Policy Access | 🟡 medium | 50 | `T1552.006` | [`suspicious_sysvol_domain_group_policy_access.yaml`](./suspicious_sysvol_domain_group_policy_access.yaml) |
| Suspicious Usage Of Active Directory Diagnostic Tool (ntdsutil.exe) | 🟡 medium | 50 | `T1003.003` | [`suspicious_usage_of_active_directory_diagnostic_tool_ntdsutil_exe.yaml`](./suspicious_usage_of_active_directory_diagnostic_tool_ntdsutil_exe.yaml) |
| Suspicious Usage of For Loop with Recursive Directory Search in CMD | 🟡 medium | 50 | `T1059.003`, `T1027.010` | [`suspicious_usage_of_for_loop_with_recursive_directory_search_in_cmd.yaml`](./suspicious_usage_of_for_loop_with_recursive_directory_search_in_cmd.yaml) |
| Suspicious Use of PsLogList | 🟡 medium | 50 | `T1087`, `T1087.001`, `T1087.002` | [`suspicious_use_of_psloglist.yaml`](./suspicious_use_of_psloglist.yaml) |
| Suspicious Userinit Child Process | 🟡 medium | 50 | `T1055` | [`suspicious_userinit_child_process.yaml`](./suspicious_userinit_child_process.yaml) |
| Suspicious VBoxDrvInst.exe Parameters | 🟡 medium | 50 | `T1112` | [`suspicious_vboxdrvinst_exe_parameters.yaml`](./suspicious_vboxdrvinst_exe_parameters.yaml) |
| Suspicious Vsls-Agent Command With AgentExtensionPath Load | 🟡 medium | 50 | `T1218` | [`suspicious_vsls_agent_command_with_agentextensionpath_load.yaml`](./suspicious_vsls_agent_command_with_agentextensionpath_load.yaml) |
| Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE | 🟡 medium | 50 | `T1685` | [`suspicious_windows_defender_folder_exclusion_added_via_reg_exe.yaml`](./suspicious_windows_defender_folder_exclusion_added_via_reg_exe.yaml) |
| Suspicious WindowsTerminal Child Processes | 🟡 medium | 50 | — | [`suspicious_windowsterminal_child_processes.yaml`](./suspicious_windowsterminal_child_processes.yaml) |
| Suspicious Workstation Locking via Rundll32 | 🟡 medium | 50 | — | [`suspicious_workstation_locking_via_rundll32.yaml`](./suspicious_workstation_locking_via_rundll32.yaml) |
| Suspicious X509Enrollment - Process Creation | 🟡 medium | 50 | `T1553.004` | [`suspicious_x509enrollment_process_creation.yaml`](./suspicious_x509enrollment_process_creation.yaml) |
| Suspicious XOR Encoded PowerShell Command | 🟡 medium | 50 | `T1059.001`, `T1140`, `T1027` | [`suspicious_xor_encoded_powershell_command.yaml`](./suspicious_xor_encoded_powershell_command.yaml) |
| Suspicious ZipExec Execution | 🟡 medium | 50 | `T1218`, `T1202` | [`suspicious_zipexec_execution.yaml`](./suspicious_zipexec_execution.yaml) |
| SyncAppvPublishingServer Execute Arbitrary PowerShell Code | 🟡 medium | 50 | `T1218` | [`syncappvpublishingserver_execute_arbitrary_powershell_code.yaml`](./syncappvpublishingserver_execute_arbitrary_powershell_code.yaml) |
| SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code | 🟡 medium | 50 | `T1218`, `T1216` | [`syncappvpublishingserver_vbs_execute_arbitrary_powershell_code.yaml`](./syncappvpublishingserver_vbs_execute_arbitrary_powershell_code.yaml) |
| Sysinternals PsService Execution | 🟡 medium | 50 | `T1543.003` | [`sysinternals_psservice_execution.yaml`](./sysinternals_psservice_execution.yaml) |
| Sysinternals PsSuspend Execution | 🟡 medium | 50 | `T1543.003` | [`sysinternals_pssuspend_execution.yaml`](./sysinternals_pssuspend_execution.yaml) |
| Sysmon Configuration Update | 🟡 medium | 50 | `T1685` | [`sysmon_configuration_update.yaml`](./sysmon_configuration_update.yaml) |
| Sysprep on AppData Folder | 🟡 medium | 50 | `T1059` | [`sysprep_on_appdata_folder.yaml`](./sysprep_on_appdata_folder.yaml) |
| System Disk And Volume Reconnaissance Via Wmic.EXE | 🟡 medium | 50 | `T1047`, `T1082` | [`system_disk_and_volume_reconnaissance_via_wmic_exe.yaml`](./system_disk_and_volume_reconnaissance_via_wmic_exe.yaml) |
| System Language Discovery via Reg.Exe | 🟡 medium | 50 | `T1614.001` | [`system_language_discovery_via_reg_exe.yaml`](./system_language_discovery_via_reg_exe.yaml) |
| Tap Installer Execution | 🟡 medium | 50 | `T1048` | [`tap_installer_execution.yaml`](./tap_installer_execution.yaml) |
| UAC Bypass via Windows Firewall Snap-In Hijack | 🟡 medium | 50 | `T1548` | [`uac_bypass_via_windows_firewall_snap_in_hijack.yaml`](./uac_bypass_via_windows_firewall_snap_in_hijack.yaml) |
| Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE | 🟡 medium | 50 | `T1218` | [`uncommon_assistive_technology_applications_execution_via_atbroker_exe.yaml`](./uncommon_assistive_technology_applications_execution_via_atbroker_exe.yaml) |
| Uncommon AddinUtil.EXE CommandLine Execution | 🟡 medium | 50 | `T1218` | [`uncommon_addinutil_exe_commandline_execution.yaml`](./uncommon_addinutil_exe_commandline_execution.yaml) |
| Uncommon Child Process Of AddinUtil.EXE | 🟡 medium | 50 | `T1218` | [`uncommon_child_process_of_addinutil_exe.yaml`](./uncommon_child_process_of_addinutil_exe.yaml) |
| Uncommon Child Process Of Appvlp.EXE | 🟡 medium | 50 | `T1218` | [`uncommon_child_process_of_appvlp_exe.yaml`](./uncommon_child_process_of_appvlp_exe.yaml) |
| Uncommon Child Process Of BgInfo.EXE | 🟡 medium | 50 | `T1059.005`, `T1218`, `T1202` | [`uncommon_child_process_of_bginfo_exe.yaml`](./uncommon_child_process_of_bginfo_exe.yaml) |
| Uncommon Child Process Of Conhost.EXE | 🟡 medium | 50 | `T1202` | [`uncommon_child_process_of_conhost_exe.yaml`](./uncommon_child_process_of_conhost_exe.yaml) |
| Uncommon Child Process Of Defaultpack.EXE | 🟡 medium | 50 | `T1218` | [`uncommon_child_process_of_defaultpack_exe.yaml`](./uncommon_child_process_of_defaultpack_exe.yaml) |
| Uncommon Child Process Spawned By Odbcconf.EXE | 🟡 medium | 50 | `T1218.008` | [`uncommon_child_process_spawned_by_odbcconf_exe.yaml`](./uncommon_child_process_spawned_by_odbcconf_exe.yaml) |
| Uncommon Child Processes Of SndVol.exe | 🟡 medium | 50 | — | [`uncommon_child_processes_of_sndvol_exe.yaml`](./uncommon_child_processes_of_sndvol_exe.yaml) |
| Uncommon Extension Shim Database Installation Via Sdbinst.EXE | 🟡 medium | 50 | `T1546.011` | [`uncommon_extension_shim_database_installation_via_sdbinst_exe.yaml`](./uncommon_extension_shim_database_installation_via_sdbinst_exe.yaml) |
| Uncommon Link.EXE Parent Process | 🟡 medium | 50 | `T1218` | [`uncommon_link_exe_parent_process.yaml`](./uncommon_link_exe_parent_process.yaml) |
| Uncommon Sigverif.EXE Child Process | 🟡 medium | 50 | `T1216` | [`uncommon_sigverif_exe_child_process.yaml`](./uncommon_sigverif_exe_child_process.yaml) |
| Uncommon Svchost Parent Process | 🟡 medium | 50 | `T1036.005` | [`uncommon_svchost_parent_process.yaml`](./uncommon_svchost_parent_process.yaml) |
| Uncommon System Information Discovery Via Wmic.EXE | 🟡 medium | 50 | `T1082` | [`uncommon_system_information_discovery_via_wmic_exe.yaml`](./uncommon_system_information_discovery_via_wmic_exe.yaml) |
| Unsigned AppX Installation Attempt Using Add-AppxPackage | 🟡 medium | 50 | — | [`unsigned_appx_installation_attempt_using_add_appxpackage.yaml`](./unsigned_appx_installation_attempt_using_add_appxpackage.yaml) |
| Unusual Parent Process For Cmd.EXE | 🟡 medium | 50 | `T1059` | [`unusual_parent_process_for_cmd_exe.yaml`](./unusual_parent_process_for_cmd_exe.yaml) |
| Usage Of Web Request Commands And Cmdlets | 🟡 medium | 50 | `T1059.001` | [`usage_of_web_request_commands_and_cmdlets.yaml`](./usage_of_web_request_commands_and_cmdlets.yaml) |
| Use Icacls to Hide File to Everyone | 🟡 medium | 50 | `T1564.001` | [`use_icacls_to_hide_file_to_everyone.yaml`](./use_icacls_to_hide_file_to_everyone.yaml) |
| Use NTFS Short Name in Command Line | 🟡 medium | 50 | `T1564.004` | [`use_ntfs_short_name_in_command_line.yaml`](./use_ntfs_short_name_in_command_line.yaml) |
| Use NTFS Short Name in Image | 🟡 medium | 50 | `T1564.004` | [`use_ntfs_short_name_in_image.yaml`](./use_ntfs_short_name_in_image.yaml) |
| Use of FSharp Interpreters | 🟡 medium | 50 | `T1059` | [`use_of_fsharp_interpreters.yaml`](./use_of_fsharp_interpreters.yaml) |
| Use of OpenConsole | 🟡 medium | 50 | `T1059` | [`use_of_openconsole.yaml`](./use_of_openconsole.yaml) |
| Use of Pcalua For Execution | 🟡 medium | 50 | `T1059` | [`use_of_pcalua_for_execution.yaml`](./use_of_pcalua_for_execution.yaml) |
| Use of Remote.exe | 🟡 medium | 50 | `T1127` | [`use_of_remote_exe.yaml`](./use_of_remote_exe.yaml) |
| Use of Scriptrunner.exe | 🟡 medium | 50 | `T1218` | [`use_of_scriptrunner_exe.yaml`](./use_of_scriptrunner_exe.yaml) |
| Use Of The SFTP.EXE Binary As A LOLBIN | 🟡 medium | 50 | `T1218` | [`use_of_the_sftp_exe_binary_as_a_lolbin.yaml`](./use_of_the_sftp_exe_binary_as_a_lolbin.yaml) |
| Use of TTDInject.exe | 🟡 medium | 50 | `T1127` | [`use_of_ttdinject_exe.yaml`](./use_of_ttdinject_exe.yaml) |
| Use of UltraVNC Remote Access Software | 🟡 medium | 50 | `T1219.002` | [`use_of_ultravnc_remote_access_software.yaml`](./use_of_ultravnc_remote_access_software.yaml) |
| Use of VisualUiaVerifyNative.exe | 🟡 medium | 50 | `T1218` | [`use_of_visualuiaverifynative_exe.yaml`](./use_of_visualuiaverifynative_exe.yaml) |
| Use of VSIISExeLauncher.exe | 🟡 medium | 50 | `T1127` | [`use_of_vsiisexelauncher_exe.yaml`](./use_of_vsiisexelauncher_exe.yaml) |
| Use of Wfc.exe | 🟡 medium | 50 | `T1127` | [`use_of_wfc_exe.yaml`](./use_of_wfc_exe.yaml) |
| Use Short Name Path in Image | 🟡 medium | 50 | `T1564.004` | [`use_short_name_path_in_image.yaml`](./use_short_name_path_in_image.yaml) |
| User Added to Local Administrators Group | 🟡 medium | 50 | `T1098` | [`user_added_to_local_administrators_group.yaml`](./user_added_to_local_administrators_group.yaml) |
| User Discovery And Export Via Get-ADUser Cmdlet | 🟡 medium | 50 | `T1033` | [`user_discovery_and_export_via_get_aduser_cmdlet.yaml`](./user_discovery_and_export_via_get_aduser_cmdlet.yaml) |
| UtilityFunctions.ps1 Proxy Dll | 🟡 medium | 50 | `T1216` | [`utilityfunctions_ps1_proxy_dll.yaml`](./utilityfunctions_ps1_proxy_dll.yaml) |
| Veeam Backup Database Suspicious Query | 🟡 medium | 50 | `T1005` | [`veeam_backup_database_suspicious_query.yaml`](./veeam_backup_database_suspicious_query.yaml) |
| Verclsid.exe Runs COM Object | 🟡 medium | 50 | `T1218` | [`verclsid_exe_runs_com_object.yaml`](./verclsid_exe_runs_com_object.yaml) |
| Visual Studio Code Tunnel Execution | 🟡 medium | 50 | `T1071.001`, `T1219` | [`visual_studio_code_tunnel_execution.yaml`](./visual_studio_code_tunnel_execution.yaml) |
| Visual Studio Code Tunnel Service Installation | 🟡 medium | 50 | `T1071.001` | [`visual_studio_code_tunnel_service_installation.yaml`](./visual_studio_code_tunnel_service_installation.yaml) |
| Visual Studio Code Tunnel Shell Execution | 🟡 medium | 50 | `T1071.001` | [`visual_studio_code_tunnel_shell_execution.yaml`](./visual_studio_code_tunnel_shell_execution.yaml) |
| Visual Studio NodejsTools PressAnyKey Arbitrary Binary Execution | 🟡 medium | 50 | `T1218` | [`visual_studio_nodejstools_pressanykey_arbitrary_binary_execution.yaml`](./visual_studio_nodejstools_pressanykey_arbitrary_binary_execution.yaml) |
| Visual Studio NodejsTools PressAnyKey Renamed Execution | 🟡 medium | 50 | `T1218` | [`visual_studio_nodejstools_pressanykey_renamed_execution.yaml`](./visual_studio_nodejstools_pressanykey_renamed_execution.yaml) |
| Weak or Abused Passwords In CLI | 🟡 medium | 50 | — | [`weak_or_abused_passwords_in_cli.yaml`](./weak_or_abused_passwords_in_cli.yaml) |
| WebDav Client Execution Via Rundll32.EXE | 🟡 medium | 50 | `T1048.003` | [`webdav_client_execution_via_rundll32_exe.yaml`](./webdav_client_execution_via_rundll32_exe.yaml) |
| Whoami.EXE Execution Anomaly | 🟡 medium | 50 | `T1033` | [`whoami_exe_execution_anomaly.yaml`](./whoami_exe_execution_anomaly.yaml) |
| Whoami.EXE Execution With Output Option | 🟡 medium | 50 | `T1033` | [`whoami_exe_execution_with_output_option.yaml`](./whoami_exe_execution_with_output_option.yaml) |
| Windows Account Access Removal via Logoff Exec | 🟡 medium | 36 | `T1531`, `T1059.001` | [`windows_account_access_removal_via_logoff_exec.yaml`](./windows_account_access_removal_via_logoff_exec.yaml) |
| Windows AdFind Exe | 🟡 medium | 25 | `T1018` | [`windows_adfind_exe.yaml`](./windows_adfind_exe.yaml) |
| Windows Admin Share Mount Via Net.EXE | 🟡 medium | 50 | `T1021.002` | [`windows_admin_share_mount_via_net_exe.yaml`](./windows_admin_share_mount_via_net_exe.yaml) |
| Windows Archive Collected Data via Rar | 🟡 medium | 49 | `T1560.001` | [`windows_archive_collected_data_via_rar.yaml`](./windows_archive_collected_data_via_rar.yaml) |
| Windows Attempt To Stop Security Service | 🟡 medium | 20 | `T1562.001` | [`windows_attempt_to_stop_security_service.yaml`](./windows_attempt_to_stop_security_service.yaml) |
| Windows Audit Policy Cleared via Auditpol | 🟡 medium | 16 | `T1562.002` | [`windows_audit_policy_cleared_via_auditpol.yaml`](./windows_audit_policy_cleared_via_auditpol.yaml) |
| Windows Audit Policy Disabled via Legacy Auditpol | 🟡 medium | 25 | `T1562.002` | [`windows_audit_policy_disabled_via_legacy_auditpol.yaml`](./windows_audit_policy_disabled_via_legacy_auditpol.yaml) |
| Windows Audit Policy Excluded Category via Auditpol | 🟡 medium | 25 | `T1562.002` | [`windows_audit_policy_excluded_category_via_auditpol.yaml`](./windows_audit_policy_excluded_category_via_auditpol.yaml) |
| Windows Audit Policy Security Descriptor Tampering via Auditpol | 🟡 medium | 16 | `T1562.002` | [`windows_audit_policy_security_descriptor_tampering_via_auditpol.yaml`](./windows_audit_policy_security_descriptor_tampering_via_auditpol.yaml) |
| Windows Audit Policy Subcategory Disabled via Auditpol | 🟡 medium | 25 | `T1562.002` | [`windows_audit_policy_disabled_via_auditpol.yaml`](./windows_audit_policy_disabled_via_auditpol.yaml) |
| Windows AutoIt3 Execution | 🟡 medium | 50 | `T1059` | [`windows_autoit3_execution.yaml`](./windows_autoit3_execution.yaml) |
| Windows Backup Deleted Via Wbadmin.EXE | 🟡 medium | 50 | `T1490` | [`windows_backup_deleted_via_wbadmin_exe.yaml`](./windows_backup_deleted_via_wbadmin_exe.yaml) |
| Windows Binary Executed From WSL | 🟡 medium | 50 | `T1202` | [`windows_binary_executed_from_wsl.yaml`](./windows_binary_executed_from_wsl.yaml) |
| Windows BitLockerToGo Process Execution | 🟡 medium | 45 | `T1218` | [`windows_bitlockertogo_process_execution.yaml`](./windows_bitlockertogo_process_execution.yaml) |
| Windows Bypass UAC via Pkgmgr Tool | 🟡 medium | 9 | `T1548.002` | [`windows_bypass_uac_via_pkgmgr_tool.yaml`](./windows_bypass_uac_via_pkgmgr_tool.yaml) |
| Windows Cabinet File Extraction Via Expand | 🟡 medium | 50 | `T1105` | [`windows_cabinet_file_extraction_via_expand.yaml`](./windows_cabinet_file_extraction_via_expand.yaml) |
| Windows Cached Domain Credentials Reg Query | 🟡 medium | 36 | `T1003.005` | [`windows_cached_domain_credentials_reg_query.yaml`](./windows_cached_domain_credentials_reg_query.yaml) |
| Windows Chrome Enable Extension Loading via Command-Line | 🟡 medium | 30 | `T1185` | [`windows_chrome_enable_extension_loading_via_command_line.yaml`](./windows_chrome_enable_extension_loading_via_command_line.yaml) |
| Windows Chromium Browser with Custom User Data Directory | 🟡 medium | 40 | `T1497` | [`windows_chromium_browser_launched_with_small_window_size.yaml`](./windows_chromium_browser_launched_with_small_window_size.yaml) |
| Windows Chromium Browser with Custom User Data Directory | 🟡 medium | 40 | `T1497` | [`windows_chromium_browser_with_custom_user_data_directory.yaml`](./windows_chromium_browser_with_custom_user_data_directory.yaml) |
| Windows Cmdline Tool Execution From Non-Shell Process | 🟡 medium | 56 | `T1059.007` | [`windows_cmdline_tool_execution_from_non_shell_process.yaml`](./windows_cmdline_tool_execution_from_non_shell_process.yaml) |
| Windows Command and Scripting Interpreter Path Traversal | 🟡 medium | 36 | `T1059` | [`windows_command_and_scripting_interpreter_hunting_path_traversal.yaml`](./windows_command_and_scripting_interpreter_hunting_path_traversal.yaml) |
| Windows Create Local Administrator Account Via Net | 🟡 medium | 30 | `T1136.001` | [`windows_create_local_administrator_account_via_net.yaml`](./windows_create_local_administrator_account_via_net.yaml) |
| Windows Credential Manager Access via VaultCmd | 🟡 medium | 50 | `T1555.004` | [`windows_credential_manager_access_via_vaultcmd.yaml`](./windows_credential_manager_access_via_vaultcmd.yaml) |
| Windows Debugger Tool Execution | 🟡 medium | 36 | `T1036` | [`windows_debugger_tool_execution.yaml`](./windows_debugger_tool_execution.yaml) |
| Windows Default Domain GPO Modification via GPME | 🟡 medium | 50 | `T1484.001` | [`windows_default_domain_gpo_modification_via_gpme.yaml`](./windows_default_domain_gpo_modification_via_gpme.yaml) |
| Windows Default RDP File Unhidden | 🟡 medium | 50 | `T1021.001` | [`windows_default_rdp_file_unhidden.yaml`](./windows_default_rdp_file_unhidden.yaml) |
| Windows Disable Internet Explorer Addons | 🟡 medium | 50 | `T1176.001` | [`windows_disable_internet_explorer_addons.yaml`](./windows_disable_internet_explorer_addons.yaml) |
| Windows Disable or Modify Tools Via Taskkill | 🟡 medium | 36 | `T1562.001` | [`windows_disable_or_modify_tools_via_taskkill.yaml`](./windows_disable_or_modify_tools_via_taskkill.yaml) |
| Windows DiskShadow Proxy Execution | 🟡 medium | 56 | `T1218` | [`windows_diskshadow_proxy_execution.yaml`](./windows_diskshadow_proxy_execution.yaml) |
| Windows DNS Gather Network Info | 🟡 medium | 36 | `T1590.002` | [`windows_dns_gather_network_info.yaml`](./windows_dns_gather_network_info.yaml) |
| Windows Eventlog Cleared Via Wevtutil | 🟡 medium | 28 | `T1070.001` | [`windows_event_for_service_disabled.yaml`](./windows_event_for_service_disabled.yaml) |
| Windows EventLog Recon Activity Using Log Query Utilities | 🟡 medium | 36 | `T1654` | [`windows_eventlog_recon_activity_using_log_query_utilities.yaml`](./windows_eventlog_recon_activity_using_log_query_utilities.yaml) |
| Windows Excel ActiveMicrosoftApp Child Process | 🟡 medium | 10 | `T1021.003` | [`windows_excel_activemicrosoftapp_child_process.yaml`](./windows_excel_activemicrosoftapp_child_process.yaml) |
| Windows File and Directory Enable ReadOnly Permissions | 🟡 medium | 49 | `T1222.001` | [`windows_file_and_directory_enable_readonly_permissions.yaml`](./windows_file_and_directory_enable_readonly_permissions.yaml) |
| Windows File and Directory Permissions Enable Inheritance | 🟡 medium | 36 | `T1222.001` | [`windows_file_and_directory_permissions_enable_inheritance.yaml`](./windows_file_and_directory_permissions_enable_inheritance.yaml) |
| Windows File and Directory Permissions Remove Inheritance | 🟡 medium | 49 | `T1222.001` | [`windows_file_and_directory_permissions_remove_inheritance.yaml`](./windows_file_and_directory_permissions_remove_inheritance.yaml) |
| Windows File Collection Via Copy Utilities | 🟡 medium | 36 | `T1119` | [`windows_file_collection_via_copy_utilities.yaml`](./windows_file_collection_via_copy_utilities.yaml) |
| Windows File Download Via PowerShell | 🟡 medium | 56 | `T1059.001`, `T1105` | [`windows_file_download_via_powershell.yaml`](./windows_file_download_via_powershell.yaml) |
| Windows Files and Dirs Access Rights Modification Via Icacls | 🟡 medium | 49 | `T1222.001` | [`windows_findstr_gpp_discovery.yaml`](./windows_findstr_gpp_discovery.yaml) |
| Windows Files and Dirs Access Rights Modification Via Icacls | 🟡 medium | 49 | `T1222.001` | [`windows_gdrive_binary_activity.yaml`](./windows_gdrive_binary_activity.yaml) |
| Windows Firewall Disabled via PowerShell | 🟡 medium | 50 | `T1685` | [`windows_firewall_disabled_via_powershell.yaml`](./windows_firewall_disabled_via_powershell.yaml) |
| Windows Hotfix Updates Reconnaissance Via Wmic.EXE | 🟡 medium | 50 | `T1047` | [`windows_hotfix_updates_reconnaissance_via_wmic_exe.yaml`](./windows_hotfix_updates_reconnaissance_via_wmic_exe.yaml) |
| Windows Identify Protocol Handlers | 🟡 medium | 65 | `T1059`, `T1218` | [`windows_identify_protocol_handlers.yaml`](./windows_identify_protocol_handlers.yaml) |
| Windows Indirect Command Execution Via forfiles | 🟡 medium | 60 | `T1202` | [`windows_indirect_command_execution_via_forfiles.yaml`](./windows_indirect_command_execution_via_forfiles.yaml) |
| Windows Indirect Command Execution Via pcalua | 🟡 medium | 60 | `T1202` | [`windows_indirect_command_execution_via_pcalua.yaml`](./windows_indirect_command_execution_via_pcalua.yaml) |
| Windows Information Discovery Fsutil | 🟡 medium | 50 | `T1082` | [`windows_information_discovery_fsutil.yaml`](./windows_information_discovery_fsutil.yaml) |
| Windows InstallUtil in Non Standard Path | 🟡 medium | 49 | `T1036.003`, `T1218.004` | [`windows_installutil_in_non_standard_path.yaml`](./windows_installutil_in_non_standard_path.yaml) |
| Windows Kernel Debugger Execution | 🟡 medium | 50 | — | [`windows_kernel_debugger_execution.yaml`](./windows_kernel_debugger_execution.yaml) |
| Windows List ENV Variables Via SET From Uncommon Parent | 🟡 medium | 56 | `T1055` | [`windows_list_env_variables_via_set_command_from_uncommon_parent.yaml`](./windows_list_env_variables_via_set_command_from_uncommon_parent.yaml) |
| Windows Local LLM Framework Execution | 🟡 medium | 36 | `T1543` | [`windows_local_llm_framework_execution.yaml`](./windows_local_llm_framework_execution.yaml) |
| Windows Malicious PowerShell Process - Encoded Command | 🟡 medium | 40 | `T1027` | [`malicious_powershell_process_encoded_command_alt.yaml`](./malicious_powershell_process_encoded_command_alt.yaml) |
| Windows Malicious PowerShell Process - Execution Policy Bypass | 🟡 medium | 42 | `T1059.001` | [`malicious_powershell_process_execution_policy_bypass_alt.yaml`](./malicious_powershell_process_execution_policy_bypass_alt.yaml) |
| Windows Malicious PowerShell Process With Obfuscation Techniques | 🟡 medium | 42 | `T1059.001` | [`malicious_powershell_process_with_obfuscation_techniques.yaml`](./malicious_powershell_process_with_obfuscation_techniques.yaml) |
| Windows Modify ACL Permission To Files Or Folder | 🟡 medium | 32 | `T1222` | [`modify_acl_permission_to_files_or_folder.yaml`](./modify_acl_permission_to_files_or_folder.yaml) |
| Windows Modify Registry Regedit Silent Reg Import | 🟡 medium | 49 | `T1112` | [`windows_modify_registry_regedit_silent_reg_import.yaml`](./windows_modify_registry_regedit_silent_reg_import.yaml) |
| Windows New Deny Permission Set On Service SD Via Sc.EXE | 🟡 medium | 30 | `T1564` | [`windows_new_deny_permission_set_on_service_sd_via_sc_exe.yaml`](./windows_new_deny_permission_set_on_service_sd_via_sc_exe.yaml) |
| Windows New Service Security Descriptor Set Via Sc.EXE | 🟡 medium | 36 | `T1564` | [`windows_new_service_security_descriptor_set_via_sc_exe.yaml`](./windows_new_service_security_descriptor_set_via_sc_exe.yaml) |
| Windows Ngrok Reverse Proxy Usage | 🟡 medium | 50 | `T1572`, `T1090`, `T1102` | [`windows_ngrok_reverse_proxy_usage.yaml`](./windows_ngrok_reverse_proxy_usage.yaml) |
| Windows NirSoft Utilities | 🟡 medium | 40 | `T1588.002` | [`windows_nirsoft_utilities.yaml`](./windows_nirsoft_utilities.yaml) |
| Windows Odbcconf Load DLL | 🟡 medium | 42 | `T1218.008` | [`windows_odbcconf_load_dll.yaml`](./windows_odbcconf_load_dll.yaml) |
| Windows Odbcconf Load Response File | 🟡 medium | 42 | `T1218.008` | [`windows_odbcconf_load_response_file.yaml`](./windows_odbcconf_load_response_file.yaml) |
| Windows Office Product Spawned Child Process For Download | 🟡 medium | 35 | `T1566.001` | [`windows_office_product_spawned_child_process_for_download.yaml`](./windows_office_product_spawned_child_process_for_download.yaml) |
| Windows PowerShell Connect To Internet With Hidden Window | 🟡 medium | 42 | `T1059.001` | [`powershell_connect_to_internet_with_hidden_window_alt.yaml`](./powershell_connect_to_internet_with_hidden_window_alt.yaml) |
| Windows Recall Feature Enabled Via Reg.EXE | 🟡 medium | 50 | `T1113` | [`windows_recall_feature_enabled_via_reg_exe.yaml`](./windows_recall_feature_enabled_via_reg_exe.yaml) |
| Windows Recovery Environment Disabled Via Reagentc | 🟡 medium | 50 | `T1490` | [`windows_recovery_environment_disabled_via_reagentc.yaml`](./windows_recovery_environment_disabled_via_reagentc.yaml) |
| Windows Torrent Activity | 🟡 medium | 40 | `T1048` | [`windows_torrent_activity.yaml`](./windows_torrent_activity.yaml) |
| Windows WBAdmin File Recovery From Backup | 🟡 medium | 50 | `T1490`, `T1565.001` | [`windows_wbadmin_file_recovery_from_backup.yaml`](./windows_wbadmin_file_recovery_from_backup.yaml) |
| Winrar Compressing Dump Files | 🟡 medium | 50 | `T1560.001` | [`winrar_compressing_dump_files.yaml`](./winrar_compressing_dump_files.yaml) |
| WinRAR Execution in Non-Standard Folder | 🟡 medium | 50 | `T1560.001` | [`winrar_execution_in_non_standard_folder.yaml`](./winrar_execution_in_non_standard_folder.yaml) |
| Wlrmdr.EXE Uncommon Argument Or Child Process | 🟡 medium | 50 | `T1218` | [`wlrmdr_exe_uncommon_argument_or_child_process.yaml`](./wlrmdr_exe_uncommon_argument_or_child_process.yaml) |
| WMI Persistence - Script Event Consumer | 🟡 medium | 50 | `T1546.003` | [`wmi_persistence_script_event_consumer.yaml`](./wmi_persistence_script_event_consumer.yaml) |
| WMIC Remote Command Execution | 🟡 medium | 50 | `T1047` | [`wmic_remote_command_execution.yaml`](./wmic_remote_command_execution.yaml) |
| WmiPrvSE Spawned A Process | 🟡 medium | 50 | `T1047` | [`wmiprvse_spawned_a_process.yaml`](./wmiprvse_spawned_a_process.yaml) |
| Write Protect For Storage Disabled | 🟡 medium | 50 | `T1685` | [`write_protect_for_storage_disabled.yaml`](./write_protect_for_storage_disabled.yaml) |
| Writing Of Malicious Files To The Fonts Folder | 🟡 medium | 50 | `T1211`, `T1059` | [`writing_of_malicious_files_to_the_fonts_folder.yaml`](./writing_of_malicious_files_to_the_fonts_folder.yaml) |
| Wscript Shell Run In CommandLine | 🟡 medium | 50 | `T1059` | [`wscript_shell_run_in_commandline.yaml`](./wscript_shell_run_in_commandline.yaml) |
| WSL Child Process Anomaly | 🟡 medium | 50 | `T1218`, `T1202` | [`wsl_child_process_anomaly.yaml`](./wsl_child_process_anomaly.yaml) |
| XBAP Execution From Uncommon Locations Via PresentationHost.EXE | 🟡 medium | 50 | `T1218` | [`xbap_execution_from_uncommon_locations_via_presentationhost_exe.yaml`](./xbap_execution_from_uncommon_locations_via_presentationhost_exe.yaml) |
| XSL Script Execution Via WMIC.EXE | 🟡 medium | 50 | `T1047`, `T1220`, `T1059.005`… | [`xsl_script_execution_via_wmic_exe.yaml`](./xsl_script_execution_via_wmic_exe.yaml) |
| Hunting 3CXDesktopApp Software | 🔵 low | 30 | `T1195.002` | [`hunting_3cxdesktopapp_software.yaml`](./hunting_3cxdesktopapp_software.yaml) |
| Malicious PowerShell Process - Execution Policy Bypass | 🔵 low | 30 | `T1059.001` | [`malicious_powershell_process_execution_policy_bypass.yaml`](./malicious_powershell_process_execution_policy_bypass.yaml) |
| Network Discovery Using Route Windows App | 🔵 low | 30 | `T1016.001` | [`network_discovery_using_route_windows_app.yaml`](./network_discovery_using_route_windows_app.yaml) |
| Permission Modification using Takeown App | 🔵 low | 30 | `T1222` | [`permission_modification_using_takeown_app.yaml`](./permission_modification_using_takeown_app.yaml) |
| Ping Sleep Batch Command | 🔵 low | 30 | `T1497.003` | [`ping_sleep_batch_command.yaml`](./ping_sleep_batch_command.yaml) |
| Potential Telegram API Request Via CommandLine | 🔵 low | 30 | `T1102.002`, `T1041` | [`potential_telegram_api_request_via_commandline.yaml`](./potential_telegram_api_request_via_commandline.yaml) |
| PowerShell - Connect To Internet With Hidden Window | 🔵 low | 30 | `T1059.001` | [`powershell_connect_to_internet_with_hidden_window.yaml`](./powershell_connect_to_internet_with_hidden_window.yaml) |
| PowerShell Get LocalGroup Discovery | 🔵 low | 30 | `T1069.001` | [`powershell_get_localgroup_discovery.yaml`](./powershell_get_localgroup_discovery.yaml) |
| PowerShell Get LocalGroup Discovery | 🔵 low | 30 | `T1069.001` | [`powershell_get_localgroup_discovery_alt.yaml`](./powershell_get_localgroup_discovery_alt.yaml) |
| Regsvr32 Silent and Install Param Dll Loading | 🔵 low | 30 | `T1218.010` | [`regsvr32_silent_and_install_param_dll_loading.yaml`](./regsvr32_silent_and_install_param_dll_loading.yaml) |
| Regsvr32 with Known Silent Switch Cmdline | 🔵 low | 30 | `T1218.010` | [`regsvr32_with_known_silent_switch_cmdline.yaml`](./regsvr32_with_known_silent_switch_cmdline.yaml) |
| Windows Audit Policy Restored via Auditpol | 🔵 low | 16 | `T1562.002` | [`windows_audit_policy_restored_via_auditpol.yaml`](./windows_audit_policy_restored_via_auditpol.yaml) |
| Windows Browser Process Launched with Unusual Flags | 🔵 low | 15 | `T1185` | [`windows_browser_process_launched_with_unusual_flags.yaml`](./windows_browser_process_launched_with_unusual_flags.yaml) |
| Windows Explorer Spawning PowerShell or Cmd | 🔵 low | 25 | `T1059.001`, `T1204.002` | [`windows_explorer_exe_spawning_powershell_or_cmd.yaml`](./windows_explorer_exe_spawning_powershell_or_cmd.yaml) |
| Windows Group Discovery Via Net | 🔵 low | 25 | `T1069.001`, `T1069.002` | [`windows_group_discovery_via_net.yaml`](./windows_group_discovery_via_net.yaml) |
| Windows Indicator Removal Via Rmdir | 🔵 low | 25 | `T1070` | [`windows_indicator_removal_via_rmdir.yaml`](./windows_indicator_removal_via_rmdir.yaml) |
| Windows Net System Service Discovery | 🔵 low | 3 | `T1007` | [`windows_net_system_service_discovery.yaml`](./windows_net_system_service_discovery.yaml) |
| Windows Network Connection Discovery Via Net | 🔵 low | 15 | `T1049` | [`windows_network_connection_discovery_via_net.yaml`](./windows_network_connection_discovery_via_net.yaml) |
| Windows Network Connection Discovery With Arp | 🔵 low | 25 | `T1049` | [`network_connection_discovery_with_arp.yaml`](./network_connection_discovery_with_arp.yaml) |
| Windows Network Share Interaction Via Net | 🔵 low | 20 | `T1135`, `T1039` | [`windows_network_share_interaction_via_net.yaml`](./windows_network_share_interaction_via_net.yaml) |
| Windows Odbcconf Hunting | 🔵 low | 20 | `T1218.008` | [`windows_odbcconf_hunting.yaml`](./windows_odbcconf_hunting.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
