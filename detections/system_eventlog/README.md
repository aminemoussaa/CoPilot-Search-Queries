# system eventlog

Windows **System** channel — Service Control Manager, Kerberos KDC, NetLogon, LSA and driver providers.

**67 rules** — critical 6, high 35, medium 26

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| CobaltStrike Service Installations - System | critical | T1021.002, T1543.003, T1569.002 | [cobaltstrike_service_installations_system.yaml](./cobaltstrike_service_installations_system.yaml) |
| Goofy Guineapig Backdoor Service Creation | critical | — | [goofy_guineapig_backdoor_service_creation.yaml](./goofy_guineapig_backdoor_service_creation.yaml) |
| Moriya Rootkit - System | critical | T1543.003 | [moriya_rootkit_system.yaml](./moriya_rootkit_system.yaml) |
| OilRig APT Schedule Task Persistence - System | critical | T1053.005, T1543.003, T1112, T1071.004 | [oilrig_apt_schedule_task_persistence_system.yaml](./oilrig_apt_schedule_task_persistence_system.yaml) |
| SNAKE Malware Service Persistence | critical | — | [snake_malware_service_persistence.yaml](./snake_malware_service_persistence.yaml) |
| Turla PNG Dropper Service | critical | T1543.003 | [turla_png_dropper_service.yaml](./turla_png_dropper_service.yaml) |
| COLDSTEEL Persistence Service Creation | high | — | [coldsteel_persistence_service_creation.yaml](./coldsteel_persistence_service_creation.yaml) |
| Credential Dumping Tools Service Execution - System | high | T1003.001, T1003.002, T1003.004, T1003.005… | [credential_dumping_tools_service_execution_system.yaml](./credential_dumping_tools_service_execution_system.yaml) |
| Critical Hive In Suspicious Location Access Bits Cleared | high | T1003.002 | [critical_hive_in_suspicious_location_access_bits_cleared.yaml](./critical_hive_in_suspicious_location_access_bits_cleared.yaml) |
| DHCP Server Error Failed Loading the CallOut DLL | high | T1574.001 | [dhcp_server_error_failed_loading_the_callout_dll.yaml](./dhcp_server_error_failed_loading_the_callout_dll.yaml) |
| DHCP Server Loaded the CallOut DLL | high | T1574.001 | [dhcp_server_loaded_the_callout_dll.yaml](./dhcp_server_loaded_the_callout_dll.yaml) |
| HackTool Service Registration or Execution | high | T1569.002 | [hacktool_service_registration_or_execution.yaml](./hacktool_service_registration_or_execution.yaml) |
| Important Windows Eventlog Cleared | high | T1685.005 | [important_windows_eventlog_cleared.yaml](./important_windows_eventlog_cleared.yaml) |
| Important Windows Service Terminated Unexpectedly | high | — | [important_windows_service_terminated_unexpectedly.yaml](./important_windows_service_terminated_unexpectedly.yaml) |
| Important Windows Service Terminated With Error | high | — | [important_windows_service_terminated_with_error.yaml](./important_windows_service_terminated_with_error.yaml) |
| Invoke-Obfuscation CLIP+ Launcher - System | high | T1027, T1059.001 | [invoke_obfuscation_clip_launcher_system.yaml](./invoke_obfuscation_clip_launcher_system.yaml) |
| Invoke-Obfuscation Obfuscated IEX Invocation - System | high | T1027 | [invoke_obfuscation_obfuscated_iex_invocation_system.yaml](./invoke_obfuscation_obfuscated_iex_invocation_system.yaml) |
| Invoke-Obfuscation STDIN+ Launcher - System | high | T1027, T1059.001 | [invoke_obfuscation_stdin_launcher_system.yaml](./invoke_obfuscation_stdin_launcher_system.yaml) |
| Invoke-Obfuscation VAR+ Launcher - System | high | T1027, T1059.001 | [invoke_obfuscation_var_launcher_system.yaml](./invoke_obfuscation_var_launcher_system.yaml) |
| Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - System | high | T1027, T1059.001 | [invoke_obfuscation_var_launcher_obfuscation_system.yaml](./invoke_obfuscation_var_launcher_obfuscation_system.yaml) |
| Invoke-Obfuscation Via Stdin - System | high | T1027, T1059.001 | [invoke_obfuscation_via_stdin_system.yaml](./invoke_obfuscation_via_stdin_system.yaml) |
| Invoke-Obfuscation Via Use Clip - System | high | T1027, T1059.001 | [invoke_obfuscation_via_use_clip_system.yaml](./invoke_obfuscation_via_use_clip_system.yaml) |
| Invoke-Obfuscation Via Use MSHTA - System | high | T1027, T1059.001 | [invoke_obfuscation_via_use_mshta_system.yaml](./invoke_obfuscation_via_use_mshta_system.yaml) |
| Invoke-Obfuscation Via Use Rundll32 - System | high | T1027, T1059.001 | [invoke_obfuscation_via_use_rundll32_system.yaml](./invoke_obfuscation_via_use_rundll32_system.yaml) |
| KrbRelayUp Service Installation | high | T1543 | [krbrelayup_service_installation.yaml](./krbrelayup_service_installation.yaml) |
| Local Privilege Escalation Indicator TabTip | high | T1557.001 | [local_privilege_escalation_indicator_tabtip.yaml](./local_privilege_escalation_indicator_tabtip.yaml) |
| Meterpreter or Cobalt Strike Getsystem Service Installation - System | high | T1134.001, T1134.002 | [meterpreter_or_cobalt_strike_getsystem_service_installation_system.yaml](./meterpreter_or_cobalt_strike_getsystem_service_installation_system.yaml) |
| NTFS Vulnerability Exploitation | high | T1499.001 | [ntfs_vulnerability_exploitation.yaml](./ntfs_vulnerability_exploitation.yaml) |
| Potential KDC RC4-HMAC Downgrade Exploit - CVE-2022-37966 | high | — | [potential_kdc_rc4_hmac_downgrade_exploit_cve_2022_37966.yaml](./potential_kdc_rc4_hmac_downgrade_exploit_cve_2022_37966.yaml) |
| PowerShell Scripts Installed as Services | high | T1569.002 | [powershell_scripts_installed_as_services.yaml](./powershell_scripts_installed_as_services.yaml) |
| ProcessHacker Privilege Elevation | high | T1543.003, T1569.002 | [processhacker_privilege_elevation.yaml](./processhacker_privilege_elevation.yaml) |
| RTCore Suspicious Service Installation | high | — | [rtcore_suspicious_service_installation.yaml](./rtcore_suspicious_service_installation.yaml) |
| Service Installation with Suspicious Folder Pattern | high | T1543.003 | [service_installation_with_suspicious_folder_pattern.yaml](./service_installation_with_suspicious_folder_pattern.yaml) |
| Service Installed By Unusual Client - System | high | T1543 | [service_installed_by_unusual_client_system.yaml](./service_installed_by_unusual_client_system.yaml) |
| smbexec.py Service Installation | high | T1021.002, T1569.002 | [smbexec_py_service_installation.yaml](./smbexec_py_service_installation.yaml) |
| StoneDrill Service Install | high | T1543.003 | [stonedrill_service_install.yaml](./stonedrill_service_install.yaml) |
| Suspicious Service Installation | high | T1543.003 | [suspicious_service_installation.yaml](./suspicious_service_installation.yaml) |
| Suspicious Service Installation Script | high | T1543.003 | [suspicious_service_installation_script.yaml](./suspicious_service_installation_script.yaml) |
| Sysmon Application Crashed | high | T1685 | [sysmon_application_crashed.yaml](./sysmon_application_crashed.yaml) |
| Turla Service Install | high | T1543.003 | [turla_service_install.yaml](./turla_service_install.yaml) |
| Vulnerable Netlogon Secure Channel Connection Allowed | high | T1548 | [vulnerable_netlogon_secure_channel_connection_allowed.yaml](./vulnerable_netlogon_secure_channel_connection_allowed.yaml) |
| Anydesk Remote Access Software Service Installation | medium | — | [anydesk_remote_access_software_service_installation.yaml](./anydesk_remote_access_software_service_installation.yaml) |
| Certificate Use With No Strong Mapping | medium | — | [certificate_use_with_no_strong_mapping.yaml](./certificate_use_with_no_strong_mapping.yaml) |
| Crash Dump Created By Operating System | medium | T1003.002, T1005 | [crash_dump_created_by_operating_system.yaml](./crash_dump_created_by_operating_system.yaml) |
| CSExec Service Installation | medium | T1569.002 | [csexec_service_installation.yaml](./csexec_service_installation.yaml) |
| Eventlog Cleared | medium | T1685.005 | [eventlog_cleared.yaml](./eventlog_cleared.yaml) |
| Invoke-Obfuscation COMPRESS OBFUSCATION - System | medium | T1027, T1059.001 | [invoke_obfuscation_compress_obfuscation_system.yaml](./invoke_obfuscation_compress_obfuscation_system.yaml) |
| Invoke-Obfuscation RUNDLL LAUNCHER - System | medium | T1027, T1059.001 | [invoke_obfuscation_rundll_launcher_system.yaml](./invoke_obfuscation_rundll_launcher_system.yaml) |
| ISATAP Router Address Was Set | medium | T1557, T1565.002 | [isatap_router_address_was_set.yaml](./isatap_router_address_was_set.yaml) |
| Mesh Agent Service Installation | medium | T1219.002 | [mesh_agent_service_installation.yaml](./mesh_agent_service_installation.yaml) |
| NetSupport Manager Service Install | medium | — | [netsupport_manager_service_install.yaml](./netsupport_manager_service_install.yaml) |
| New PDQDeploy Service - Client Side | medium | T1543.003 | [new_pdqdeploy_service_client_side.yaml](./new_pdqdeploy_service_client_side.yaml) |
| New PDQDeploy Service - Server Side | medium | T1543.003 | [new_pdqdeploy_service_server_side.yaml](./new_pdqdeploy_service_server_side.yaml) |
| NTLMv1 Logon Between Client and Server | medium | T1550.002 | [ntlmv1_logon_between_client_and_server.yaml](./ntlmv1_logon_between_client_and_server.yaml) |
| PAExec Service Installation | medium | T1569.002 | [paexec_service_installation.yaml](./paexec_service_installation.yaml) |
| Potential CVE-2021-42278 Exploitation Attempt | medium | T1558.003 | [potential_cve_2021_42278_exploitation_attempt.yaml](./potential_cve_2021_42278_exploitation_attempt.yaml) |
| Potential CVE-2021-42287 Exploitation Attempt | medium | T1558.003 | [potential_cve_2021_42287_exploitation_attempt.yaml](./potential_cve_2021_42287_exploitation_attempt.yaml) |
| Potential RDP Exploit CVE-2019-0708 | medium | T1210 | [potential_rdp_exploit_cve_2019_0708.yaml](./potential_rdp_exploit_cve_2019_0708.yaml) |
| PsExec Service Installation | medium | T1569.002 | [psexec_service_installation.yaml](./psexec_service_installation.yaml) |
| RemCom Service Installation | medium | T1569.002 | [remcom_service_installation.yaml](./remcom_service_installation.yaml) |
| Remote Access Tool Services Have Been Installed - System | medium | T1543.003, T1569.002 | [remote_access_tool_services_have_been_installed_system.yaml](./remote_access_tool_services_have_been_installed_system.yaml) |
| Remote Utilities Host Service Install | medium | — | [remote_utilities_host_service_install.yaml](./remote_utilities_host_service_install.yaml) |
| Service Installation in Suspicious Folder | medium | T1543.003 | [service_installation_in_suspicious_folder.yaml](./service_installation_in_suspicious_folder.yaml) |
| TacticalRMM Service Installation | medium | T1219.002 | [tacticalrmm_service_installation.yaml](./tacticalrmm_service_installation.yaml) |
| Tap Driver Installation | medium | T1048 | [tap_driver_installation.yaml](./tap_driver_installation.yaml) |
| Uncommon Service Installation Image Path | medium | T1543.003 | [uncommon_service_installation_image_path.yaml](./uncommon_service_installation_image_path.yaml) |
| Windows Defender Threat Detection Service Disabled | medium | T1685 | [windows_defender_threat_detection_service_disabled.yaml](./windows_defender_threat_detection_service_disabled.yaml) |
