# eid 4104 script block logging

PowerShell **Operational** channel, Event ID 4104 — script block logging.

**250 rules** — critical 6, high 76, medium 148, low 20

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| Delete ShadowCopy With PowerShell | critical | T1490 | [delete_shadowcopy_with_powershell.yaml](./delete_shadowcopy_with_powershell.yaml) |
| MailSniper Invoke Functions | critical | T1114.001 | [mailsniper_invoke_functions.yaml](./mailsniper_invoke_functions.yaml) |
| Powershell Remove Windows Defender Directory | critical | T1562.001 | [powershell_remove_windows_defender_directory.yaml](./powershell_remove_windows_defender_directory.yaml) |
| PowerShell WebRequest Using Memory Stream | critical | T1059.001, T1105, T1027.011 | [powershell_webrequest_using_memory_stream.yaml](./powershell_webrequest_using_memory_stream.yaml) |
| Silence.EDA Detection | critical | T1059.001, T1071.004, T1572, T1529 | [silence_eda_detection.yaml](./silence_eda_detection.yaml) |
| Suspicious PowerShell Mailbox Export to Share - PS | critical | — | [suspicious_powershell_mailbox_export_to_share_ps.yaml](./suspicious_powershell_mailbox_export_to_share_ps.yaml) |
| AADInternals PowerShell Cmdlets Execution - PsScript | high | — | [aadinternals_powershell_cmdlets_execution_psscript.yaml](./aadinternals_powershell_cmdlets_execution_psscript.yaml) |
| Abuse of Service Permissions to Hide Services Via Set-Service - PS | high | T1574.011 | [abuse_of_service_permissions_to_hide_services_via_set_service_ps.yaml](./abuse_of_service_permissions_to_hide_services_via_set_service_ps.yaml) |
| AMSI Bypass Pattern Assembly GetType | high | T1685 | [amsi_bypass_pattern_assembly_gettype.yaml](./amsi_bypass_pattern_assembly_gettype.yaml) |
| Clearing Windows Console History | high | T1070, T1070.003 | [clearing_windows_console_history.yaml](./clearing_windows_console_history.yaml) |
| Code Executed Via Office Add-in XLL File | high | T1137.006 | [code_executed_via_office_add_in_xll_file.yaml](./code_executed_via_office_add_in_xll_file.yaml) |
| Create Volume Shadow Copy with Powershell | high | T1003.003 | [create_volume_shadow_copy_with_powershell.yaml](./create_volume_shadow_copy_with_powershell.yaml) |
| Deletion of Volume Shadow Copies via WMI with PowerShell - PS Script | high | T1490 | [deletion_of_volume_shadow_copies_via_wmi_with_powershell_ps_script.yaml](./deletion_of_volume_shadow_copies_via_wmi_with_powershell_ps_script.yaml) |
| Detect Certify With PowerShell Script Block Logging | high | T1059.001, T1649 | [detect_certify_with_powershell_script_block_logging.yaml](./detect_certify_with_powershell_script_block_logging.yaml) |
| Detect Copy of ShadowCopy with Script Block Logging | high | T1003.002 | [detect_copy_of_shadowcopy_with_script_block_logging.yaml](./detect_copy_of_shadowcopy_with_script_block_logging.yaml) |
| Detect Empire with PowerShell Script Block Logging | high | T1059.001 | [detect_empire_with_powershell_script_block_logging.yaml](./detect_empire_with_powershell_script_block_logging.yaml) |
| Detect Mimikatz With PowerShell Script Block Logging | high | T1003, T1059.001 | [detect_mimikatz_with_powershell_script_block_logging.yaml](./detect_mimikatz_with_powershell_script_block_logging.yaml) |
| Disable of ETW Trace - Powershell | high | T1070, T1685 | [disable_of_etw_trace_powershell.yaml](./disable_of_etw_trace_powershell.yaml) |
| Disable Powershell Command History | high | T1070.003 | [disable_powershell_command_history.yaml](./disable_powershell_command_history.yaml) |
| Disable-WindowsOptionalFeature Command PowerShell | high | T1685 | [disable_windowsoptionalfeature_command_powershell.yaml](./disable_windowsoptionalfeature_command_powershell.yaml) |
| DSInternals Suspicious PowerShell Cmdlets - ScriptBlock | high | T1059.001 | [dsinternals_suspicious_powershell_cmdlets_scriptblock.yaml](./dsinternals_suspicious_powershell_cmdlets_scriptblock.yaml) |
| Exchange PowerShell Module Usage | high | T1059.001 | [exchange_powershell_module_usage.yaml](./exchange_powershell_module_usage.yaml) |
| HackTool - Rubeus Execution - ScriptBlock | high | T1003, T1558.003, T1550.003 | [hacktool_rubeus_execution_scriptblock.yaml](./hacktool_rubeus_execution_scriptblock.yaml) |
| HackTool - WinPwn Execution - ScriptBlock | high | T1046, T1082, T1106, T1518… | [hacktool_winpwn_execution_scriptblock.yaml](./hacktool_winpwn_execution_scriptblock.yaml) |
| Interactive Session on Remote Endpoint with PowerShell | high | T1021.006 | [interactive_session_on_remote_endpoint_with_powershell.yaml](./interactive_session_on_remote_endpoint_with_powershell.yaml) |
| Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell | high | T1027, T1059.001 | [invoke_obfuscation_obfuscated_iex_invocation_powershell.yaml](./invoke_obfuscation_obfuscated_iex_invocation_powershell.yaml) |
| Invoke-Obfuscation Via Use MSHTA - PowerShell | high | T1027, T1059.001 | [invoke_obfuscation_via_use_mshta_powershell.yaml](./invoke_obfuscation_via_use_mshta_powershell.yaml) |
| Invoke-Obfuscation Via Use Rundll32 - PowerShell | high | T1027, T1059.001 | [invoke_obfuscation_via_use_rundll32_powershell.yaml](./invoke_obfuscation_via_use_rundll32_powershell.yaml) |
| Kerberos Pre-Authentication Flag Disabled with PowerShell | high | T1558.004 | [kerberos_pre_authentication_flag_disabled_with_powershell.yaml](./kerberos_pre_authentication_flag_disabled_with_powershell.yaml) |
| Lace Tempest PowerShell Evidence Eraser | high | T1059.001 | [lace_tempest_powershell_evidence_eraser.yaml](./lace_tempest_powershell_evidence_eraser.yaml) |
| Lace Tempest PowerShell Launcher | high | T1059.001 | [lace_tempest_powershell_launcher.yaml](./lace_tempest_powershell_launcher.yaml) |
| Live Memory Dump Using Powershell | high | T1003 | [live_memory_dump_using_powershell.yaml](./live_memory_dump_using_powershell.yaml) |
| Malicious Nishang PowerShell Commandlets | high | T1059.001 | [malicious_nishang_powershell_commandlets.yaml](./malicious_nishang_powershell_commandlets.yaml) |
| Malicious ShellIntel PowerShell Commandlets | high | T1059.001 | [malicious_shellintel_powershell_commandlets.yaml](./malicious_shellintel_powershell_commandlets.yaml) |
| NTFS Alternate Data Stream | high | T1564.004, T1059.001 | [ntfs_alternate_data_stream.yaml](./ntfs_alternate_data_stream.yaml) |
| Potential APT FIN7 POWERHOLD Execution | high | T1059.001 | [potential_apt_fin7_powerhold_execution.yaml](./potential_apt_fin7_powerhold_execution.yaml) |
| Potential Invoke-Mimikatz PowerShell Script | high | T1003 | [potential_invoke_mimikatz_powershell_script.yaml](./potential_invoke_mimikatz_powershell_script.yaml) |
| Potential Persistence Via Security Descriptors - ScriptBlock | high | — | [potential_persistence_via_security_descriptors_scriptblock.yaml](./potential_persistence_via_security_descriptors_scriptblock.yaml) |
| Potential POWERTRASH Script Execution | high | T1059.001 | [potential_powertrash_script_execution.yaml](./potential_powertrash_script_execution.yaml) |
| Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell ScriptBlock | high | T1218 | [potential_remotefxvgpudisablement_exe_abuse_powershell_scriptblock.yaml](./potential_remotefxvgpudisablement_exe_abuse_powershell_scriptblock.yaml) |
| Potential WinAPI Calls Via PowerShell Scripts | high | T1059.001, T1106, T1620 | [potential_winapi_calls_via_powershell_scripts.yaml](./potential_winapi_calls_via_powershell_scripts.yaml) |
| Powershell Add Name Resolution Policy Table Rule | high | T1565 | [powershell_add_name_resolution_policy_table_rule.yaml](./powershell_add_name_resolution_policy_table_rule.yaml) |
| PowerShell ADRecon Execution | high | T1059.001 | [powershell_adrecon_execution.yaml](./powershell_adrecon_execution.yaml) |
| PowerShell COM Hijacking InProcServer32 Modification | high | T1059.001, T1546.015 | [powershell_com_hijacking_inprocserver32_modification.yaml](./powershell_com_hijacking_inprocserver32_modification.yaml) |
| PowerShell Credential Prompt | high | T1059.001 | [powershell_credential_prompt.yaml](./powershell_credential_prompt.yaml) |
| Powershell DNSExfiltration | high | T1048 | [powershell_dnsexfiltration.yaml](./powershell_dnsexfiltration.yaml) |
| PowerShell Execute COM Object | high | T1546.015, T1059.001 | [powershell_execute_com_object.yaml](./powershell_execute_com_object.yaml) |
| Powershell Fileless Process Injection via GetProcAddress | high | T1055, T1059.001 | [powershell_fileless_process_injection_via_getprocaddress.yaml](./powershell_fileless_process_injection_via_getprocaddress.yaml) |
| PowerShell Get-Process LSASS in ScriptBlock | high | T1003.001 | [powershell_get_process_lsass_in_scriptblock.yaml](./powershell_get_process_lsass_in_scriptblock.yaml) |
| Powershell Install a DLL in System Directory | high | T1556.002 | [powershell_install_a_dll_in_system_directory.yaml](./powershell_install_a_dll_in_system_directory.yaml) |
| PowerShell Invoke WmiExec Usage | high | T1047 | [powershell_invoke_wmiexec_usage.yaml](./powershell_invoke_wmiexec_usage.yaml) |
| Powershell Load Module in Meterpreter | high | T1059.001 | [powershell_load_module_in_meterpreter.yaml](./powershell_load_module_in_meterpreter.yaml) |
| PowerShell Loading DotNET into Memory via Reflection | high | T1059.001 | [powershell_loading_dotnet_into_memory_via_reflection.yaml](./powershell_loading_dotnet_into_memory_via_reflection.yaml) |
| Powershell Processing Stream Of Data | high | T1059.001 | [powershell_processing_stream_of_data.yaml](./powershell_processing_stream_of_data.yaml) |
| PowerShell PSAttack | high | T1059.001 | [powershell_psattack.yaml](./powershell_psattack.yaml) |
| PowerShell Script Block With URL Chain | high | T1059.001, T1105 | [powershell_script_block_with_url_chain.yaml](./powershell_script_block_with_url_chain.yaml) |
| PowerShell Set-Acl On Windows Folder - PsScript | high | T1222 | [powershell_set_acl_on_windows_folder_psscript.yaml](./powershell_set_acl_on_windows_folder_psscript.yaml) |
| PowerShell ShellCode | high | T1055, T1059.001 | [powershell_shellcode.yaml](./powershell_shellcode.yaml) |
| Powershell Using memory As Backing Store | high | T1059.001 | [powershell_using_memory_as_backing_store.yaml](./powershell_using_memory_as_backing_store.yaml) |
| PowerShell Web Access Installation - PsScript | high | T1059.001 | [powershell_web_access_installation_psscript.yaml](./powershell_web_access_installation_psscript.yaml) |
| PowerShell Windows Defender Exclusion Commands | high | T1562.001 | [powershell_windows_defender_exclusion_commands.yaml](./powershell_windows_defender_exclusion_commands.yaml) |
| PowerView PowerShell Cmdlets - ScriptBlock | high | T1059.001 | [powerview_powershell_cmdlets_scriptblock.yaml](./powerview_powershell_cmdlets_scriptblock.yaml) |
| PSAsyncShell - Asynchronous TCP Reverse Shell | high | T1059.001 | [psasyncshell_asynchronous_tcp_reverse_shell.yaml](./psasyncshell_asynchronous_tcp_reverse_shell.yaml) |
| Suspicious Kerberos Ticket Request via PowerShell Script - ScriptBlock | high | T1558.003 | [suspicious_kerberos_ticket_request_via_powershell_script_scriptblock.yaml](./suspicious_kerberos_ticket_request_via_powershell_script_scriptblock.yaml) |
| Suspicious PowerShell Invocations - Generic | high | T1059.001 | [suspicious_powershell_invocations_generic.yaml](./suspicious_powershell_invocations_generic.yaml) |
| Suspicious PowerShell Invocations - Specific | high | T1059.001 | [suspicious_powershell_invocations_specific.yaml](./suspicious_powershell_invocations_specific.yaml) |
| Suspicious Service DACL Modification Via Set-Service Cmdlet - PS | high | T1574.011 | [suspicious_service_dacl_modification_via_set_service_cmdlet_ps.yaml](./suspicious_service_dacl_modification_via_set_service_cmdlet_ps.yaml) |
| Tamper Windows Defender - ScriptBlockLogging | high | T1685 | [tamper_windows_defender_scriptblocklogging.yaml](./tamper_windows_defender_scriptblocklogging.yaml) |
| Tamper Windows Defender Remove-MpPreference - ScriptBlockLogging | high | T1685 | [tamper_windows_defender_remove_mppreference_scriptblocklogging.yaml](./tamper_windows_defender_remove_mppreference_scriptblocklogging.yaml) |
| Veeam Backup Servers Credential Dumping Script Execution | high | — | [veeam_backup_servers_credential_dumping_script_execution.yaml](./veeam_backup_servers_credential_dumping_script_execution.yaml) |
| Windows Enable PowerShell Web Access | high | T1059.001 | [windows_enable_powershell_web_access.yaml](./windows_enable_powershell_web_access.yaml) |
| Windows ESX Admins Group Creation via PowerShell | high | T1136.001, T1136.002 | [windows_esx_admins_group_creation_via_powershell.yaml](./windows_esx_admins_group_creation_via_powershell.yaml) |
| Windows Forest Discovery with GetForestDomain | high | T1087.002 | [windows_forest_discovery_with_getforestdomain.yaml](./windows_forest_discovery_with_getforestdomain.yaml) |
| Windows PowerShell Add Module to Global Assembly Cache | high | T1505.004 | [windows_powershell_add_module_to_global_assembly_cache.yaml](./windows_powershell_add_module_to_global_assembly_cache.yaml) |
| Windows PowerShell Disable HTTP Logging | high | T1505.004, T1562.002 | [windows_powershell_disable_http_logging.yaml](./windows_powershell_disable_http_logging.yaml) |
| Windows PowerShell Enable SMB1Protocol Feature | high | T1027.005 | [powershell_enable_smb1protocol_feature.yaml](./powershell_enable_smb1protocol_feature.yaml) |
| Windows PowerShell IIS Components WebGlobalModule Usage | high | T1505.004 | [windows_powershell_iis_components_webglobalmodule_usage.yaml](./windows_powershell_iis_components_webglobalmodule_usage.yaml) |
| Windows PowerShell Process With Malicious String | high | T1059.001 | [windows_powershell_process_with_malicious_string.yaml](./windows_powershell_process_with_malicious_string.yaml) |
| Windows PowerShell Script Block With Malicious String | high | T1059.001 | [windows_powershell_script_block_with_malicious_string.yaml](./windows_powershell_script_block_with_malicious_string.yaml) |
| Windows PowerSploit GPP Discovery | high | T1552.006 | [windows_powersploit_gpp_discovery.yaml](./windows_powersploit_gpp_discovery.yaml) |
| Windows Screen Capture Via Powershell | high | T1113 | [windows_screen_capture_via_powershell.yaml](./windows_screen_capture_via_powershell.yaml) |
| WMImplant Hack Tool | high | T1047, T1059.001 | [wmimplant_hack_tool.yaml](./wmimplant_hack_tool.yaml) |
| Access to Browser Login Data | medium | T1555.003 | [access_to_browser_login_data.yaml](./access_to_browser_login_data.yaml) |
| Add Windows Capability Via PowerShell Script | medium | — | [add_windows_capability_via_powershell_script.yaml](./add_windows_capability_via_powershell_script.yaml) |
| AdsiSearcher Account Discovery | medium | T1087.002 | [adsisearcher_account_discovery.yaml](./adsisearcher_account_discovery.yaml) |
| Allow Inbound Traffic In Firewall Rule | medium | T1021.001 | [allow_inbound_traffic_in_firewall_rule.yaml](./allow_inbound_traffic_in_firewall_rule.yaml) |
| Automated Collection Command PowerShell | medium | T1119 | [automated_collection_command_powershell.yaml](./automated_collection_command_powershell.yaml) |
| Certificate Exported Via PowerShell - ScriptBlock | medium | T1552.004 | [certificate_exported_via_powershell_scriptblock.yaml](./certificate_exported_via_powershell_scriptblock.yaml) |
| Change PowerShell Policies to an Insecure Level - PowerShell | medium | T1059.001 | [change_powershell_policies_to_an_insecure_level_powershell.yaml](./change_powershell_policies_to_an_insecure_level_powershell.yaml) |
| Change User Agents with WebRequest | medium | T1071.001 | [change_user_agents_with_webrequest.yaml](./change_user_agents_with_webrequest.yaml) |
| Clear PowerShell History - PowerShell | medium | T1070.003 | [clear_powershell_history_powershell.yaml](./clear_powershell_history_powershell.yaml) |
| Computer Discovery And Export Via Get-ADComputer Cmdlet - PowerShell | medium | T1033 | [computer_discovery_and_export_via_get_adcomputer_cmdlet_powershell.yaml](./computer_discovery_and_export_via_get_adcomputer_cmdlet_powershell.yaml) |
| Detected Windows Software Discovery - PowerShell | medium | T1518 | [detected_windows_software_discovery_powershell.yaml](./detected_windows_software_discovery_powershell.yaml) |
| DirectorySearcher Powershell Exploitation | medium | T1018 | [directorysearcher_powershell_exploitation.yaml](./directorysearcher_powershell_exploitation.yaml) |
| Disabled Kerberos Pre-Authentication Discovery With Get-ADUser | medium | T1558.004 | [disabled_kerberos_pre_authentication_discovery_with_get_aduser.yaml](./disabled_kerberos_pre_authentication_discovery_with_get_aduser.yaml) |
| Disabled Kerberos Pre-Authentication Discovery With PowerView | medium | T1558.004 | [disabled_kerberos_pre_authentication_discovery_with_powerview.yaml](./disabled_kerberos_pre_authentication_discovery_with_powerview.yaml) |
| DMSA Service Account Created in Specific OUs - PowerShell | medium | T1078.002, T1098 | [dmsa_service_account_created_in_specific_ous_powershell.yaml](./dmsa_service_account_created_in_specific_ous_powershell.yaml) |
| Domain Group Discovery with Adsisearcher | medium | T1069.002 | [domain_group_discovery_with_adsisearcher.yaml](./domain_group_discovery_with_adsisearcher.yaml) |
| Dump Credentials from Windows Credential Manager With PowerShell | medium | T1555 | [dump_credentials_from_windows_credential_manager_with_powershell.yaml](./dump_credentials_from_windows_credential_manager_with_powershell.yaml) |
| Elevated Group Discovery with PowerView | medium | T1069.002 | [elevated_group_discovery_with_powerview.yaml](./elevated_group_discovery_with_powerview.yaml) |
| Enable Windows Remote Management | medium | T1021.006 | [enable_windows_remote_management.yaml](./enable_windows_remote_management.yaml) |
| Enumerate Credentials from Windows Credential Manager With PowerShell | medium | T1555 | [enumerate_credentials_from_windows_credential_manager_with_powershell.yaml](./enumerate_credentials_from_windows_credential_manager_with_powershell.yaml) |
| Execute Invoke-command on Remote Host | medium | T1021.006 | [execute_invoke_command_on_remote_host.yaml](./execute_invoke_command_on_remote_host.yaml) |
| Extracting Information with PowerShell | medium | T1552.001 | [extracting_information_with_powershell.yaml](./extracting_information_with_powershell.yaml) |
| Get ADUser with PowerShell Script Block | medium | T1087.002 | [get_aduser_with_powershell_script_block.yaml](./get_aduser_with_powershell_script_block.yaml) |
| Get-ADUser Enumeration Using UserAccountControl Flags | medium | T1033 | [get_aduser_enumeration_using_useraccountcontrol_flags.yaml](./get_aduser_enumeration_using_useraccountcontrol_flags.yaml) |
| Get-DomainComputer with PowerShell Script Block | medium | T1018 | [getdomaincomputer_with_powershell_script_block.yaml](./getdomaincomputer_with_powershell_script_block.yaml) |
| Get-DomainController with PowerShell Script Block | medium | T1018 | [getdomaincontroller_with_powershell_script_block.yaml](./getdomaincontroller_with_powershell_script_block.yaml) |
| Get-DomainGroup with PowerShell Script Block | medium | T1069.002 | [getdomaingroup_with_powershell_script_block.yaml](./getdomaingroup_with_powershell_script_block.yaml) |
| Get-DomainTrust with PowerShell Script Block | medium | T1482 | [get_domaintrust_with_powershell_script_block.yaml](./get_domaintrust_with_powershell_script_block.yaml) |
| Get-DomainUser with PowerShell Script Block | medium | T1087.002 | [get_domainuser_with_powershell_script_block.yaml](./get_domainuser_with_powershell_script_block.yaml) |
| Get-ForestTrust with PowerShell Script Block | medium | T1482, T1059.001 | [get_foresttrust_with_powershell_script_block.yaml](./get_foresttrust_with_powershell_script_block.yaml) |
| Get-WmiObject Ds_Computer with PowerShell Script Block | medium | T1018 | [getwmiobject_ds_computer_with_powershell_script_block.yaml](./getwmiobject_ds_computer_with_powershell_script_block.yaml) |
| Get-WmiObject Ds_Group with PowerShell Script Block | medium | T1069.002 | [getwmiobject_ds_group_with_powershell_script_block.yaml](./getwmiobject_ds_group_with_powershell_script_block.yaml) |
| Get-WmiObject Ds_User with PowerShell Script Block | medium | T1087.002 | [getwmiobject_ds_user_with_powershell_script_block.yaml](./getwmiobject_ds_user_with_powershell_script_block.yaml) |
| Import PowerShell Modules From Suspicious Directories | medium | T1059.001 | [import_powershell_modules_from_suspicious_directories.yaml](./import_powershell_modules_from_suspicious_directories.yaml) |
| Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell | medium | T1027, T1059.001 | [invoke_obfuscation_compress_obfuscation_powershell.yaml](./invoke_obfuscation_compress_obfuscation_powershell.yaml) |
| Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell | medium | T1027, T1059.001 | [invoke_obfuscation_rundll_launcher_powershell.yaml](./invoke_obfuscation_rundll_launcher_powershell.yaml) |
| Malicious PowerShell Keywords | medium | T1059.001 | [malicious_powershell_keywords.yaml](./malicious_powershell_keywords.yaml) |
| Manipulation of User Computer or Group Security Principals Across AD | medium | T1136.002 | [manipulation_of_user_computer_or_group_security_principals_across_ad.yaml](./manipulation_of_user_computer_or_group_security_principals_across_ad.yaml) |
| Modify Group Policy Settings - ScriptBlockLogging | medium | T1484.001 | [modify_group_policy_settings_scriptblocklogging.yaml](./modify_group_policy_settings_scriptblocklogging.yaml) |
| Potential Active Directory Enumeration Using AD Module - PsScript | medium | — | [potential_active_directory_enumeration_using_ad_module_psscript.yaml](./potential_active_directory_enumeration_using_ad_module_psscript.yaml) |
| Potential AMSI Bypass Script Using NULL Bits | medium | T1685 | [potential_amsi_bypass_script_using_null_bits.yaml](./potential_amsi_bypass_script_using_null_bits.yaml) |
| Potential COM Objects Download Cradles Usage - PS Script | medium | T1105 | [potential_com_objects_download_cradles_usage_ps_script.yaml](./potential_com_objects_download_cradles_usage_ps_script.yaml) |
| Potential Data Exfiltration Via Audio File | medium | — | [potential_data_exfiltration_via_audio_file.yaml](./potential_data_exfiltration_via_audio_file.yaml) |
| Potential In-Memory Execution Using Reflection.Assembly | medium | T1620 | [potential_in_memory_execution_using_reflection_assembly.yaml](./potential_in_memory_execution_using_reflection_assembly.yaml) |
| Potential Keylogger Activity | medium | T1056.001 | [potential_keylogger_activity.yaml](./potential_keylogger_activity.yaml) |
| Potential Packet Capture Activity Via Start-NetEventSession - ScriptBlock | medium | T1040 | [potential_packet_capture_activity_via_start_neteventsession_scriptblock.yaml](./potential_packet_capture_activity_via_start_neteventsession_scriptblock.yaml) |
| Potential Persistence Via PowerShell User Profile Using Add-Content | medium | T1546.013 | [potential_persistence_via_powershell_user_profile_using_add_content.yaml](./potential_persistence_via_powershell_user_profile_using_add_content.yaml) |
| Potential Suspicious PowerShell Keywords | medium | T1059.001 | [potential_suspicious_powershell_keywords.yaml](./potential_suspicious_powershell_keywords.yaml) |
| Potential Suspicious Windows Feature Enabled | medium | — | [potential_suspicious_windows_feature_enabled.yaml](./potential_suspicious_windows_feature_enabled.yaml) |
| Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock | medium | T1018, T1558, T1589.002 | [potential_unconstrained_delegation_discovery_via_get_adcomputer_scriptblock.yaml](./potential_unconstrained_delegation_discovery_via_get_adcomputer_scriptblock.yaml) |
| Potentially Suspicious Call To Win32_NTEventlogFile Class - PSScript | medium | — | [potentially_suspicious_call_to_win32_nteventlogfile_class_psscript.yaml](./potentially_suspicious_call_to_win32_nteventlogfile_class_psscript.yaml) |
| PowerShell Create Local User | medium | T1059.001, T1136.001 | [powershell_create_local_user.yaml](./powershell_create_local_user.yaml) |
| Powershell Create Scheduled Task | medium | T1053.005 | [powershell_create_scheduled_task.yaml](./powershell_create_scheduled_task.yaml) |
| Powershell Creating Thread Mutex | medium | T1027.005, T1059.001 | [powershell_creating_thread_mutex.yaml](./powershell_creating_thread_mutex.yaml) |
| PowerShell Deleted Mounted Share | medium | T1070.005 | [powershell_deleted_mounted_share.yaml](./powershell_deleted_mounted_share.yaml) |
| Powershell Detect Virtualization Environment | medium | T1497.001 | [powershell_detect_virtualization_environment.yaml](./powershell_detect_virtualization_environment.yaml) |
| Powershell Directory Enumeration | medium | T1083 | [powershell_directory_enumeration.yaml](./powershell_directory_enumeration.yaml) |
| Powershell Execute Batch Script | medium | T1059.003 | [powershell_execute_batch_script.yaml](./powershell_execute_batch_script.yaml) |
| Powershell Fileless Script Contains Base64 Encoded Content | medium | T1027, T1059.001 | [powershell_fileless_script_contains_base64_encoded_content.yaml](./powershell_fileless_script_contains_base64_encoded_content.yaml) |
| PowerShell Hotfix Enumeration | medium | — | [powershell_hotfix_enumeration.yaml](./powershell_hotfix_enumeration.yaml) |
| PowerShell ICMP Exfiltration | medium | T1048.003 | [powershell_icmp_exfiltration.yaml](./powershell_icmp_exfiltration.yaml) |
| PowerShell Invoke CIMMethod CIMSession | medium | T1047 | [powershell_invoke_cimmethod_cimsession.yaml](./powershell_invoke_cimmethod_cimsession.yaml) |
| Powershell Keylogging | medium | T1056.001 | [powershell_keylogging.yaml](./powershell_keylogging.yaml) |
| Powershell Local Email Collection | medium | T1114.001 | [powershell_local_email_collection.yaml](./powershell_local_email_collection.yaml) |
| Powershell LocalAccount Manipulation | medium | T1098 | [powershell_localaccount_manipulation.yaml](./powershell_localaccount_manipulation.yaml) |
| Powershell MsXml COM Object | medium | T1059.001 | [powershell_msxml_com_object.yaml](./powershell_msxml_com_object.yaml) |
| Powershell Remote Services Add TrustedHost | medium | T1021.006 | [powershell_remote_services_add_trustedhost.yaml](./powershell_remote_services_add_trustedhost.yaml) |
| PowerShell Remote Session Creation | medium | T1059.001 | [powershell_remote_session_creation.yaml](./powershell_remote_session_creation.yaml) |
| PowerShell Script With File Hostname Resolving Capabilities | medium | T1020 | [powershell_script_with_file_hostname_resolving_capabilities.yaml](./powershell_script_with_file_hostname_resolving_capabilities.yaml) |
| Powershell Sensitive File Discovery | medium | T1083 | [powershell_sensitive_file_discovery.yaml](./powershell_sensitive_file_discovery.yaml) |
| PowerShell Start-BitsTransfer | medium | T1197 | [powershell_start_bitstransfer.yaml](./powershell_start_bitstransfer.yaml) |
| Powershell Store File In Alternate Data Stream | medium | T1564.004 | [powershell_store_file_in_alternate_data_stream.yaml](./powershell_store_file_in_alternate_data_stream.yaml) |
| Powershell Timestomp | medium | T1070.006 | [powershell_timestomp.yaml](./powershell_timestomp.yaml) |
| Powershell WMI Persistence | medium | T1546.003 | [powershell_wmi_persistence.yaml](./powershell_wmi_persistence.yaml) |
| PowerShell WMI Win32_Product Install MSI | medium | T1218.007 | [powershell_wmi_win32_product_install_msi.yaml](./powershell_wmi_win32_product_install_msi.yaml) |
| PowerShell Write-EventLog Usage | medium | — | [powershell_write_eventlog_usage.yaml](./powershell_write_eventlog_usage.yaml) |
| Powershell XML Execute Command | medium | T1059.001 | [powershell_xml_execute_command.yaml](./powershell_xml_execute_command.yaml) |
| Recon AVProduct Through PowerShell or WMI | medium | T1592 | [recon_avproduct_through_pwh_or_wmi.yaml](./recon_avproduct_through_pwh_or_wmi.yaml) |
| Recon Information for Export with PowerShell | medium | T1119 | [recon_information_for_export_with_powershell.yaml](./recon_information_for_export_with_powershell.yaml) |
| Registry Modification Attempt Via VBScript - PowerShell | medium | T1112, T1059.005 | [registry_modification_attempt_via_vbscript_powershell.yaml](./registry_modification_attempt_via_vbscript_powershell.yaml) |
| Registry-Free Process Scope COR_PROFILER | medium | T1574.012 | [registry_free_process_scope_cor_profiler.yaml](./registry_free_process_scope_cor_profiler.yaml) |
| Remote Process Instantiation via DCOM and PowerShell Script Block | medium | T1021.003 | [remote_process_instantiation_via_dcom_and_powershell_script_block.yaml](./remote_process_instantiation_via_dcom_and_powershell_script_block.yaml) |
| Remote Process Instantiation via WinRM and PowerShell Script Block | medium | T1021.006 | [remote_process_instantiation_via_winrm_and_powershell_script_block.yaml](./remote_process_instantiation_via_winrm_and_powershell_script_block.yaml) |
| Remote Process Instantiation via WMI and PowerShell Script Block | medium | T1047 | [remote_process_instantiation_via_wmi_and_powershell_script_block.yaml](./remote_process_instantiation_via_wmi_and_powershell_script_block.yaml) |
| Remote System Discovery with Adsisearcher | medium | T1018 | [remote_system_discovery_with_adsisearcher.yaml](./remote_system_discovery_with_adsisearcher.yaml) |
| Remove Account From Domain Admin Group | medium | T1531 | [remove_account_from_domain_admin_group.yaml](./remove_account_from_domain_admin_group.yaml) |
| Root Certificate Installed - PowerShell | medium | T1553.004 | [root_certificate_installed_powershell.yaml](./root_certificate_installed_powershell.yaml) |
| Security Software Discovery Via Powershell Script | medium | T1518.001 | [security_software_discovery_via_powershell_script.yaml](./security_software_discovery_via_powershell_script.yaml) |
| Service Registry Permissions Weakness Check | medium | T1574.011 | [service_registry_permissions_weakness_check.yaml](./service_registry_permissions_weakness_check.yaml) |
| ServicePrincipalNames Discovery with PowerShell | medium | T1558.003 | [serviceprincipalnames_discovery_with_powershell.yaml](./serviceprincipalnames_discovery_with_powershell.yaml) |
| Suspicious Eventlog Clear | medium | T1685.005 | [suspicious_eventlog_clear.yaml](./suspicious_eventlog_clear.yaml) |
| Suspicious FromBase64String Usage On Gzip Archive - Ps Script | medium | T1132.001 | [suspicious_frombase64string_usage_on_gzip_archive_ps_script.yaml](./suspicious_frombase64string_usage_on_gzip_archive_ps_script.yaml) |
| Suspicious Get-ADReplAccount | medium | T1003.006 | [suspicious_get_adreplaccount.yaml](./suspicious_get_adreplaccount.yaml) |
| Suspicious GetTypeFromCLSID ShellExecute | medium | T1546.015 | [suspicious_gettypefromclsid_shellexecute.yaml](./suspicious_gettypefromclsid_shellexecute.yaml) |
| Suspicious Hyper-V Cmdlets | medium | T1564.006 | [suspicious_hyper_v_cmdlets.yaml](./suspicious_hyper_v_cmdlets.yaml) |
| Suspicious Invoke-Item From Mount-DiskImage | medium | T1553.005 | [suspicious_invoke_item_from_mount_diskimage.yaml](./suspicious_invoke_item_from_mount_diskimage.yaml) |
| Suspicious IO.FileStream | medium | T1070.003 | [suspicious_io_filestream.yaml](./suspicious_io_filestream.yaml) |
| Suspicious New-PSDrive to Admin Share | medium | T1021.002 | [suspicious_new_psdrive_to_admin_share.yaml](./suspicious_new_psdrive_to_admin_share.yaml) |
| Suspicious PowerShell Download - Powershell Script | medium | T1059.001 | [suspicious_powershell_download_powershell_script.yaml](./suspicious_powershell_download_powershell_script.yaml) |
| Suspicious PowerShell WindowStyle Option | medium | T1564.003 | [suspicious_powershell_windowstyle_option.yaml](./suspicious_powershell_windowstyle_option.yaml) |
| Suspicious Start-Process PassThru | medium | T1036.003 | [suspicious_start_process_passthru.yaml](./suspicious_start_process_passthru.yaml) |
| Suspicious TCP Tunnel Via PowerShell Script | medium | T1090 | [suspicious_tcp_tunnel_via_powershell_script.yaml](./suspicious_tcp_tunnel_via_powershell_script.yaml) |
| Suspicious Unblock-File | medium | T1553.005 | [suspicious_unblock_file.yaml](./suspicious_unblock_file.yaml) |
| Suspicious X509Enrollment - Ps Script | medium | T1553.004 | [suspicious_x509enrollment_ps_script.yaml](./suspicious_x509enrollment_ps_script.yaml) |
| SyncAppvPublishingServer Execution to Bypass Powershell Restriction | medium | T1218 | [syncappvpublishingserver_execution_to_bypass_powershell_restriction.yaml](./syncappvpublishingserver_execution_to_bypass_powershell_restriction.yaml) |
| Testing Usage of Uncommonly Used Port | medium | T1571 | [testing_usage_of_uncommonly_used_port.yaml](./testing_usage_of_uncommonly_used_port.yaml) |
| Troubleshooting Pack Cmdlet Execution | medium | T1202 | [troubleshooting_pack_cmdlet_execution.yaml](./troubleshooting_pack_cmdlet_execution.yaml) |
| Unloading AMSI via Reflection | medium | T1059.001, T1562 | [unloading_amsi_via_reflection.yaml](./unloading_amsi_via_reflection.yaml) |
| Unsigned AppX Installation Attempt Using Add-AppxPackage - PsScript | medium | — | [unsigned_appx_installation_attempt_using_add_appxpackage_psscript.yaml](./unsigned_appx_installation_attempt_using_add_appxpackage_psscript.yaml) |
| Usage Of Web Request Commands And Cmdlets - ScriptBlock | medium | T1059.001 | [usage_of_web_request_commands_and_cmdlets_scriptblock.yaml](./usage_of_web_request_commands_and_cmdlets_scriptblock.yaml) |
| User Discovery And Export Via Get-ADUser Cmdlet - PowerShell | medium | T1033 | [user_discovery_and_export_via_get_aduser_cmdlet_powershell.yaml](./user_discovery_and_export_via_get_aduser_cmdlet_powershell.yaml) |
| Windows Account Discovery for None Disable User Account | medium | T1087.001 | [windows_account_discovery_for_none_disable_user_account.yaml](./windows_account_discovery_for_none_disable_user_account.yaml) |
| Windows Account Discovery With NetUser PreauthNotRequire | medium | T1087 | [windows_account_discovery_with_netuser_preauthnotrequire.yaml](./windows_account_discovery_with_netuser_preauthnotrequire.yaml) |
| Windows Archive Collected Data via Powershell | medium | T1560 | [windows_archive_collected_data_via_powershell.yaml](./windows_archive_collected_data_via_powershell.yaml) |
| Windows ClipBoard Data via Get-ClipBoard | medium | T1115 | [windows_clipboard_data_via_get_clipboard.yaml](./windows_clipboard_data_via_get_clipboard.yaml) |
| Windows Defender Exclusions Added - PowerShell | medium | T1685, T1059 | [windows_defender_exclusions_added_powershell.yaml](./windows_defender_exclusions_added_powershell.yaml) |
| Windows Exfiltration Over C2 Via Invoke RestMethod | medium | T1041 | [windows_exfiltration_over_c2_via_invoke_restmethod.yaml](./windows_exfiltration_over_c2_via_invoke_restmethod.yaml) |
| Windows Exfiltration Over C2 Via Powershell UploadString | medium | T1041 | [windows_exfiltration_over_c2_via_powershell_uploadstring.yaml](./windows_exfiltration_over_c2_via_powershell_uploadstring.yaml) |
| Windows File Share Discovery With Powerview | medium | T1135 | [windows_file_share_discovery_with_powerview.yaml](./windows_file_share_discovery_with_powerview.yaml) |
| Windows Find Domain Organizational Units with GetDomainOU | medium | T1087.002 | [windows_find_domain_organizational_units_with_getdomainou.yaml](./windows_find_domain_organizational_units_with_getdomainou.yaml) |
| Windows Find Interesting ACL with FindInterestingDomainAcl | medium | T1087.002 | [windows_find_interesting_acl_with_findinterestingdomainacl.yaml](./windows_find_interesting_acl_with_findinterestingdomainacl.yaml) |
| Windows Firewall Profile Disabled | medium | T1686.003 | [windows_firewall_profile_disabled.yaml](./windows_firewall_profile_disabled.yaml) |
| Windows Gather Victim Host Information Camera | medium | T1592.001 | [windows_gather_victim_host_information_camera.yaml](./windows_gather_victim_host_information_camera.yaml) |
| Windows Get Local Admin with FindLocalAdminAccess | medium | T1087.002 | [windows_get_local_admin_with_findlocaladminaccess.yaml](./windows_get_local_admin_with_findlocaladminaccess.yaml) |
| Windows Get-AdComputer Unconstrained Delegation Discovery | medium | T1018 | [windows_get_adcomputer_unconstrained_delegation_discovery.yaml](./windows_get_adcomputer_unconstrained_delegation_discovery.yaml) |
| Windows Linked Policies In ADSI Discovery | medium | T1087.002 | [windows_linked_policies_in_adsi_discovery.yaml](./windows_linked_policies_in_adsi_discovery.yaml) |
| Windows PowerShell 4104 Hunting | medium | T1059.001 | [powershell_4104_hunting.yaml](./powershell_4104_hunting.yaml) |
| Windows PowerShell Cryptography Namespace | medium | T1059.001 | [windows_powershell_cryptography_namespace.yaml](./windows_powershell_cryptography_namespace.yaml) |
| Windows PowerShell Domain Enumeration | medium | T1059.001 | [powershell_domain_enumeration.yaml](./powershell_domain_enumeration.yaml) |
| Windows PowerShell Export Certificate | medium | T1552.004, T1649 | [windows_powershell_export_certificate.yaml](./windows_powershell_export_certificate.yaml) |
| Windows PowerShell Export PfxCertificate | medium | T1552.004, T1649 | [windows_powershell_export_pfxcertificate.yaml](./windows_powershell_export_pfxcertificate.yaml) |
| Windows Powershell History File Deletion | medium | T1059.003, T1070.003 | [windows_powershell_history_file_deletion.yaml](./windows_powershell_history_file_deletion.yaml) |
| Windows Powershell Import Applocker Policy | medium | T1059.001, T1562.001 | [windows_powershell_import_applocker_policy.yaml](./windows_powershell_import_applocker_policy.yaml) |
| Windows PowerShell Invoke-RestMethod IP Information Collection | medium | T1082, T1016, T1059.001 | [windows_powershell_invoke_restmethod_ip_information_collection.yaml](./windows_powershell_invoke_restmethod_ip_information_collection.yaml) |
| Windows PowerShell Invoke-Sqlcmd Execution | medium | T1059.001, T1059.003 | [windows_powershell_invoke_sqlcmd_execution.yaml](./windows_powershell_invoke_sqlcmd_execution.yaml) |
| Windows Powershell Logoff User via Quser | medium | T1059.001, T1531 | [windows_powershell_logoff_user_via_quser.yaml](./windows_powershell_logoff_user_via_quser.yaml) |
| Windows PowerShell MSIX Package Installation | medium | T1059.001, T1547.001 | [windows_powershell_msix_package_installation.yaml](./windows_powershell_msix_package_installation.yaml) |
| Windows PowerShell ScheduleTask | medium | T1053.005, T1059.001 | [windows_powershell_scheduletask.yaml](./windows_powershell_scheduletask.yaml) |
| Windows PowerShell WMI Win32 ScheduledJob | medium | T1059.001 | [windows_powershell_wmi_win32_scheduledjob.yaml](./windows_powershell_wmi_win32_scheduledjob.yaml) |
| Windows PowerView AD Access Control List Enumeration | medium | T1078.002, T1069 | [windows_powerview_ad_access_control_list_enumeration.yaml](./windows_powerview_ad_access_control_list_enumeration.yaml) |
| Windows PowerView Constrained Delegation Discovery | medium | T1018 | [windows_powerview_constrained_delegation_discovery.yaml](./windows_powerview_constrained_delegation_discovery.yaml) |
| Windows PowerView Kerberos Service Ticket Request | medium | T1558.003 | [windows_powerview_kerberos_service_ticket_request.yaml](./windows_powerview_kerberos_service_ticket_request.yaml) |
| Windows PowerView SPN Discovery | medium | T1558.003 | [windows_powerview_spn_discovery.yaml](./windows_powerview_spn_discovery.yaml) |
| Windows PowerView Unconstrained Delegation Discovery | medium | T1018 | [windows_powerview_unconstrained_delegation_discovery.yaml](./windows_powerview_unconstrained_delegation_discovery.yaml) |
| Windows Screen Capture with CopyFromScreen | medium | T1113 | [windows_screen_capture_with_copyfromscreen.yaml](./windows_screen_capture_with_copyfromscreen.yaml) |
| Winlogon Helper DLL | medium | T1547.004 | [winlogon_helper_dll.yaml](./winlogon_helper_dll.yaml) |
| WMIC Unquoted Services Path Lookup - PowerShell | medium | T1047 | [wmic_unquoted_services_path_lookup_powershell.yaml](./wmic_unquoted_services_path_lookup_powershell.yaml) |
| Zip A Folder With PowerShell For Staging In Temp - PowerShell Script | medium | T1074.001 | [zip_a_folder_with_powershell_for_staging_in_temp_powershell_script.yaml](./zip_a_folder_with_powershell_for_staging_in_temp_powershell_script.yaml) |
| Get ADDefaultDomainPasswordPolicy with Powershell Script Block | low | T1201 | [get_addefaultdomainpasswordpolicy_with_powershell_script_block.yaml](./get_addefaultdomainpasswordpolicy_with_powershell_script_block.yaml) |
| Get ADUserResultantPasswordPolicy with Powershell Script Block | low | T1201 | [get_aduserresultantpasswordpolicy_with_powershell_script_block.yaml](./get_aduserresultantpasswordpolicy_with_powershell_script_block.yaml) |
| Get DomainPolicy with PowerShell Script Block | low | T1201 | [get_domainpolicy_with_powershell_script_block.yaml](./get_domainpolicy_with_powershell_script_block.yaml) |
| Get-AdComputer with PowerShell Script Block | low | T1018 | [getadcomputer_with_powershell_script_block.yaml](./getadcomputer_with_powershell_script_block.yaml) |
| Get-AdGroup with PowerShell Script Block | low | T1069.002 | [getadgroup_with_powershell_script_block.yaml](./getadgroup_with_powershell_script_block.yaml) |
| Get-CurrentUser with PowerShell Script Block | low | T1033 | [getcurrent_user_with_powershell_script_block.yaml](./getcurrent_user_with_powershell_script_block.yaml) |
| Get-LocalUser with PowerShell Script Block | low | T1087.001, T1059.001 | [getlocaluser_with_powershell_script_block.yaml](./getlocaluser_with_powershell_script_block.yaml) |
| Get-NetTcpconnection with PowerShell Script Block | low | T1049 | [getnettcpconnection_with_powershell_script_block.yaml](./getnettcpconnection_with_powershell_script_block.yaml) |
| Get-WMIObject Group Discovery with Script Block Logging | low | T1069.001 | [get_wmiobject_group_discovery_with_script_block_logging.yaml](./get_wmiobject_group_discovery_with_script_block_logging.yaml) |
| Get-WmiObject Win32_UserAccount with PowerShell Script Block | low | T1087.001, T1059.001 | [getwmiobject_user_account_with_powershell_script_block.yaml](./getwmiobject_user_account_with_powershell_script_block.yaml) |
| Powershell Get LocalGroup Discovery with Script Block Logging | low | T1069.001 | [powershell_get_localgroup_discovery_with_script_block_logging.yaml](./powershell_get_localgroup_discovery_with_script_block_logging.yaml) |
| PowerShell Start or Stop Service | low | T1059.001 | [powershell_start_or_stop_service.yaml](./powershell_start_or_stop_service.yaml) |
| Recon Using WMI Class | low | T1592, T1059.001 | [recon_using_wmi_class.yaml](./recon_using_wmi_class.yaml) |
| User Discovery With Env Vars PowerShell Script Block | low | T1033 | [user_discovery_with_env_vars_powershell_script_block.yaml](./user_discovery_with_env_vars_powershell_script_block.yaml) |
| Windows Account Discovery for Sam Account Name | low | T1087 | [windows_account_discovery_for_sam_account_name.yaml](./windows_account_discovery_for_sam_account_name.yaml) |
| Windows Domain Account Discovery Via Get-NetComputer | low | T1087.002 | [windows_domain_account_discovery_via_get_netcomputer.yaml](./windows_domain_account_discovery_via_get_netcomputer.yaml) |
| Windows PowerShell Enable PowerShell Remoting | low | T1059.001 | [powershell_enable_powershell_remoting.yaml](./powershell_enable_powershell_remoting.yaml) |
| Windows PowerShell Get CIMInstance Remote Computer | low | T1059.001 | [windows_powershell_get_ciminstance_remote_computer.yaml](./windows_powershell_get_ciminstance_remote_computer.yaml) |
| Windows Root Domain linked policies Discovery | low | T1087.002 | [windows_root_domain_linked_policies_discovery.yaml](./windows_root_domain_linked_policies_discovery.yaml) |
| WMI Recon Running Process Or Services | low | T1592 | [wmi_recon_running_process_or_services.yaml](./wmi_recon_running_process_or_services.yaml) |
