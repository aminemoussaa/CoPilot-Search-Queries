# eid 10 process access

Sysmon Event ID 10 — process access (handle open).

**24 rules** — high 20, medium 4

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| CMSTP Execution Process Access | high | T1218.003, T1559.001 | [cmstp_execution_process_access.yaml](./cmstp_execution_process_access.yaml) |
| Credential Dumping Activity By Python Based Tool | high | T1003.001 | [credential_dumping_activity_by_python_based_tool.yaml](./credential_dumping_activity_by_python_based_tool.yaml) |
| Credential Dumping Attempt Via Svchost | high | T1548 | [credential_dumping_attempt_via_svchost.yaml](./credential_dumping_attempt_via_svchost.yaml) |
| Credential Dumping Attempt Via WerFault | high | T1003.001 | [credential_dumping_attempt_via_werfault.yaml](./credential_dumping_attempt_via_werfault.yaml) |
| HackTool - Generic Process Access | high | T1003.001 | [hacktool_generic_process_access.yaml](./hacktool_generic_process_access.yaml) |
| HackTool - HandleKatz Duplicating LSASS Handle | high | T1106, T1003.001 | [hacktool_handlekatz_duplicating_lsass_handle.yaml](./hacktool_handlekatz_duplicating_lsass_handle.yaml) |
| HackTool - LittleCorporal Generated Maldoc Injection | high | T1204.002, T1055.003 | [hacktool_littlecorporal_generated_maldoc_injection.yaml](./hacktool_littlecorporal_generated_maldoc_injection.yaml) |
| HackTool - SysmonEnte Execution | high | T1685.001 | [hacktool_sysmonente_execution.yaml](./hacktool_sysmonente_execution.yaml) |
| LSASS Access From Potentially White-Listed Processes | high | T1003.001 | [lsass_access_from_potentially_white_listed_processes.yaml](./lsass_access_from_potentially_white_listed_processes.yaml) |
| LSASS Memory Access by Tool With Dump Keyword In Name | high | T1003.001 | [lsass_memory_access_by_tool_with_dump_keyword_in_name.yaml](./lsass_memory_access_by_tool_with_dump_keyword_in_name.yaml) |
| Lsass Memory Dump via Comsvcs DLL | high | T1003.001 | [lsass_memory_dump_via_comsvcs_dll.yaml](./lsass_memory_dump_via_comsvcs_dll.yaml) |
| Malware Shellcode in Verclsid Target Process | high | T1055 | [malware_shellcode_in_verclsid_target_process.yaml](./malware_shellcode_in_verclsid_target_process.yaml) |
| Potential Exploitation of RCE Vulnerability CVE-2025-33053 - Process Access | high | T1218, T1105 | [potential_exploitation_of_rce_vulnerability_cve_2025_33053_process_access.yaml](./potential_exploitation_of_rce_vulnerability_cve_2025_33053_process_access.yaml) |
| Remote LSASS Process Access Through Windows Remote Management | high | T1003.001, T1059.001, T1021.006 | [remote_lsass_process_access_through_windows_remote_management.yaml](./remote_lsass_process_access_through_windows_remote_management.yaml) |
| Suspicious LSASS Access Via MalSecLogon | high | T1003.001 | [suspicious_lsass_access_via_malseclogon.yaml](./suspicious_lsass_access_via_malseclogon.yaml) |
| Suspicious Process Access of MsMpEng by WerFaultSecure - EDR-Freeze | high | T1685 | [suspicious_process_access_of_msmpeng_by_werfaultsecure_edr_freeze.yaml](./suspicious_process_access_of_msmpeng_by_werfaultsecure_edr_freeze.yaml) |
| Suspicious Process Access to LSASS with Dbgcore/Dbghelp DLLs | high | T1003.001, T1685 | [suspicious_process_access_to_lsass_with_dbgcore_dbghelp_dlls.yaml](./suspicious_process_access_to_lsass_with_dbgcore_dbghelp_dlls.yaml) |
| Suspicious Svchost Process Access | high | T1685.001 | [suspicious_svchost_process_access.yaml](./suspicious_svchost_process_access.yaml) |
| UAC Bypass Using WOW64 Logger DLL Hijack | high | T1548.002 | [uac_bypass_using_wow64_logger_dll_hijack.yaml](./uac_bypass_using_wow64_logger_dll_hijack.yaml) |
| Windows Access Token Manipulation Winlogon Duplicate Token Handle | high | T1134.001 | [windows_access_token_manipulation_winlogon_duplicate_token_handle.yaml](./windows_access_token_manipulation_winlogon_duplicate_token_handle.yaml) |
| Function Call From Undocumented COM Interface EditionUpgradeManager | medium | T1548.002 | [function_call_from_undocumented_com_interface_editionupgrademanager.yaml](./function_call_from_undocumented_com_interface_editionupgrademanager.yaml) |
| Potential Credential Dumping Activity Via LSASS | medium | T1003.001 | [potential_credential_dumping_activity_via_lsass.yaml](./potential_credential_dumping_activity_via_lsass.yaml) |
| Potential Direct Syscall of NtOpenProcess | medium | T1106 | [potential_direct_syscall_of_ntopenprocess.yaml](./potential_direct_syscall_of_ntopenprocess.yaml) |
| Potentially Suspicious GrantedAccess Flags On LSASS | medium | T1003.001 | [potentially_suspicious_grantedaccess_flags_on_lsass.yaml](./potentially_suspicious_grantedaccess_flags_on_lsass.yaml) |
