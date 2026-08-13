# eid 4103 module logging

PowerShell **Operational** channel, Event ID 4103 — module / pipeline logging.

**20 rules** — critical 1, high 9, medium 10

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| Bad Opsec Powershell Code Artifacts | critical | T1059.001 | [bad_opsec_powershell_code_artifacts.yaml](./bad_opsec_powershell_code_artifacts.yaml) |
| HackTool - Evil-WinRm Execution - PowerShell Module | high | — | [hacktool_evil_winrm_execution_powershell_module.yaml](./hacktool_evil_winrm_execution_powershell_module.yaml) |
| Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module | high | T1027, T1059.001 | [invoke_obfuscation_obfuscated_iex_invocation_powershell_module.yaml](./invoke_obfuscation_obfuscated_iex_invocation_powershell_module.yaml) |
| Invoke-Obfuscation Via Use MSHTA - PowerShell Module | high | T1027, T1059.001 | [invoke_obfuscation_via_use_mshta_powershell_module.yaml](./invoke_obfuscation_via_use_mshta_powershell_module.yaml) |
| Invoke-Obfuscation Via Use Rundll32 - PowerShell Module | high | T1027, T1059.001 | [invoke_obfuscation_via_use_rundll32_powershell_module.yaml](./invoke_obfuscation_via_use_rundll32_powershell_module.yaml) |
| Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module | high | T1218 | [potential_remotefxvgpudisablement_exe_abuse_powershell_module.yaml](./potential_remotefxvgpudisablement_exe_abuse_powershell_module.yaml) |
| Remote PowerShell Session (PS Module) | high | T1059.001, T1021.006 | [remote_powershell_session_ps_module.yaml](./remote_powershell_session_ps_module.yaml) |
| Suspicious Get-ADDBAccount Usage | high | T1003.003 | [suspicious_get_addbaccount_usage.yaml](./suspicious_get_addbaccount_usage.yaml) |
| Suspicious PowerShell Invocations - Generic - PowerShell Module | high | T1059.001 | [suspicious_powershell_invocations_generic_powershell_module.yaml](./suspicious_powershell_invocations_generic_powershell_module.yaml) |
| Suspicious PowerShell Invocations - Specific - PowerShell Module | high | T1059.001 | [suspicious_powershell_invocations_specific_powershell_module.yaml](./suspicious_powershell_invocations_specific_powershell_module.yaml) |
| Alternate PowerShell Hosts - PowerShell Module | medium | T1059.001 | [alternate_powershell_hosts_powershell_module.yaml](./alternate_powershell_hosts_powershell_module.yaml) |
| Clear PowerShell History - PowerShell Module | medium | T1070.003 | [clear_powershell_history_powershell_module.yaml](./clear_powershell_history_powershell_module.yaml) |
| Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module | medium | T1027, T1059.001 | [invoke_obfuscation_compress_obfuscation_powershell_module.yaml](./invoke_obfuscation_compress_obfuscation_powershell_module.yaml) |
| Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell Module | medium | T1027, T1059.001 | [invoke_obfuscation_rundll_launcher_powershell_module.yaml](./invoke_obfuscation_rundll_launcher_powershell_module.yaml) |
| Potential Active Directory Enumeration Using AD Module - PsModule | medium | — | [potential_active_directory_enumeration_using_ad_module_psmodule.yaml](./potential_active_directory_enumeration_using_ad_module_psmodule.yaml) |
| PowerShell Get Clipboard | medium | T1115 | [powershell_get_clipboard.yaml](./powershell_get_clipboard.yaml) |
| Suspicious Computer Machine Password by PowerShell | medium | T1078 | [suspicious_computer_machine_password_by_powershell.yaml](./suspicious_computer_machine_password_by_powershell.yaml) |
| Suspicious PowerShell Download - PoshModule | medium | T1059.001 | [suspicious_powershell_download_poshmodule.yaml](./suspicious_powershell_download_poshmodule.yaml) |
| SyncAppvPublishingServer Bypass Powershell Restriction - PS Module | medium | T1218 | [syncappvpublishingserver_bypass_powershell_restriction_ps_module.yaml](./syncappvpublishingserver_bypass_powershell_restriction_ps_module.yaml) |
| Zip A Folder With PowerShell For Staging In Temp  - PowerShell Module | medium | T1074.001 | [zip_a_folder_with_powershell_for_staging_in_temp_powershell_module.yaml](./zip_a_folder_with_powershell_for_staging_in_temp_powershell_module.yaml) |
