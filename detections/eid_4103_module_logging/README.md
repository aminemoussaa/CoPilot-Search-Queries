# PowerShell Event ID 4103 — Module Logging

**Platform** `Windows` · **Log source** PowerShell `Microsoft-Windows-PowerShell/Operational` · **20 rules**

Pipeline execution details: the commands and parameter bindings PowerShell actually invoked, after aliases and obfuscation are resolved.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🔴 critical 1 · 🟠 high 9 · 🟡 medium 10 |
| Status | experimental 20 |
| ATT&CK techniques | 9 distinct |
| Provenance | 20 Sigma-derived, 0 written for this repo |
| Event IDs queried | `4103` (20) |

## Onboarding

Enable **Turn on Module Logging** via Group Policy (`Administrative Templates > Windows Components > Windows PowerShell`) with module names set to `*`, then collect the PowerShell Operational channel.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 20 |
| `data_win_eventdata_payload` | 13 |
| `data_win_eventdata_contextInfo` | 9 |

## Top ATT&CK techniques

[`T1059.001`](https://attack.mitre.org/techniques/T1059/001/) (11) · [`T1027`](https://attack.mitre.org/techniques/T1027/) (5) · [`T1218`](https://attack.mitre.org/techniques/T1218/) (2) · [`T1070.003`](https://attack.mitre.org/techniques/T1070/003/) (1) · [`T1115`](https://attack.mitre.org/techniques/T1115/) (1) · [`T1021.006`](https://attack.mitre.org/techniques/T1021/006/) (1) · [`T1078`](https://attack.mitre.org/techniques/T1078/) (1) · [`T1003.003`](https://attack.mitre.org/techniques/T1003/003/) (1)

## Rules (20)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Bad Opsec Powershell Code Artifacts | 🔴 critical | 90 | `T1059.001` | [`bad_opsec_powershell_code_artifacts.yaml`](./bad_opsec_powershell_code_artifacts.yaml) |
| HackTool - Evil-WinRm Execution - PowerShell Module | 🟠 high | 75 | — | [`hacktool_evil_winrm_execution_powershell_module.yaml`](./hacktool_evil_winrm_execution_powershell_module.yaml) |
| Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_obfuscated_iex_invocation_powershell_module.yaml`](./invoke_obfuscation_obfuscated_iex_invocation_powershell_module.yaml) |
| Invoke-Obfuscation Via Use MSHTA - PowerShell Module | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_via_use_mshta_powershell_module.yaml`](./invoke_obfuscation_via_use_mshta_powershell_module.yaml) |
| Invoke-Obfuscation Via Use Rundll32 - PowerShell Module | 🟠 high | 75 | `T1027`, `T1059.001` | [`invoke_obfuscation_via_use_rundll32_powershell_module.yaml`](./invoke_obfuscation_via_use_rundll32_powershell_module.yaml) |
| Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module | 🟠 high | 75 | `T1218` | [`potential_remotefxvgpudisablement_exe_abuse_powershell_module.yaml`](./potential_remotefxvgpudisablement_exe_abuse_powershell_module.yaml) |
| Remote PowerShell Session (PS Module) | 🟠 high | 75 | `T1059.001`, `T1021.006` | [`remote_powershell_session_ps_module.yaml`](./remote_powershell_session_ps_module.yaml) |
| Suspicious Get-ADDBAccount Usage | 🟠 high | 75 | `T1003.003` | [`suspicious_get_addbaccount_usage.yaml`](./suspicious_get_addbaccount_usage.yaml) |
| Suspicious PowerShell Invocations - Generic - PowerShell Module | 🟠 high | 75 | `T1059.001` | [`suspicious_powershell_invocations_generic_powershell_module.yaml`](./suspicious_powershell_invocations_generic_powershell_module.yaml) |
| Suspicious PowerShell Invocations - Specific - PowerShell Module | 🟠 high | 75 | `T1059.001` | [`suspicious_powershell_invocations_specific_powershell_module.yaml`](./suspicious_powershell_invocations_specific_powershell_module.yaml) |
| Alternate PowerShell Hosts - PowerShell Module | 🟡 medium | 50 | `T1059.001` | [`alternate_powershell_hosts_powershell_module.yaml`](./alternate_powershell_hosts_powershell_module.yaml) |
| Clear PowerShell History - PowerShell Module | 🟡 medium | 50 | `T1070.003` | [`clear_powershell_history_powershell_module.yaml`](./clear_powershell_history_powershell_module.yaml) |
| Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module | 🟡 medium | 50 | `T1027`, `T1059.001` | [`invoke_obfuscation_compress_obfuscation_powershell_module.yaml`](./invoke_obfuscation_compress_obfuscation_powershell_module.yaml) |
| Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell Module | 🟡 medium | 50 | `T1027`, `T1059.001` | [`invoke_obfuscation_rundll_launcher_powershell_module.yaml`](./invoke_obfuscation_rundll_launcher_powershell_module.yaml) |
| Potential Active Directory Enumeration Using AD Module - PsModule | 🟡 medium | 50 | — | [`potential_active_directory_enumeration_using_ad_module_psmodule.yaml`](./potential_active_directory_enumeration_using_ad_module_psmodule.yaml) |
| PowerShell Get Clipboard | 🟡 medium | 50 | `T1115` | [`powershell_get_clipboard.yaml`](./powershell_get_clipboard.yaml) |
| Suspicious Computer Machine Password by PowerShell | 🟡 medium | 50 | `T1078` | [`suspicious_computer_machine_password_by_powershell.yaml`](./suspicious_computer_machine_password_by_powershell.yaml) |
| Suspicious PowerShell Download - PoshModule | 🟡 medium | 50 | `T1059.001` | [`suspicious_powershell_download_poshmodule.yaml`](./suspicious_powershell_download_poshmodule.yaml) |
| SyncAppvPublishingServer Bypass Powershell Restriction - PS Module | 🟡 medium | 50 | `T1218` | [`syncappvpublishingserver_bypass_powershell_restriction_ps_module.yaml`](./syncappvpublishingserver_bypass_powershell_restriction_ps_module.yaml) |
| Zip A Folder With PowerShell For Staging In Temp  - PowerShell Module | 🟡 medium | 50 | `T1074.001` | [`zip_a_folder_with_powershell_for_staging_in_temp_powershell_module.yaml`](./zip_a_folder_with_powershell_for_staging_in_temp_powershell_module.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
