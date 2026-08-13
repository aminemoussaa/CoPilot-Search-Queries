# eid 12 13 14 registry events

Sysmon Event IDs 12/13/14 — rules that search the registry events together.

**40 rules** — critical 10, high 21, medium 9

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| FlowCloud Registry Markers | critical | T1112 | [flowcloud_registry_markers.yaml](./flowcloud_registry_markers.yaml) |
| Leviathan Registry Key Activity | critical | T1547.001 | [leviathan_registry_key_activity.yaml](./leviathan_registry_key_activity.yaml) |
| OceanLotus Registry Activity | critical | T1112 | [oceanlotus_registry_activity.yaml](./oceanlotus_registry_activity.yaml) |
| OilRig APT Registry Persistence | critical | T1053.005, T1543.003, T1112, T1071.004 | [oilrig_apt_registry_persistence.yaml](./oilrig_apt_registry_persistence.yaml) |
| Pandemic Registry Key | critical | T1105 | [pandemic_registry_key.yaml](./pandemic_registry_key.yaml) |
| Potential Credential Dumping Via LSASS SilentProcessExit Technique | critical | T1003.001 | [potential_credential_dumping_via_lsass_silentprocessexit_technique.yaml](./potential_credential_dumping_via_lsass_silentprocessexit_technique.yaml) |
| PrinterNightmare Mimikatz Driver Name | critical | T1204 | [printernightmare_mimikatz_driver_name.yaml](./printernightmare_mimikatz_driver_name.yaml) |
| Registry Entries For Azorult Malware | critical | T1112 | [registry_entries_for_azorult_malware.yaml](./registry_entries_for_azorult_malware.yaml) |
| Sticky Key Like Backdoor Usage - Registry | critical | T1546.008 | [sticky_key_like_backdoor_usage_registry.yaml](./sticky_key_like_backdoor_usage_registry.yaml) |
| Windows Credential Editor Registry | critical | T1003.001 | [windows_credential_editor_registry.yaml](./windows_credential_editor_registry.yaml) |
| CMSTP Execution Registry Event | high | T1218.003 | [cmstp_execution_registry_event.yaml](./cmstp_execution_registry_event.yaml) |
| Creation of a Local Hidden User Account by Registry | high | T1136.001 | [creation_of_a_local_hidden_user_account_by_registry.yaml](./creation_of_a_local_hidden_user_account_by_registry.yaml) |
| Diamond Sleet APT Scheduled Task Creation - Registry | high | T1685 | [diamond_sleet_apt_scheduled_task_creation_registry.yaml](./diamond_sleet_apt_scheduled_task_creation_registry.yaml) |
| Disable Security Events Logging Adding Reg Key MiniNt | high | T1685.001, T1112 | [disable_security_events_logging_adding_reg_key_minint.yaml](./disable_security_events_logging_adding_reg_key_minint.yaml) |
| DLL Load via LSASS | high | T1547.008 | [dll_load_via_lsass.yaml](./dll_load_via_lsass.yaml) |
| Esentutl Volume Shadow Copy Service Keys | high | T1003.002 | [esentutl_volume_shadow_copy_service_keys.yaml](./esentutl_volume_shadow_copy_service_keys.yaml) |
| HybridConnectionManager Service Installation - Registry | high | T1608 | [hybridconnectionmanager_service_installation_registry.yaml](./hybridconnectionmanager_service_installation_registry.yaml) |
| Narrator's Feedback-Hub Persistence | high | T1547.001 | [narrator_s_feedback_hub_persistence.yaml](./narrator_s_feedback_hub_persistence.yaml) |
| NetNTLM Downgrade Attack - Registry | high | T1685, T1112 | [netntlm_downgrade_attack_registry.yaml](./netntlm_downgrade_attack_registry.yaml) |
| Potential Qakbot Registry Activity | high | T1112 | [potential_qakbot_registry_activity.yaml](./potential_qakbot_registry_activity.yaml) |
| RedMimicry Winnti Playbook Registry Manipulation | high | T1112 | [redmimicry_winnti_playbook_registry_manipulation.yaml](./redmimicry_winnti_playbook_registry_manipulation.yaml) |
| Registry Persistence Mechanisms in Recycle Bin | high | T1547 | [registry_persistence_mechanisms_in_recycle_bin.yaml](./registry_persistence_mechanisms_in_recycle_bin.yaml) |
| Security Support Provider (SSP) Added to LSA Configuration | high | T1547.005 | [security_support_provider_ssp_added_to_lsa_configuration.yaml](./security_support_provider_ssp_added_to_lsa_configuration.yaml) |
| Shell Open Registry Keys Manipulation | high | T1548.002, T1546.001 | [shell_open_registry_keys_manipulation.yaml](./shell_open_registry_keys_manipulation.yaml) |
| SNAKE Malware Covert Store Registry Key | high | — | [snake_malware_covert_store_registry_key.yaml](./snake_malware_covert_store_registry_key.yaml) |
| Suspicious Camera and Microphone Access | high | T1125, T1123 | [suspicious_camera_and_microphone_access.yaml](./suspicious_camera_and_microphone_access.yaml) |
| Suspicious Run Key from Download | high | T1547.001 | [suspicious_run_key_from_download.yaml](./suspicious_run_key_from_download.yaml) |
| UAC Bypass Via Wsreset | high | T1548.002 | [uac_bypass_via_wsreset.yaml](./uac_bypass_via_wsreset.yaml) |
| Wdigest CredGuard Registry Modification | high | T1112 | [wdigest_credguard_registry_modification.yaml](./wdigest_credguard_registry_modification.yaml) |
| Windows Defender Threat Severity Default Action Modified | high | T1685 | [windows_defender_threat_severity_default_action_modified.yaml](./windows_defender_threat_severity_default_action_modified.yaml) |
| WINEKEY Registry Modification | high | T1547 | [winekey_registry_modification.yaml](./winekey_registry_modification.yaml) |
| Atbroker Registry Change | medium | T1218, T1547 | [atbroker_registry_change.yaml](./atbroker_registry_change.yaml) |
| New DLL Added to AppCertDlls Registry Key | medium | T1546.009 | [new_dll_added_to_appcertdlls_registry_key.yaml](./new_dll_added_to_appcertdlls_registry_key.yaml) |
| New DLL Added to AppInit_DLLs Registry Key | medium | T1546.010 | [new_dll_added_to_appinit_dlls_registry_key.yaml](./new_dll_added_to_appinit_dlls_registry_key.yaml) |
| New PortProxy Registry Entry Added | medium | T1090 | [new_portproxy_registry_entry_added.yaml](./new_portproxy_registry_entry_added.yaml) |
| Office Application Startup - Office Test | medium | T1137.002 | [office_application_startup_office_test.yaml](./office_application_startup_office_test.yaml) |
| Path To Screensaver Binary Modified | medium | T1546.002 | [path_to_screensaver_binary_modified.yaml](./path_to_screensaver_binary_modified.yaml) |
| Registry Tampering by Potentially Suspicious Processes | medium | T1112, T1059.005 | [registry_tampering_by_potentially_suspicious_processes.yaml](./registry_tampering_by_potentially_suspicious_processes.yaml) |
| Run Once Task Configuration in Registry | medium | T1112 | [run_once_task_configuration_in_registry.yaml](./run_once_task_configuration_in_registry.yaml) |
| Windows Registry Trust Record Modification | medium | T1566.001 | [windows_registry_trust_record_modification.yaml](./windows_registry_trust_record_modification.yaml) |
