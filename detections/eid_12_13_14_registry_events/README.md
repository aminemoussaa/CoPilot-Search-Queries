# Sysmon Event IDs 12 / 13 / 14 — Registry Events

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **40 rules**

Rules that search key creation, value set and key rename together, because the technique can surface as any of the three.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🔴 critical 10 · 🟠 high 21 · 🟡 medium 9 |
| Status | experimental 39, production 1 |
| ATT&CK techniques | 30 distinct |
| Provenance | 40 Sigma-derived, 0 written for this repo |
| Event IDs queried | `12` (40), `13` (40), `14` (40) |

## Onboarding

Enable `RegistryEvent` in the Sysmon config so all three event IDs are produced.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_eventdata_targetObject` | 40 |
| `data_win_system_eventID` | 40 |
| `data_win_eventdata_details` | 9 |
| `data_win_eventdata_image` | 8 |
| `data_win_eventdata_eventType` | 5 |
| `data_win_eventdata_newName` | 4 |

## Top ATT&CK techniques

[`T1112`](https://attack.mitre.org/techniques/T1112/) (11) · [`T1547`](https://attack.mitre.org/techniques/T1547/) (3) · [`T1685`](https://attack.mitre.org/techniques/T1685/) (3) · [`T1547.001`](https://attack.mitre.org/techniques/T1547/001/) (3) · [`T1003.001`](https://attack.mitre.org/techniques/T1003/001/) (2) · [`T1548.002`](https://attack.mitre.org/techniques/T1548/002/) (2) · [`T1218`](https://attack.mitre.org/techniques/T1218/) (1) · [`T1218.003`](https://attack.mitre.org/techniques/T1218/003/) (1)

## Rules (40)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| FlowCloud Registry Markers | 🔴 critical | 90 | `T1112` | [`flowcloud_registry_markers.yaml`](./flowcloud_registry_markers.yaml) |
| Leviathan Registry Key Activity | 🔴 critical | 90 | `T1547.001` | [`leviathan_registry_key_activity.yaml`](./leviathan_registry_key_activity.yaml) |
| OceanLotus Registry Activity | 🔴 critical | 90 | `T1112` | [`oceanlotus_registry_activity.yaml`](./oceanlotus_registry_activity.yaml) |
| OilRig APT Registry Persistence | 🔴 critical | 90 | `T1053.005`, `T1543.003`, `T1112`… | [`oilrig_apt_registry_persistence.yaml`](./oilrig_apt_registry_persistence.yaml) |
| Pandemic Registry Key | 🔴 critical | 90 | `T1105` | [`pandemic_registry_key.yaml`](./pandemic_registry_key.yaml) |
| Potential Credential Dumping Via LSASS SilentProcessExit Technique | 🔴 critical | 90 | `T1003.001` | [`potential_credential_dumping_via_lsass_silentprocessexit_technique.yaml`](./potential_credential_dumping_via_lsass_silentprocessexit_technique.yaml) |
| PrinterNightmare Mimikatz Driver Name | 🔴 critical | 90 | `T1204` | [`printernightmare_mimikatz_driver_name.yaml`](./printernightmare_mimikatz_driver_name.yaml) |
| Registry Entries For Azorult Malware | 🔴 critical | 90 | `T1112` | [`registry_entries_for_azorult_malware.yaml`](./registry_entries_for_azorult_malware.yaml) |
| Sticky Key Like Backdoor Usage - Registry | 🔴 critical | 90 | `T1546.008` | [`sticky_key_like_backdoor_usage_registry.yaml`](./sticky_key_like_backdoor_usage_registry.yaml) |
| Windows Credential Editor Registry | 🔴 critical | 90 | `T1003.001` | [`windows_credential_editor_registry.yaml`](./windows_credential_editor_registry.yaml) |
| CMSTP Execution Registry Event | 🟠 high | 75 | `T1218.003` | [`cmstp_execution_registry_event.yaml`](./cmstp_execution_registry_event.yaml) |
| Creation of a Local Hidden User Account by Registry | 🟠 high | 75 | `T1136.001` | [`creation_of_a_local_hidden_user_account_by_registry.yaml`](./creation_of_a_local_hidden_user_account_by_registry.yaml) |
| Diamond Sleet APT Scheduled Task Creation - Registry | 🟠 high | 75 | `T1685` | [`diamond_sleet_apt_scheduled_task_creation_registry.yaml`](./diamond_sleet_apt_scheduled_task_creation_registry.yaml) |
| Disable Security Events Logging Adding Reg Key MiniNt | 🟠 high | 75 | `T1685.001`, `T1112` | [`disable_security_events_logging_adding_reg_key_minint.yaml`](./disable_security_events_logging_adding_reg_key_minint.yaml) |
| DLL Load via LSASS | 🟠 high | 75 | `T1547.008` | [`dll_load_via_lsass.yaml`](./dll_load_via_lsass.yaml) |
| Esentutl Volume Shadow Copy Service Keys | 🟠 high | 75 | `T1003.002` | [`esentutl_volume_shadow_copy_service_keys.yaml`](./esentutl_volume_shadow_copy_service_keys.yaml) |
| HybridConnectionManager Service Installation - Registry | 🟠 high | 75 | `T1608` | [`hybridconnectionmanager_service_installation_registry.yaml`](./hybridconnectionmanager_service_installation_registry.yaml) |
| Narrator's Feedback-Hub Persistence | 🟠 high | 75 | `T1547.001` | [`narrator_s_feedback_hub_persistence.yaml`](./narrator_s_feedback_hub_persistence.yaml) |
| NetNTLM Downgrade Attack - Registry | 🟠 high | 75 | `T1685`, `T1112` | [`netntlm_downgrade_attack_registry.yaml`](./netntlm_downgrade_attack_registry.yaml) |
| Potential Qakbot Registry Activity | 🟠 high | 75 | `T1112` | [`potential_qakbot_registry_activity.yaml`](./potential_qakbot_registry_activity.yaml) |
| RedMimicry Winnti Playbook Registry Manipulation | 🟠 high | 75 | `T1112` | [`redmimicry_winnti_playbook_registry_manipulation.yaml`](./redmimicry_winnti_playbook_registry_manipulation.yaml) |
| Registry Persistence Mechanisms in Recycle Bin | 🟠 high | 75 | `T1547` | [`registry_persistence_mechanisms_in_recycle_bin.yaml`](./registry_persistence_mechanisms_in_recycle_bin.yaml) |
| Security Support Provider (SSP) Added to LSA Configuration | 🟠 high | 75 | `T1547.005` | [`security_support_provider_ssp_added_to_lsa_configuration.yaml`](./security_support_provider_ssp_added_to_lsa_configuration.yaml) |
| Shell Open Registry Keys Manipulation | 🟠 high | 75 | `T1548.002`, `T1546.001` | [`shell_open_registry_keys_manipulation.yaml`](./shell_open_registry_keys_manipulation.yaml) |
| SNAKE Malware Covert Store Registry Key | 🟠 high | 75 | — | [`snake_malware_covert_store_registry_key.yaml`](./snake_malware_covert_store_registry_key.yaml) |
| Suspicious Camera and Microphone Access | 🟠 high | 75 | `T1125`, `T1123` | [`suspicious_camera_and_microphone_access.yaml`](./suspicious_camera_and_microphone_access.yaml) |
| Suspicious Run Key from Download | 🟠 high | 75 | `T1547.001` | [`suspicious_run_key_from_download.yaml`](./suspicious_run_key_from_download.yaml) |
| UAC Bypass Via Wsreset | 🟠 high | 75 | `T1548.002` | [`uac_bypass_via_wsreset.yaml`](./uac_bypass_via_wsreset.yaml) |
| Wdigest CredGuard Registry Modification | 🟠 high | 75 | `T1112` | [`wdigest_credguard_registry_modification.yaml`](./wdigest_credguard_registry_modification.yaml) |
| Windows Defender Threat Severity Default Action Modified | 🟠 high | 75 | `T1685` | [`windows_defender_threat_severity_default_action_modified.yaml`](./windows_defender_threat_severity_default_action_modified.yaml) |
| WINEKEY Registry Modification | 🟠 high | 75 | `T1547` | [`winekey_registry_modification.yaml`](./winekey_registry_modification.yaml) |
| Atbroker Registry Change | 🟡 medium | 50 | `T1218`, `T1547` | [`atbroker_registry_change.yaml`](./atbroker_registry_change.yaml) |
| New DLL Added to AppCertDlls Registry Key | 🟡 medium | 50 | `T1546.009` | [`new_dll_added_to_appcertdlls_registry_key.yaml`](./new_dll_added_to_appcertdlls_registry_key.yaml) |
| New DLL Added to AppInit_DLLs Registry Key | 🟡 medium | 50 | `T1546.010` | [`new_dll_added_to_appinit_dlls_registry_key.yaml`](./new_dll_added_to_appinit_dlls_registry_key.yaml) |
| New PortProxy Registry Entry Added | 🟡 medium | 50 | `T1090` | [`new_portproxy_registry_entry_added.yaml`](./new_portproxy_registry_entry_added.yaml) |
| Office Application Startup - Office Test | 🟡 medium | 50 | `T1137.002` | [`office_application_startup_office_test.yaml`](./office_application_startup_office_test.yaml) |
| Path To Screensaver Binary Modified | 🟡 medium | 50 | `T1546.002` | [`path_to_screensaver_binary_modified.yaml`](./path_to_screensaver_binary_modified.yaml) |
| Registry Tampering by Potentially Suspicious Processes | 🟡 medium | 50 | `T1112`, `T1059.005` | [`registry_tampering_by_potentially_suspicious_processes.yaml`](./registry_tampering_by_potentially_suspicious_processes.yaml) |
| Run Once Task Configuration in Registry | 🟡 medium | 50 | `T1112` | [`run_once_task_configuration_in_registry.yaml`](./run_once_task_configuration_in_registry.yaml) |
| Windows Registry Trust Record Modification | 🟡 medium | 50 | `T1566.001` | [`windows_registry_trust_record_modification.yaml`](./windows_registry_trust_record_modification.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
