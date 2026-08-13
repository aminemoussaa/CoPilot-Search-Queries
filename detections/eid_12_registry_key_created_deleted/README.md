# Sysmon Event ID 12 — Registry Key Created / Deleted

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **14 rules**

Registry key creation and deletion, distinct from value writes.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 8 · 🟡 medium 6 |
| Status | experimental 13, production 1 |
| ATT&CK techniques | 5 distinct |
| Provenance | 13 Sigma-derived, 1 written for this repo |
| Event IDs queried | `12` (14) |

## Onboarding

Enable `RegistryEvent` in the Sysmon config; event ID 12 covers key add/delete.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_eventdata_targetObject` | 14 |
| `data_win_system_eventID` | 14 |
| `data_win_eventdata_eventType` | 5 |
| `data_win_eventdata_image` | 3 |

## Top ATT&CK techniques

[`T1685`](https://attack.mitre.org/techniques/T1685/) (5) · [`T1112`](https://attack.mitre.org/techniques/T1112/) (5) · [`T1070.003`](https://attack.mitre.org/techniques/T1070/003/) (1) · [`T1070`](https://attack.mitre.org/techniques/T1070/) (1) · [`T1113`](https://attack.mitre.org/techniques/T1113/) (1)

## Rules (14)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Folder Removed From Exploit Guard ProtectedFolders List - Registry | 🟠 high | 75 | `T1685` | [`folder_removed_from_exploit_guard_protectedfolders_list_registry.yaml`](./folder_removed_from_exploit_guard_protectedfolders_list_registry.yaml) |
| Potential NetWire RAT Activity - Registry | 🟠 high | 75 | `T1112` | [`potential_netwire_rat_activity_registry.yaml`](./potential_netwire_rat_activity_registry.yaml) |
| Potential Ursnif Malware Activity - Registry | 🟠 high | 75 | `T1112` | [`potential_ursnif_malware_activity_registry.yaml`](./potential_ursnif_malware_activity_registry.yaml) |
| Removal Of AMSI Provider Registry Keys | 🟠 high | 75 | `T1685` | [`removal_of_amsi_provider_registry_keys.yaml`](./removal_of_amsi_provider_registry_keys.yaml) |
| RunMRU Registry Key Deletion - Registry | 🟠 high | 75 | `T1070.003` | [`runmru_registry_key_deletion_registry.yaml`](./runmru_registry_key_deletion_registry.yaml) |
| Terminal Server Client Connection History Cleared - Registry | 🟠 high | 75 | `T1070`, `T1112` | [`terminal_server_client_connection_history_cleared_registry.yaml`](./terminal_server_client_connection_history_cleared_registry.yaml) |
| Windows Credential Guard Related Registry Value Deleted - Registry | 🟠 high | 75 | `T1685` | [`windows_credential_guard_related_registry_value_deleted_registry.yaml`](./windows_credential_guard_related_registry_value_deleted_registry.yaml) |
| Windows Modify Registry Delete Firewall Rules | 🟠 high | 64 | `T1112` | [`windows_modify_registry_delete_firewall_rules.yaml`](./windows_modify_registry_delete_firewall_rules.yaml) |
| Delete Defender Scan ShellEx Context Menu Registry Key | 🟡 medium | 50 | — | [`delete_defender_scan_shellex_context_menu_registry_key.yaml`](./delete_defender_scan_shellex_context_menu_registry_key.yaml) |
| Potential Persistence Via Disk Cleanup Handler - Registry | 🟡 medium | 50 | — | [`potential_persistence_via_disk_cleanup_handler_registry.yaml`](./potential_persistence_via_disk_cleanup_handler_registry.yaml) |
| Removal Of Index Value to Hide Schedule Task - Registry | 🟡 medium | 50 | `T1685` | [`removal_of_index_value_to_hide_schedule_task_registry.yaml`](./removal_of_index_value_to_hide_schedule_task_registry.yaml) |
| Removal of Potential COM Hijacking Registry Keys | 🟡 medium | 50 | `T1112` | [`removal_of_potential_com_hijacking_registry_keys.yaml`](./removal_of_potential_com_hijacking_registry_keys.yaml) |
| Removal Of SD Value to Hide Schedule Task - Registry | 🟡 medium | 50 | `T1685` | [`removal_of_sd_value_to_hide_schedule_task_registry.yaml`](./removal_of_sd_value_to_hide_schedule_task_registry.yaml) |
| Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted | 🟡 medium | 50 | `T1113` | [`windows_recall_feature_enabled_disableaidataanalysis_value_deleted.yaml`](./windows_recall_feature_enabled_disableaidataanalysis_value_deleted.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
