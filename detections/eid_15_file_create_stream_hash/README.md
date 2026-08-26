# Sysmon Event ID 15 — FileCreateStreamHash

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **8 rules**

Alternate data stream creation, including the `Zone.Identifier` mark-of-the-web that reveals a file's download origin.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 5 · 🟡 medium 3 |
| Status | experimental 8 |
| ATT&CK techniques | 1 distinct |
| Provenance | 8 Sigma-derived, 0 written for this repo |
| Event IDs queried | `15` (8) |

## Onboarding

Enable `FileCreateStreamHash` in the Sysmon config for the extensions you care about.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 8 |
| `data_win_eventdata_contents` | 6 |
| `data_win_eventdata_targetFilename` | 6 |
| `data_win_eventdata_image` | 2 |
| `data_win_eventdata_hash` | 1 |

## Top ATT&CK techniques

[`T1564.004`](https://attack.mitre.org/techniques/T1564/004/) (5)

## Rules (8)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Exports Registry Key To an Alternate Data Stream | 🟠 high | 75 | `T1564.004` | [`exports_registry_key_to_an_alternate_data_stream.yaml`](./exports_registry_key_to_an_alternate_data_stream.yaml) |
| Potential Suspicious Winget Package Installation | 🟠 high | 75 | — | [`potential_suspicious_winget_package_installation.yaml`](./potential_suspicious_winget_package_installation.yaml) |
| Potentially Suspicious File Download From ZIP TLD | 🟠 high | 75 | — | [`potentially_suspicious_file_download_from_zip_tld.yaml`](./potentially_suspicious_file_download_from_zip_tld.yaml) |
| Suspicious File Download From File Sharing Websites -  File Stream | 🟠 high | 75 | `T1564.004` | [`suspicious_file_download_from_file_sharing_websites_file_stream.yaml`](./suspicious_file_download_from_file_sharing_websites_file_stream.yaml) |
| Unusual File Download from Direct IP Address | 🟠 high | 75 | `T1564.004` | [`unusual_file_download_from_direct_ip_address.yaml`](./unusual_file_download_from_direct_ip_address.yaml) |
| Creation Of a Suspicious ADS File Outside a Browser Download | 🟡 medium | 50 | — | [`creation_of_a_suspicious_ads_file_outside_a_browser_download.yaml`](./creation_of_a_suspicious_ads_file_outside_a_browser_download.yaml) |
| Hidden Executable In NTFS Alternate Data Stream | 🟡 medium | 50 | `T1564.004` | [`hidden_executable_in_ntfs_alternate_data_stream.yaml`](./hidden_executable_in_ntfs_alternate_data_stream.yaml) |
| Unusual File Download From File Sharing Websites - File Stream | 🟡 medium | 50 | `T1564.004` | [`unusual_file_download_from_file_sharing_websites_file_stream.yaml`](./unusual_file_download_from_file_sharing_websites_file_stream.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
