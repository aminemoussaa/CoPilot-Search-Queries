# Microsoft 365 Threat Intelligence

**Platform** `Cloud` · **Log source** Office 365 Management Activity API — `ThreatIntelligence` workload · **12 rules**

Verdicts raised by Defender for Office 365: malicious mail, URLs and attachments detected in the tenant.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟡 medium 12 |
| Status | experimental 12 |
| ATT&CK techniques | 7 distinct |
| Provenance | 12 Sigma-derived, 0 written for this repo |

## Onboarding

Subscribe the Wazuh `office365` module to the `ThreatIntelligence` workload. Requires a Defender for Office 365 licence.

## Top ATT&CK techniques

[`T1573`](https://attack.mitre.org/techniques/T1573/) (2) · [`T1078`](https://attack.mitre.org/techniques/T1078/) (2) · [`T1114`](https://attack.mitre.org/techniques/T1114/) (2) · [`T1537`](https://attack.mitre.org/techniques/T1537/) (1) · [`T1486`](https://attack.mitre.org/techniques/T1486/) (1) · [`T1485`](https://attack.mitre.org/techniques/T1485/) (1) · [`T1199`](https://attack.mitre.org/techniques/T1199/) (1)

## Rules (12)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Activity from Anonymous IP Addresses | 🟡 medium | 50 | `T1573` | [`activity_from_anonymous_ip_addresses.yaml`](./activity_from_anonymous_ip_addresses.yaml) |
| Activity from Infrequent Country | 🟡 medium | 50 | `T1573` | [`activity_from_infrequent_country.yaml`](./activity_from_infrequent_country.yaml) |
| Activity Performed by Terminated User | 🟡 medium | 50 | — | [`activity_performed_by_terminated_user.yaml`](./activity_performed_by_terminated_user.yaml) |
| Data Exfiltration to Unsanctioned Apps | 🟡 medium | 50 | `T1537` | [`data_exfiltration_to_unsanctioned_apps.yaml`](./data_exfiltration_to_unsanctioned_apps.yaml) |
| Logon from a Risky IP Address | 🟡 medium | 50 | `T1078` | [`logon_from_a_risky_ip_address.yaml`](./logon_from_a_risky_ip_address.yaml) |
| Microsoft 365 - Impossible Travel Activity | 🟡 medium | 50 | `T1078` | [`microsoft_365_impossible_travel_activity.yaml`](./microsoft_365_impossible_travel_activity.yaml) |
| Microsoft 365 - Potential Ransomware Activity | 🟡 medium | 50 | `T1486` | [`microsoft_365_potential_ransomware_activity.yaml`](./microsoft_365_potential_ransomware_activity.yaml) |
| Microsoft 365 - Unusual Volume of File Deletion | 🟡 medium | 50 | `T1485` | [`microsoft_365_unusual_volume_of_file_deletion.yaml`](./microsoft_365_unusual_volume_of_file_deletion.yaml) |
| Microsoft 365 - User Restricted from Sending Email | 🟡 medium | 50 | `T1199` | [`microsoft_365_user_restricted_from_sending_email.yaml`](./microsoft_365_user_restricted_from_sending_email.yaml) |
| PST Export Alert Using eDiscovery Alert | 🟡 medium | 50 | `T1114` | [`pst_export_alert_using_ediscovery_alert.yaml`](./pst_export_alert_using_ediscovery_alert.yaml) |
| PST Export Alert Using New-ComplianceSearchAction | 🟡 medium | 50 | `T1114` | [`pst_export_alert_using_new_compliancesearchaction.yaml`](./pst_export_alert_using_new_compliancesearchaction.yaml) |
| Suspicious OAuth App File Download Activities | 🟡 medium | 50 | — | [`suspicious_oauth_app_file_download_activities.yaml`](./suspicious_oauth_app_file_download_activities.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
