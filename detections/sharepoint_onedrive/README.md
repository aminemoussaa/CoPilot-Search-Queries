# SharePoint & OneDrive

**Platform** `Cloud` · **Log source** Office 365 Management Activity API — `SharePoint` / `OneDrive` workloads · **4 rules**

File-plane activity: mass download, mass deletion and mass external sharing — the strongest data-exfiltration signals in M365.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 4 |
| Status | production 4 |
| ATT&CK techniques | 5 distinct |
| Provenance | 0 Sigma-derived, 4 written for this repo |

## Onboarding

Subscribe the Wazuh `office365` module to the `SharePoint` and `OneDrive` workloads.

## Top ATT&CK techniques

[`T1567`](https://attack.mitre.org/techniques/T1567/) (2) · [`T1485`](https://attack.mitre.org/techniques/T1485/) (2) · [`T1070`](https://attack.mitre.org/techniques/T1070/) (2) · [`T1213.002`](https://attack.mitre.org/techniques/T1213/002/) (1) · [`T1213`](https://attack.mitre.org/techniques/T1213/) (1)

## Rules (4)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| M365 Mass External Sharing | 🟠 high | 70 | `T1213.002`, `T1567` | [`m365_mass_external_sharing.yaml`](./m365_mass_external_sharing.yaml) |
| M365 Mass File Deletion | 🟠 high | 80 | `T1485`, `T1070` | [`m365_mass_file_deletion.yaml`](./m365_mass_file_deletion.yaml) |
| M365 Mass File Download | 🟠 high | 75 | `T1213`, `T1567` | [`m365_mass_file_download.yaml`](./m365_mass_file_download.yaml) |
| M365 Suspicious File Deletion | 🟠 high | 65 | `T1485`, `T1070` | [`m365_suspicious_file_deletion.yaml`](./m365_suspicious_file_deletion.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
