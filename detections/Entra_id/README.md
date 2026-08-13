# Microsoft Entra ID (Azure AD)

**Platform** `Cloud` · **Log source** Office 365 Management Activity API — `AzureActiveDirectory` workload · **4 rules**

Identity-plane activity: conditional access bypass, MFA being disabled, federation and domain changes, and other tenant-level identity backdoors.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 2 · 🟡 medium 2 |
| Status | experimental 4 |
| ATT&CK techniques | 5 distinct |
| Provenance | 4 Sigma-derived, 0 written for this repo |

## Onboarding

Register an Entra ID application with Office 365 Management Activity API permissions and configure the Wazuh `office365` module to subscribe to the `AzureActiveDirectory` workload.

## Top ATT&CK techniques

[`T1078`](https://attack.mitre.org/techniques/T1078/) (1) · [`T1556.006`](https://attack.mitre.org/techniques/T1556/006/) (1) · [`T1484.002`](https://attack.mitre.org/techniques/T1484/002/) (1) · [`T1566.001`](https://attack.mitre.org/techniques/T1566/001/) (1) · [`T1566.002`](https://attack.mitre.org/techniques/T1566/002/) (1)

## Rules (4)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Azure Login Bypassing Conditional Access Policies | 🟠 high | 75 | `T1078` | [`azure_login_bypassing_conditional_access_policies.yaml`](./azure_login_bypassing_conditional_access_policies.yaml) |
| Disabling Multi Factor Authentication | 🟠 high | 75 | `T1556.006` | [`disabling_multi_factor_authentication.yaml`](./disabling_multi_factor_authentication.yaml) |
| New Federated Domain Added | 🟡 medium | 50 | `T1484.002` | [`new_federated_domain_added.yaml`](./new_federated_domain_added.yaml) |
| Suspicious Email Delivered In Microsoft 365 | 🟡 medium | 50 | `T1566.001`, `T1566.002` | [`suspicious_email_delivered_in_microsoft_365.yaml`](./suspicious_email_delivered_in_microsoft_365.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
