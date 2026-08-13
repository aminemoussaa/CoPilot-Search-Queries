# entra id

Office 365 Management Activity API, `AzureActiveDirectory` workload — Entra ID sign-ins, directory and federation changes.

**4 rules** — high 2, medium 2

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| Azure Login Bypassing Conditional Access Policies | high | T1078 | [azure_login_bypassing_conditional_access_policies.yaml](./azure_login_bypassing_conditional_access_policies.yaml) |
| Disabling Multi Factor Authentication | high | T1556.006 | [disabling_multi_factor_authentication.yaml](./disabling_multi_factor_authentication.yaml) |
| New Federated Domain Added | medium | T1484.002 | [new_federated_domain_added.yaml](./new_federated_domain_added.yaml) |
| Suspicious Email Delivered In Microsoft 365 | medium | T1566.001, T1566.002 | [suspicious_email_delivered_in_microsoft_365.yaml](./suspicious_email_delivered_in_microsoft_365.yaml) |
