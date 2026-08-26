# Web Server Access Logs

**Platform** `Web` · **Log source** Nginx / Apache access logs · **2 rules**

Requests to internet-facing applications, used to catch exploitation of public-facing services and scripted tooling by user agent.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟡 medium 2 |
| Status | production 2 |
| ATT&CK techniques | 4 distinct |
| Provenance | 0 Sigma-derived, 2 written for this repo |

## Onboarding

Ship access logs with the Wazuh agent so they decode into `data_url`, `data_protocol` and `full_log`.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `decoder_name` | 2 |
| `data_protocol` | 1 |
| `data_url` | 1 |
| `full_log` | 1 |

## Top ATT&CK techniques

[`T1133`](https://attack.mitre.org/techniques/T1133/) (1) · [`T1190`](https://attack.mitre.org/techniques/T1190/) (1) · [`T1505.003`](https://attack.mitre.org/techniques/T1505/003/) (1) · [`T1071.001`](https://attack.mitre.org/techniques/T1071/001/) (1)

## Rules (2)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Exploit Public Facing Application via Apache Commons Text | 🟡 medium | 60 | `T1133`, `T1190`, `T1505.003` | [`exploit_public_facing_application_via_apache_commons_text.yaml`](./exploit_public_facing_application_via_apache_commons_text.yaml) |
| HTTP Scripting Tool User Agent | 🟡 medium | 40 | `T1071.001` | [`http_scripting_tool_user_agent.yaml`](./http_scripting_tool_user_agent.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
