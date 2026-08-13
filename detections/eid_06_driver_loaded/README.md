# Sysmon Event ID 6 — Driver Loaded

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **7 rules**

Kernel driver loads with signature status — the primary source for bring-your-own-vulnerable-driver (BYOVD) detection.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 5 · 🟡 medium 2 |
| Status | experimental 7 |
| ATT&CK techniques | 5 distinct |
| Provenance | 7 Sigma-derived, 0 written for this repo |
| Event IDs queried | `6` (7) |

## Onboarding

Enable `DriverLoad` in the Sysmon config. Low volume, high value; leave it unfiltered.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_eventdata_imageLoaded` | 7 |
| `data_win_system_eventID` | 7 |
| `data_win_eventdata_hashes` | 5 |

## Top ATT&CK techniques

[`T1543.003`](https://attack.mitre.org/techniques/T1543/003/) (4) · [`T1543`](https://attack.mitre.org/techniques/T1543/) (2) · [`T1068`](https://attack.mitre.org/techniques/T1068/) (1) · [`T1599.001`](https://attack.mitre.org/techniques/T1599/001/) (1) · [`T1557.001`](https://attack.mitre.org/techniques/T1557/001/) (1)

## Rules (7)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Driver Load From A Temporary Directory | 🟠 high | 75 | `T1543.003` | [`driver_load_from_a_temporary_directory.yaml`](./driver_load_from_a_temporary_directory.yaml) |
| PUA - Process Hacker Driver Load | 🟠 high | 75 | `T1543` | [`pua_process_hacker_driver_load.yaml`](./pua_process_hacker_driver_load.yaml) |
| Vulnerable HackSys Extreme Vulnerable Driver Load | 🟠 high | 75 | `T1543.003` | [`vulnerable_hacksys_extreme_vulnerable_driver_load.yaml`](./vulnerable_hacksys_extreme_vulnerable_driver_load.yaml) |
| Vulnerable WinRing0 Driver Load | 🟠 high | 75 | `T1543.003` | [`vulnerable_winring0_driver_load.yaml`](./vulnerable_winring0_driver_load.yaml) |
| WinDivert Driver Load | 🟠 high | 75 | `T1599.001`, `T1557.001` | [`windivert_driver_load.yaml`](./windivert_driver_load.yaml) |
| Malicious Driver Load By Name | 🟡 medium | 50 | `T1543.003`, `T1068` | [`malicious_driver_load_by_name.yaml`](./malicious_driver_load_by_name.yaml) |
| PUA - System Informer Driver Load | 🟡 medium | 50 | `T1543` | [`pua_system_informer_driver_load.yaml`](./pua_system_informer_driver_load.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
