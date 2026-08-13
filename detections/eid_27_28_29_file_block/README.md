# Sysmon Event IDs 27 / 28 / 29 — File Block & Executable Detected

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **3 rules**

Blocked executable writes (27), blocked file shredding (28) and executable file detection (29) — Sysmon acting as a preventive control.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 2 · 🟡 medium 1 |
| Status | experimental 3 |
| ATT&CK techniques | 0 distinct |
| Provenance | 3 Sigma-derived, 0 written for this repo |
| Event IDs queried | `27` (1), `28` (1), `29` (1) |

## Onboarding

Requires Sysmon 14+ with `FileBlockExecutable` / `FileBlockShredding` configured. These block as well as log, so roll out carefully.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 3 |

## Rules (3)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Sysmon Blocked Executable | 🟠 high | 75 | — | [`sysmon_blocked_executable.yaml`](./sysmon_blocked_executable.yaml) |
| Sysmon Blocked File Shredding | 🟠 high | 75 | — | [`sysmon_blocked_file_shredding.yaml`](./sysmon_blocked_file_shredding.yaml) |
| Sysmon File Executable Creation Detected | 🟡 medium | 50 | — | [`sysmon_file_executable_creation_detected.yaml`](./sysmon_file_executable_creation_detected.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
