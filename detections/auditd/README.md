# Linux Auditd

**Platform** `Linux` · **Log source** Linux `auditd` · **16 rules**

Kernel audit records — syscall execution, file access and privilege changes — decoded into `data_audit_*` fields.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🟠 high 6 · 🟡 medium 10 |
| Status | experimental 16 |
| ATT&CK techniques | 19 distinct |
| Provenance | 16 Sigma-derived, 0 written for this repo |

## Onboarding

Install `auditd`, load rules covering the syscalls and paths you want, and enable the Wazuh agent's auditd integration.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_audit_type` | 15 |
| `data_audit_file_name` | 7 |
| `data_audit_execve_a1` | 5 |
| `data_audit_execve_a0` | 5 |
| `data_audit_exe` | 3 |
| `data_audit_command` | 1 |
| `data_audit_execve_a2` | 1 |
| `data_audit_key` | 1 |

## Top ATT&CK techniques

[`T1685`](https://attack.mitre.org/techniques/T1685/) (2) · [`T1059.004`](https://attack.mitre.org/techniques/T1059/004/) (2) · [`T1106`](https://attack.mitre.org/techniques/T1106/) (1) · [`T1059`](https://attack.mitre.org/techniques/T1059/) (1) · [`T1136.001`](https://attack.mitre.org/techniques/T1136/001/) (1) · [`T1048.003`](https://attack.mitre.org/techniques/T1048/003/) (1) · [`T1003`](https://attack.mitre.org/techniques/T1003/) (1) · [`T1056.001`](https://attack.mitre.org/techniques/T1056/001/) (1)

## Rules (16)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Auditing Configuration Changes on Linux Host | 🟠 high | 75 | `T1685` | [`auditing_configuration_changes_on_linux_host.yaml`](./auditing_configuration_changes_on_linux_host.yaml) |
| BPFDoor Abnormal Process ID or Lock File Accessed | 🟠 high | 75 | `T1106`, `T1059` | [`bpfdoor_abnormal_process_id_or_lock_file_accessed.yaml`](./bpfdoor_abnormal_process_id_or_lock_file_accessed.yaml) |
| Linux Keylogging with Pam.d | 🟠 high | 75 | `T1003`, `T1056.001` | [`linux_keylogging_with_pam_d.yaml`](./linux_keylogging_with_pam_d.yaml) |
| Loading of Kernel Module via Insmod | 🟠 high | 75 | `T1547.006` | [`loading_of_kernel_module_via_insmod.yaml`](./loading_of_kernel_module_via_insmod.yaml) |
| Logging Configuration Changes on Linux Host | 🟠 high | 75 | `T1685` | [`logging_configuration_changes_on_linux_host.yaml`](./logging_configuration_changes_on_linux_host.yaml) |
| Modification of ld.so.preload | 🟠 high | 75 | `T1574.006` | [`modification_of_ld_so_preload.yaml`](./modification_of_ld_so_preload.yaml) |
| Creation Of An User Account | 🟡 medium | 50 | `T1136.001` | [`creation_of_an_user_account.yaml`](./creation_of_an_user_account.yaml) |
| Data Exfiltration with Wget | 🟡 medium | 50 | `T1048.003` | [`data_exfiltration_with_wget.yaml`](./data_exfiltration_with_wget.yaml) |
| Masquerading as Linux Crond Process | 🟡 medium | 50 | `T1036.003` | [`masquerading_as_linux_crond_process.yaml`](./masquerading_as_linux_crond_process.yaml) |
| Modify System Firewall | 🟡 medium | 50 | `T1686` | [`modify_system_firewall.yaml`](./modify_system_firewall.yaml) |
| Potential Abuse of Linux Magic System Request Key | 🟡 medium | 50 | `T1059.004`, `T1529`, `T1489`… | [`potential_abuse_of_linux_magic_system_request_key.yaml`](./potential_abuse_of_linux_magic_system_request_key.yaml) |
| Program Executions in Suspicious Folders | 🟡 medium | 50 | `T1587`, `T1584` | [`program_executions_in_suspicious_folders.yaml`](./program_executions_in_suspicious_folders.yaml) |
| Remove Immutable File Attribute - Auditd | 🟡 medium | 50 | `T1222.002` | [`remove_immutable_file_attribute_auditd.yaml`](./remove_immutable_file_attribute_auditd.yaml) |
| Suspicious C2 Activities | 🟡 medium | 50 | — | [`suspicious_c2_activities.yaml`](./suspicious_c2_activities.yaml) |
| Suspicious Commands Linux | 🟡 medium | 50 | `T1059.004` | [`suspicious_commands_linux.yaml`](./suspicious_commands_linux.yaml) |
| Unix Shell Configuration Modification | 🟡 medium | 50 | `T1546.004` | [`unix_shell_configuration_modification.yaml`](./unix_shell_configuration_modification.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
