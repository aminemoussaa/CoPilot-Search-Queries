# auditd

Linux `auditd` records shipped by the Wazuh agent (`data_audit_*` fields).

**16 rules** — high 6, medium 10

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| Auditing Configuration Changes on Linux Host | high | T1685 | [auditing_configuration_changes_on_linux_host.yaml](./auditing_configuration_changes_on_linux_host.yaml) |
| BPFDoor Abnormal Process ID or Lock File Accessed | high | T1106, T1059 | [bpfdoor_abnormal_process_id_or_lock_file_accessed.yaml](./bpfdoor_abnormal_process_id_or_lock_file_accessed.yaml) |
| Linux Keylogging with Pam.d | high | T1003, T1056.001 | [linux_keylogging_with_pam_d.yaml](./linux_keylogging_with_pam_d.yaml) |
| Loading of Kernel Module via Insmod | high | T1547.006 | [loading_of_kernel_module_via_insmod.yaml](./loading_of_kernel_module_via_insmod.yaml) |
| Logging Configuration Changes on Linux Host | high | T1685 | [logging_configuration_changes_on_linux_host.yaml](./logging_configuration_changes_on_linux_host.yaml) |
| Modification of ld.so.preload | high | T1574.006 | [modification_of_ld_so_preload.yaml](./modification_of_ld_so_preload.yaml) |
| Creation Of An User Account | medium | T1136.001 | [creation_of_an_user_account.yaml](./creation_of_an_user_account.yaml) |
| Data Exfiltration with Wget | medium | T1048.003 | [data_exfiltration_with_wget.yaml](./data_exfiltration_with_wget.yaml) |
| Masquerading as Linux Crond Process | medium | T1036.003 | [masquerading_as_linux_crond_process.yaml](./masquerading_as_linux_crond_process.yaml) |
| Modify System Firewall | medium | T1686 | [modify_system_firewall.yaml](./modify_system_firewall.yaml) |
| Potential Abuse of Linux Magic System Request Key | medium | T1059.004, T1529, T1489, T1499 | [potential_abuse_of_linux_magic_system_request_key.yaml](./potential_abuse_of_linux_magic_system_request_key.yaml) |
| Program Executions in Suspicious Folders | medium | T1587, T1584 | [program_executions_in_suspicious_folders.yaml](./program_executions_in_suspicious_folders.yaml) |
| Remove Immutable File Attribute - Auditd | medium | T1222.002 | [remove_immutable_file_attribute_auditd.yaml](./remove_immutable_file_attribute_auditd.yaml) |
| Suspicious C2 Activities | medium | — | [suspicious_c2_activities.yaml](./suspicious_c2_activities.yaml) |
| Suspicious Commands Linux | medium | T1059.004 | [suspicious_commands_linux.yaml](./suspicious_commands_linux.yaml) |
| Unix Shell Configuration Modification | medium | T1546.004 | [unix_shell_configuration_modification.yaml](./unix_shell_configuration_modification.yaml) |
