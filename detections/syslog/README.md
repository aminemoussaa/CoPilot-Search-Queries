# Linux Syslog & auth.log

**Platform** `Linux` · **Log source** Linux `syslog` / `auth.log` · **94 rules**

Rules that match the raw log line via `full_log`, covering distributions and daemons without structured decoders. Broad coverage, coarser fidelity than Tetragon or auditd.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🔴 critical 3 · 🟠 high 23 · 🟡 medium 42 · 🔵 low 26 |
| Status | production 94 |
| ATT&CK techniques | 46 distinct |
| Provenance | 0 Sigma-derived, 94 written for this repo |

## Onboarding

Point the Wazuh agent at `/var/log/auth.log`, `/var/log/secure` and `/var/log/syslog`. These rules explicitly exclude Windows events, so no extra filtering is needed.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `rule_groups` | 94 |
| `full_log` | 90 |
| `location` | 7 |
| `default_field` | 2 |
| `message` | 1 |

## Top ATT&CK techniques

[`T1548.003`](https://attack.mitre.org/techniques/T1548/003/) (23) · [`T1485`](https://attack.mitre.org/techniques/T1485/) (9) · [`T1059.004`](https://attack.mitre.org/techniques/T1059/004/) (4) · [`T1053.003`](https://attack.mitre.org/techniques/T1053/003/) (4) · [`T1489`](https://attack.mitre.org/techniques/T1489/) (4) · [`T1562.001`](https://attack.mitre.org/techniques/T1562/001/) (3) · [`T1083`](https://attack.mitre.org/techniques/T1083/) (3) · [`T1081`](https://attack.mitre.org/techniques/T1081/) (3)

## Rules (94)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Linux Auditd Data Destruction Command | 🔴 critical | 90 | `T1485` | [`linux_auditd_data_destruction_using_no_preserve_root.yaml`](./linux_auditd_data_destruction_using_no_preserve_root.yaml) |
| Linux Critical Directory Deletion | 🔴 critical | 95 | `T1485` | [`linux_deleting_critical_directory_using_rm_command.yaml`](./linux_deleting_critical_directory_using_rm_command.yaml) |
| Linux Medusa Rootkit | 🔴 critical | 62 | `T1014`, `T1589.001` | [`linux_medusa_rootkit.yaml`](./linux_medusa_rootkit.yaml) |
| Linux Auditd Apt Privilege Escalation | 🟠 high | 72 | `T1548.003` | [`linux_apt_privilege_escalation.yaml`](./linux_apt_privilege_escalation.yaml) |
| Linux Auditd Apt-Get Privilege Escalation | 🟠 high | 72 | `T1548.003` | [`linux_apt_get_privilege_escalation.yaml`](./linux_apt_get_privilege_escalation.yaml) |
| Linux Auditd Daemon Abort | 🟠 high | 81 | `T1562.001`, `T1489` | [`linux_auditd_auditd_daemon_abort.yaml`](./linux_auditd_auditd_daemon_abort.yaml) |
| Linux Auditd Data Destruction Command | 🟠 high | 90 | `T1485` | [`linux_auditd_data_destruction_command.yaml`](./linux_auditd_data_destruction_command.yaml) |
| Linux Auditd Preload Hijack Library Calls | 🟠 high | 81 | `T1574.006` | [`linux_auditd_preload_hijack_library_calls.yaml`](./linux_auditd_preload_hijack_library_calls.yaml) |
| Linux Auditd SSH Config Keys Deletion | 🟠 high | 72 | `T1070.004`, `T1485` | [`linux_account_manipulation_of_ssh_config_and_keys.yaml`](./linux_account_manipulation_of_ssh_config_and_keys.yaml) |
| Linux Cron File Deletion | 🟠 high | 85 | `T1485` | [`linux_deletion_of_cron_jobs.yaml`](./linux_deletion_of_cron_jobs.yaml) |
| Linux DD File Overwrite | 🟠 high | 64 | `T1485` | [`linux_dd_file_overwrite.yaml`](./linux_dd_file_overwrite.yaml) |
| Linux Disable Or Modify System Firewall | 🟠 high | 64 | `T1562.004` | [`linux_auditd_disable_or_modify_system_firewall.yaml`](./linux_auditd_disable_or_modify_system_firewall.yaml) |
| Linux Init.d Script Deletion | 🟠 high | 85 | `T1485` | [`linux_deletion_of_init_daemon_script.yaml`](./linux_deletion_of_init_daemon_script.yaml) |
| Linux Kernel Driver Activity Detection | 🟠 high | 65 | `T1014` | [`linux_file_created_in_kernel_driver_directory.yaml`](./linux_file_created_in_kernel_driver_directory.yaml) |
| Linux Kernel Module Using Rmmod Utility | 🟠 high | 72 | `T1547.006` | [`linux_auditd_kernel_module_using_rmmod_utility.yaml`](./linux_auditd_kernel_module_using_rmmod_utility.yaml) |
| Linux pkexec Privilege Escalation | 🟠 high | 56 | `T1068`, `T1078` | [`cve_2021_4034.yaml`](./cve_2021_4034.yaml) |
| Linux Preload Hijack Via Preload File | 🟠 high | 81 | `T1574.006` | [`linux_auditd_preload_hijack_via_preload_file.yaml`](./linux_auditd_preload_hijack_via_preload_file.yaml) |
| Linux Private Keys and Certificate Enumeration | 🟠 high | 64 | `T1552.004` | [`linux_auditd_private_keys_and_certificate_enumeration.yaml`](./linux_auditd_private_keys_and_certificate_enumeration.yaml) |
| Linux Sudoers Tmp File Creation | 🟠 high | 72 | `T1548.003` | [`linux_sudoers_tmp_file_creation.yaml`](./linux_sudoers_tmp_file_creation.yaml) |
| Linux Suspicious React or Next.js Child Process | 🟠 high | 70 | `T1190`, `T1059.004` | [`cve_2025_55182.yaml`](./cve_2025_55182.yaml) |
| Linux Suspicious React or Next.js Child Process | 🟠 high | 70 | `T1190`, `T1059.004` | [`cve_2025_66478.yaml`](./cve_2025_66478.yaml) |
| Linux Swapoff Detection | 🟠 high | 60 | `T1217` | [`linux_auditd_hardware_addition_swapoff.yaml`](./linux_auditd_hardware_addition_swapoff.yaml) |
| Linux Unix Shell Configuration Modification | 🟠 high | 64 | `T1546.004` | [`linux_auditd_unix_shell_configuration_modification.yaml`](./linux_auditd_unix_shell_configuration_modification.yaml) |
| Suspicious Emacs Eval Execution via Sudo | 🟠 high | 70 | `T1059` | [`linux_emacs_privilege_escalation.yaml`](./linux_emacs_privilege_escalation.yaml) |
| Suspicious SSL Certificate Deletion | 🟠 high | 80 | `T1485` | [`linux_deletion_of_ssl_certificate.yaml`](./linux_deletion_of_ssl_certificate.yaml) |
| Suspicious Systemd Service Deletion | 🟠 high | 85 | `T1485` | [`linux_deletion_of_services.yaml`](./linux_deletion_of_services.yaml) |
| Linux Append Cronjob Entry On Existing Cronjob File | 🟡 medium | 49 | `T1053.003` | [`linux_auditd_possible_append_cronjob_entry_on_existing_cronjob_file.yaml`](./linux_auditd_possible_append_cronjob_entry_on_existing_cronjob_file.yaml) |
| Linux Auditd Add User | 🟡 medium | 64 | `T1136.001` | [`linux_auditd_add_user_account_type.yaml`](./linux_auditd_add_user_account_type.yaml) |
| Linux Auditd At Allow Deny Config File Modification | 🟡 medium | 49 | `T1053.002` | [`linux_at_allow_config_file_creation.yaml`](./linux_at_allow_config_file_creation.yaml) |
| Linux Auditd Base64 Decode | 🟡 medium | 45 | `T1027`, `T1140` | [`linux_auditd_base64_decode_files.yaml`](./linux_auditd_base64_decode_files.yaml) |
| Linux Auditd Chown To Root | 🟡 medium | 49 | `T1222.002` | [`linux_auditd_change_file_owner_to_root.yaml`](./linux_auditd_change_file_owner_to_root.yaml) |
| Linux Auditd Clipboard Data Copy | 🟡 medium | 50 | `T1115` | [`linux_auditd_clipboard_data_copy.yaml`](./linux_auditd_clipboard_data_copy.yaml) |
| Linux Auditd Crontab Directory Files Modification | 🟡 medium | 49 | `T1053.003` | [`linux_add_files_in_known_crontab_directories.yaml`](./linux_add_files_in_known_crontab_directories.yaml) |
| Linux Auditd Daemon Shutdown | 🟡 medium | 50 | `T1562.001` | [`linux_auditd_auditd_daemon_shutdown.yaml`](./linux_auditd_auditd_daemon_shutdown.yaml) |
| Linux Auditd Data Transfer Size Limits Via Split | 🟡 medium | 49 | `T1030` | [`linux_auditd_data_transfer_size_limits_via_split.yaml`](./linux_auditd_data_transfer_size_limits_via_split.yaml) |
| Linux Auditd Osquery Service Stop | 🟡 medium | 64 | `T1489` | [`linux_auditd_osquery_service_stop.yaml`](./linux_auditd_osquery_service_stop.yaml) |
| Linux c89 Privilege Escalation | 🟡 medium | 30 | `T1548.003` | [`linux_c89_privilege_escalation.yaml`](./linux_c89_privilege_escalation.yaml) |
| Linux c99 Privilege Escalation | 🟡 medium | 30 | `T1548.003` | [`linux_c99_privilege_escalation.yaml`](./linux_c99_privilege_escalation.yaml) |
| Linux Credential Discovery | 🟡 medium | 50 | `T1081` | [`linux_auditd_find_credentials_from_password_stores.yaml`](./linux_auditd_find_credentials_from_password_stores.yaml) |
| Linux doas Execution Detection | 🟡 medium | 50 | `T1548` | [`linux_auditd_doas_tool_execution.yaml`](./linux_auditd_doas_tool_execution.yaml) |
| Linux Edit Cron Table Parameter | 🟡 medium | 64 | `T1053.003` | [`linux_auditd_edit_cron_table_parameter.yaml`](./linux_auditd_edit_cron_table_parameter.yaml) |
| Linux File Attribute Modification Detection | 🟡 medium | 45 | `T1090` | [`linux_auditd_file_permissions_modification_via_chattr.yaml`](./linux_auditd_file_permissions_modification_via_chattr.yaml) |
| Linux File Creation In Profile Directory | 🟡 medium | 56 | `T1546.004` | [`linux_file_creation_in_profile_directory.yaml`](./linux_file_creation_in_profile_directory.yaml) |
| Linux File Discovery Detection | 🟡 medium | 45 | `T1083` | [`linux_auditd_file_and_directory_discovery.yaml`](./linux_auditd_file_and_directory_discovery.yaml) |
| Linux File Permission Modification Detection | 🟡 medium | 50 | `T1098` | [`linux_auditd_file_permission_modification_via_chmod.yaml`](./linux_auditd_file_permission_modification_via_chmod.yaml) |
| Linux Gdrive Binary Activity | 🟡 medium | 49 | `T1567` | [`linux_gdrive_binary_activity.yaml`](./linux_gdrive_binary_activity.yaml) |
| Linux Gem Privilege Escalation | 🟡 medium | 30 | `T1548.003` | [`linux_gem_privilege_escalation.yaml`](./linux_gem_privilege_escalation.yaml) |
| Linux GNU Awk Privilege Escalation | 🟡 medium | 30 | `T1548.003` | [`linux_gnu_awk_privilege_escalation.yaml`](./linux_gnu_awk_privilege_escalation.yaml) |
| Linux Hidden File/Directory Creation | 🟡 medium | 50 | `T1158` | [`linux_auditd_hidden_files_and_directories_creation.yaml`](./linux_auditd_hidden_files_and_directories_creation.yaml) |
| Linux Init Script Persistence Detection | 🟡 medium | 55 | `T1037`, `T1547` | [`linux_file_creation_in_init_boot_directory.yaml`](./linux_file_creation_in_init_boot_directory.yaml) |
| Linux MySQL Privilege Escalation | 🟡 medium | 30 | `T1548.003` | [`linux_mysql_privilege_escalation.yaml`](./linux_mysql_privilege_escalation.yaml) |
| Linux OpenVPN Privilege Escalation | 🟡 medium | 30 | `T1548.003` | [`linux_openvpn_privilege_escalation.yaml`](./linux_openvpn_privilege_escalation.yaml) |
| Linux Password Vault Discovery | 🟡 medium | 50 | `T1081` | [`linux_auditd_find_credentials_from_password_managers.yaml`](./linux_auditd_find_credentials_from_password_managers.yaml) |
| Linux PHP Privilege Escalation | 🟡 medium | 30 | `T1548.003` | [`linux_php_privilege_escalation.yaml`](./linux_php_privilege_escalation.yaml) |
| Linux Proxy Socks Curl | 🟡 medium | 56 | `T1090`, `T1095` | [`linux_proxy_socks_curl.yaml`](./linux_proxy_socks_curl.yaml) |
| Linux Security Monitoring Service Stop | 🟡 medium | 40 | `T1489` | [`linux_security_monitoring_services_stop.yaml`](./linux_security_monitoring_services_stop.yaml) |
| Linux Service File Created In Systemd Directory | 🟡 medium | 64 | `T1053.006` | [`linux_service_file_created_in_systemd_directory.yaml`](./linux_service_file_created_in_systemd_directory.yaml) |
| Linux Service Started Or Enabled | 🟡 medium | 42 | `T1053.006` | [`linux_service_started_or_enabled.yaml`](./linux_service_started_or_enabled.yaml) |
| Linux Setuid Using Chmod Utility | 🟡 medium | 49 | `T1548.001` | [`linux_setuid_using_chmod_utility.yaml`](./linux_setuid_using_chmod_utility.yaml) |
| Linux Setuid Using Setcap Utility | 🟡 medium | 49 | `T1548.001` | [`linux_setuid_using_setcap_utility.yaml`](./linux_setuid_using_setcap_utility.yaml) |
| Linux SSH Configuration Access | 🟡 medium | 55 | `T1552` | [`linux_auditd_possible_access_or_modification_of_sshd_config_file.yaml`](./linux_auditd_possible_access_or_modification_of_sshd_config_file.yaml) |
| Linux SSH Key Discovery | 🟡 medium | 50 | `T1081` | [`linux_auditd_find_ssh_private_keys.yaml`](./linux_auditd_find_ssh_private_keys.yaml) |
| Linux Sudoers File Access | 🟡 medium | 60 | `T1548` | [`linux_auditd_nopasswd_entry_in_sudoers_file.yaml`](./linux_auditd_nopasswd_entry_in_sudoers_file.yaml) |
| Linux System Reboot Via System Request Key | 🟡 medium | 49 | `T1529` | [`linux_system_reboot_via_system_request_key.yaml`](./linux_system_reboot_via_system_request_key.yaml) |
| Linux Unix Shell Enable All SysRq Functions | 🟡 medium | 36 | `T1059.004` | [`linux_unix_shell_enable_all_sysrq_functions.yaml`](./linux_unix_shell_enable_all_sysrq_functions.yaml) |
| Linux Unload Module Via Modprobe | 🟡 medium | 49 | `T1547.006` | [`linux_auditd_unload_module_via_modprobe.yaml`](./linux_auditd_unload_module_via_modprobe.yaml) |
| Linux User Account Creation Detection | 🟡 medium | 45 | `T1136.001` | [`linux_add_user_account.yaml`](./linux_add_user_account.yaml) |
| Ngrok Usage Detection | 🟡 medium | 60 | `T1572` | [`linux_ngrok_reverse_proxy_usage.yaml`](./linux_ngrok_reverse_proxy_usage.yaml) |
| Linux Auditd At Application Execution | 🔵 low | 36 | `T1053.002` | [`linux_at_application_execution.yaml`](./linux_at_application_execution.yaml) |
| Linux Auditd Crontab Listing | 🔵 low | 25 | `T1053.003`, `T1082` | [`linux_adding_crontab_using_list_parameter.yaml`](./linux_adding_crontab_using_list_parameter.yaml) |
| Linux Auditd Daemon Start | 🔵 low | 25 | `T1562.001` | [`linux_auditd_auditd_daemon_start.yaml`](./linux_auditd_auditd_daemon_start.yaml) |
| Linux Auditd Data Transfer Size Limits Via Split Syscall | 🔵 low | 25 | `T1030` | [`linux_auditd_data_transfer_size_limits_via_split_syscall.yaml`](./linux_auditd_data_transfer_size_limits_via_split_syscall.yaml) |
| Linux Auditd Database File And Directory Discovery | 🔵 low | 25 | `T1083` | [`linux_auditd_database_file_and_directory_discovery.yaml`](./linux_auditd_database_file_and_directory_discovery.yaml) |
| Linux Auditd Possible Access To Credential Files | 🔵 low | 25 | `T1003.008` | [`linux_auditd_possible_access_to_credential_files.yaml`](./linux_auditd_possible_access_to_credential_files.yaml) |
| Linux Auditd Possible Access To Sudoers File | 🔵 low | 25 | `T1548.003` | [`linux_auditd_possible_access_to_sudoers_file.yaml`](./linux_auditd_possible_access_to_sudoers_file.yaml) |
| Linux BusyBox Privilege Escalation | 🔵 low | 10 | `T1548.003`, `T1059.004` | [`linux_busybox_privilege_escalation.yaml`](./linux_busybox_privilege_escalation.yaml) |
| Linux Common Process For Elevation Control | 🔵 low | 25 | `T1548.001` | [`linux_common_process_for_elevation_control.yaml`](./linux_common_process_for_elevation_control.yaml) |
| Linux Composer Privilege Escalation | 🔵 low | 10 | `T1548.003` | [`linux_composer_privilege_escalation.yaml`](./linux_composer_privilege_escalation.yaml) |
| Linux Cpulimit Privilege Escalation | 🔵 low | 20 | `T1548.003` | [`linux_cpulimit_privilege_escalation.yaml`](./linux_cpulimit_privilege_escalation.yaml) |
| Linux Csvtool Privilege Escalation | 🔵 low | 10 | `T1548.003` | [`linux_csvtool_privilege_escalation.yaml`](./linux_csvtool_privilege_escalation.yaml) |
| Linux Find Privilege Escalation | 🔵 low | 5 | `T1548.003` | [`linux_find_privilege_escalation.yaml`](./linux_find_privilege_escalation.yaml) |
| Linux GDB Privilege Escalation | 🔵 low | 10 | `T1548.003` | [`linux_gdb_privilege_escalation.yaml`](./linux_gdb_privilege_escalation.yaml) |
| Linux Ingress Tool Transfer Hunting | 🔵 low | 25 | `T1105` | [`linux_ingress_tool_transfer_hunting.yaml`](./linux_ingress_tool_transfer_hunting.yaml) |
| Linux Make Privilege Escalation | 🔵 low | 20 | `T1548.003` | [`linux_make_privilege_escalation.yaml`](./linux_make_privilege_escalation.yaml) |
| Linux Puppet Privilege Escalation | 🔵 low | 5 | `T1548.003` | [`linux_puppet_privilege_escalation.yaml`](./linux_puppet_privilege_escalation.yaml) |
| Linux Ruby Privilege Escalation | 🔵 low | 30 | `T1548.003` | [`linux_ruby_privilege_escalation.yaml`](./linux_ruby_privilege_escalation.yaml) |
| Linux Service Restarted | 🔵 low | 25 | `T1053.006` | [`linux_service_restarted.yaml`](./linux_service_restarted.yaml) |
| Linux Sqlite3 Privilege Escalation | 🔵 low | 30 | `T1548.003` | [`linux_sqlite3_privilege_escalation.yaml`](./linux_sqlite3_privilege_escalation.yaml) |
| Linux Stop Services | 🔵 low | 25 | `T1489` | [`linux_auditd_stop_services.yaml`](./linux_auditd_stop_services.yaml) |
| Linux Sudo Or Su Execution | 🔵 low | 25 | `T1548.003` | [`linux_auditd_sudo_or_su_execution.yaml`](./linux_auditd_sudo_or_su_execution.yaml) |
| Linux System Network Configuration Discovery | 🔵 low | 25 | `T1016` | [`linux_auditd_system_network_configuration_discovery.yaml`](./linux_auditd_system_network_configuration_discovery.yaml) |
| Linux Virtual Disk File And Directory Discovery | 🔵 low | 25 | `T1083` | [`linux_auditd_virtual_disk_file_and_directory_discovery.yaml`](./linux_auditd_virtual_disk_file_and_directory_discovery.yaml) |
| Linux Visudo Utility Execution | 🔵 low | 16 | `T1548.003` | [`linux_visudo_utility_execution.yaml`](./linux_visudo_utility_execution.yaml) |
| Linux Whoami User Discovery | 🔵 low | 25 | `T1033` | [`linux_auditd_whoami_user_discovery.yaml`](./linux_auditd_whoami_user_discovery.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
