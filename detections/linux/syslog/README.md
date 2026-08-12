# syslog

Raw Linux syslog / `auth.log` lines matched on `full_log` via the Wazuh agent.

**94 rules** — critical 3, high 23, medium 42, low 26

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| Linux Auditd Data Destruction Command | critical | T1485 | [linux_auditd_data_destruction_using_no_preserve_root.yaml](./linux_auditd_data_destruction_using_no_preserve_root.yaml) |
| Linux Critical Directory Deletion | critical | T1485 | [linux_deleting_critical_directory_using_rm_command.yaml](./linux_deleting_critical_directory_using_rm_command.yaml) |
| Linux Medusa Rootkit | critical | T1014, T1589.001 | [linux_medusa_rootkit.yaml](./linux_medusa_rootkit.yaml) |
| Linux Auditd Apt Privilege Escalation | high | T1548.003 | [linux_apt_privilege_escalation.yaml](./linux_apt_privilege_escalation.yaml) |
| Linux Auditd Apt-Get Privilege Escalation | high | T1548.003 | [linux_apt_get_privilege_escalation.yaml](./linux_apt_get_privilege_escalation.yaml) |
| Linux Auditd Daemon Abort | high | T1562.001, T1489 | [linux_auditd_auditd_daemon_abort.yaml](./linux_auditd_auditd_daemon_abort.yaml) |
| Linux Auditd Data Destruction Command | high | T1485 | [linux_auditd_data_destruction_command.yaml](./linux_auditd_data_destruction_command.yaml) |
| Linux Auditd Preload Hijack Library Calls | high | T1574.006 | [linux_auditd_preload_hijack_library_calls.yaml](./linux_auditd_preload_hijack_library_calls.yaml) |
| Linux Auditd SSH Config Keys Deletion | high | T1070.004, T1485 | [linux_account_manipulation_of_ssh_config_and_keys.yaml](./linux_account_manipulation_of_ssh_config_and_keys.yaml) |
| Linux Cron File Deletion | high | T1485 | [linux_deletion_of_cron_jobs.yaml](./linux_deletion_of_cron_jobs.yaml) |
| Linux DD File Overwrite | high | T1485 | [linux_dd_file_overwrite.yaml](./linux_dd_file_overwrite.yaml) |
| Linux Disable Or Modify System Firewall | high | T1562.004 | [linux_auditd_disable_or_modify_system_firewall.yaml](./linux_auditd_disable_or_modify_system_firewall.yaml) |
| Linux Init.d Script Deletion | high | T1485 | [linux_deletion_of_init_daemon_script.yaml](./linux_deletion_of_init_daemon_script.yaml) |
| Linux Kernel Driver Activity Detection | high | T1014 | [linux_file_created_in_kernel_driver_directory.yaml](./linux_file_created_in_kernel_driver_directory.yaml) |
| Linux Kernel Module Using Rmmod Utility | high | T1547.006 | [linux_auditd_kernel_module_using_rmmod_utility.yaml](./linux_auditd_kernel_module_using_rmmod_utility.yaml) |
| Linux pkexec Privilege Escalation | high | T1068, T1078 | [cve_2021_4034.yaml](./cve_2021_4034.yaml) |
| Linux Preload Hijack Via Preload File | high | T1574.006 | [linux_auditd_preload_hijack_via_preload_file.yaml](./linux_auditd_preload_hijack_via_preload_file.yaml) |
| Linux Private Keys and Certificate Enumeration | high | T1552.004 | [linux_auditd_private_keys_and_certificate_enumeration.yaml](./linux_auditd_private_keys_and_certificate_enumeration.yaml) |
| Linux Sudoers Tmp File Creation | high | T1548.003 | [linux_sudoers_tmp_file_creation.yaml](./linux_sudoers_tmp_file_creation.yaml) |
| Linux Suspicious React or Next.js Child Process | high | T1190, T1059.004 | [cve_2025_55182.yaml](./cve_2025_55182.yaml) |
| Linux Suspicious React or Next.js Child Process | high | T1190, T1059.004 | [cve_2025_66478.yaml](./cve_2025_66478.yaml) |
| Linux Swapoff Detection | high | T1217 | [linux_auditd_hardware_addition_swapoff.yaml](./linux_auditd_hardware_addition_swapoff.yaml) |
| Linux Unix Shell Configuration Modification | high | T1546.004 | [linux_auditd_unix_shell_configuration_modification.yaml](./linux_auditd_unix_shell_configuration_modification.yaml) |
| Suspicious Emacs Eval Execution via Sudo | high | T1059 | [linux_emacs_privilege_escalation.yaml](./linux_emacs_privilege_escalation.yaml) |
| Suspicious SSL Certificate Deletion | high | T1485 | [linux_deletion_of_ssl_certificate.yaml](./linux_deletion_of_ssl_certificate.yaml) |
| Suspicious Systemd Service Deletion | high | T1485 | [linux_deletion_of_services.yaml](./linux_deletion_of_services.yaml) |
| Linux Append Cronjob Entry On Existing Cronjob File | medium | T1053.003 | [linux_auditd_possible_append_cronjob_entry_on_existing_cronjob_file.yaml](./linux_auditd_possible_append_cronjob_entry_on_existing_cronjob_file.yaml) |
| Linux Auditd Add User | medium | T1136.001 | [linux_auditd_add_user_account_type.yaml](./linux_auditd_add_user_account_type.yaml) |
| Linux Auditd At Allow Deny Config File Modification | medium | T1053.002 | [linux_at_allow_config_file_creation.yaml](./linux_at_allow_config_file_creation.yaml) |
| Linux Auditd Base64 Decode | medium | T1027, T1140 | [linux_auditd_base64_decode_files.yaml](./linux_auditd_base64_decode_files.yaml) |
| Linux Auditd Chown To Root | medium | T1222.002 | [linux_auditd_change_file_owner_to_root.yaml](./linux_auditd_change_file_owner_to_root.yaml) |
| Linux Auditd Clipboard Data Copy | medium | T1115 | [linux_auditd_clipboard_data_copy.yaml](./linux_auditd_clipboard_data_copy.yaml) |
| Linux Auditd Crontab Directory Files Modification | medium | T1053.003 | [linux_add_files_in_known_crontab_directories.yaml](./linux_add_files_in_known_crontab_directories.yaml) |
| Linux Auditd Daemon Shutdown | medium | T1562.001 | [linux_auditd_auditd_daemon_shutdown.yaml](./linux_auditd_auditd_daemon_shutdown.yaml) |
| Linux Auditd Data Transfer Size Limits Via Split | medium | T1030 | [linux_auditd_data_transfer_size_limits_via_split.yaml](./linux_auditd_data_transfer_size_limits_via_split.yaml) |
| Linux Auditd Osquery Service Stop | medium | T1489 | [linux_auditd_osquery_service_stop.yaml](./linux_auditd_osquery_service_stop.yaml) |
| Linux c89 Privilege Escalation | medium | T1548.003 | [linux_c89_privilege_escalation.yaml](./linux_c89_privilege_escalation.yaml) |
| Linux c99 Privilege Escalation | medium | T1548.003 | [linux_c99_privilege_escalation.yaml](./linux_c99_privilege_escalation.yaml) |
| Linux Credential Discovery | medium | T1081 | [linux_auditd_find_credentials_from_password_stores.yaml](./linux_auditd_find_credentials_from_password_stores.yaml) |
| Linux doas Execution Detection | medium | T1548 | [linux_auditd_doas_tool_execution.yaml](./linux_auditd_doas_tool_execution.yaml) |
| Linux Edit Cron Table Parameter | medium | T1053.003 | [linux_auditd_edit_cron_table_parameter.yaml](./linux_auditd_edit_cron_table_parameter.yaml) |
| Linux File Attribute Modification Detection | medium | T1090 | [linux_auditd_file_permissions_modification_via_chattr.yaml](./linux_auditd_file_permissions_modification_via_chattr.yaml) |
| Linux File Creation In Profile Directory | medium | T1546.004 | [linux_file_creation_in_profile_directory.yaml](./linux_file_creation_in_profile_directory.yaml) |
| Linux File Discovery Detection | medium | T1083 | [linux_auditd_file_and_directory_discovery.yaml](./linux_auditd_file_and_directory_discovery.yaml) |
| Linux File Permission Modification Detection | medium | T1098 | [linux_auditd_file_permission_modification_via_chmod.yaml](./linux_auditd_file_permission_modification_via_chmod.yaml) |
| Linux Gdrive Binary Activity | medium | T1567 | [linux_gdrive_binary_activity.yaml](./linux_gdrive_binary_activity.yaml) |
| Linux Gem Privilege Escalation | medium | T1548.003 | [linux_gem_privilege_escalation.yaml](./linux_gem_privilege_escalation.yaml) |
| Linux GNU Awk Privilege Escalation | medium | T1548.003 | [linux_gnu_awk_privilege_escalation.yaml](./linux_gnu_awk_privilege_escalation.yaml) |
| Linux Hidden File/Directory Creation | medium | T1158 | [linux_auditd_hidden_files_and_directories_creation.yaml](./linux_auditd_hidden_files_and_directories_creation.yaml) |
| Linux Init Script Persistence Detection | medium | T1037, T1547 | [linux_file_creation_in_init_boot_directory.yaml](./linux_file_creation_in_init_boot_directory.yaml) |
| Linux MySQL Privilege Escalation | medium | T1548.003 | [linux_mysql_privilege_escalation.yaml](./linux_mysql_privilege_escalation.yaml) |
| Linux OpenVPN Privilege Escalation | medium | T1548.003 | [linux_openvpn_privilege_escalation.yaml](./linux_openvpn_privilege_escalation.yaml) |
| Linux Password Vault Discovery | medium | T1081 | [linux_auditd_find_credentials_from_password_managers.yaml](./linux_auditd_find_credentials_from_password_managers.yaml) |
| Linux PHP Privilege Escalation | medium | T1548.003 | [linux_php_privilege_escalation.yaml](./linux_php_privilege_escalation.yaml) |
| Linux Proxy Socks Curl | medium | T1090, T1095 | [linux_proxy_socks_curl.yaml](./linux_proxy_socks_curl.yaml) |
| Linux Security Monitoring Service Stop | medium | T1489 | [linux_security_monitoring_services_stop.yaml](./linux_security_monitoring_services_stop.yaml) |
| Linux Service File Created In Systemd Directory | medium | T1053.006 | [linux_service_file_created_in_systemd_directory.yaml](./linux_service_file_created_in_systemd_directory.yaml) |
| Linux Service Started Or Enabled | medium | T1053.006 | [linux_service_started_or_enabled.yaml](./linux_service_started_or_enabled.yaml) |
| Linux Setuid Using Chmod Utility | medium | T1548.001 | [linux_setuid_using_chmod_utility.yaml](./linux_setuid_using_chmod_utility.yaml) |
| Linux Setuid Using Setcap Utility | medium | T1548.001 | [linux_setuid_using_setcap_utility.yaml](./linux_setuid_using_setcap_utility.yaml) |
| Linux SSH Configuration Access | medium | T1552 | [linux_auditd_possible_access_or_modification_of_sshd_config_file.yaml](./linux_auditd_possible_access_or_modification_of_sshd_config_file.yaml) |
| Linux SSH Key Discovery | medium | T1081 | [linux_auditd_find_ssh_private_keys.yaml](./linux_auditd_find_ssh_private_keys.yaml) |
| Linux Sudoers File Access | medium | T1548 | [linux_auditd_nopasswd_entry_in_sudoers_file.yaml](./linux_auditd_nopasswd_entry_in_sudoers_file.yaml) |
| Linux System Reboot Via System Request Key | medium | T1529 | [linux_system_reboot_via_system_request_key.yaml](./linux_system_reboot_via_system_request_key.yaml) |
| Linux Unix Shell Enable All SysRq Functions | medium | T1059.004 | [linux_unix_shell_enable_all_sysrq_functions.yaml](./linux_unix_shell_enable_all_sysrq_functions.yaml) |
| Linux Unload Module Via Modprobe | medium | T1547.006 | [linux_auditd_unload_module_via_modprobe.yaml](./linux_auditd_unload_module_via_modprobe.yaml) |
| Linux User Account Creation Detection | medium | T1136.001 | [linux_add_user_account.yaml](./linux_add_user_account.yaml) |
| Ngrok Usage Detection | medium | T1572 | [linux_ngrok_reverse_proxy_usage.yaml](./linux_ngrok_reverse_proxy_usage.yaml) |
| Linux Auditd At Application Execution | low | T1053.002 | [linux_at_application_execution.yaml](./linux_at_application_execution.yaml) |
| Linux Auditd Crontab Listing | low | T1053.003, T1082 | [linux_adding_crontab_using_list_parameter.yaml](./linux_adding_crontab_using_list_parameter.yaml) |
| Linux Auditd Daemon Start | low | T1562.001 | [linux_auditd_auditd_daemon_start.yaml](./linux_auditd_auditd_daemon_start.yaml) |
| Linux Auditd Data Transfer Size Limits Via Split Syscall | low | T1030 | [linux_auditd_data_transfer_size_limits_via_split_syscall.yaml](./linux_auditd_data_transfer_size_limits_via_split_syscall.yaml) |
| Linux Auditd Database File And Directory Discovery | low | T1083 | [linux_auditd_database_file_and_directory_discovery.yaml](./linux_auditd_database_file_and_directory_discovery.yaml) |
| Linux Auditd Possible Access To Credential Files | low | T1003.008 | [linux_auditd_possible_access_to_credential_files.yaml](./linux_auditd_possible_access_to_credential_files.yaml) |
| Linux Auditd Possible Access To Sudoers File | low | T1548.003 | [linux_auditd_possible_access_to_sudoers_file.yaml](./linux_auditd_possible_access_to_sudoers_file.yaml) |
| Linux BusyBox Privilege Escalation | low | T1548.003, T1059.004 | [linux_busybox_privilege_escalation.yaml](./linux_busybox_privilege_escalation.yaml) |
| Linux Common Process For Elevation Control | low | T1548.001 | [linux_common_process_for_elevation_control.yaml](./linux_common_process_for_elevation_control.yaml) |
| Linux Composer Privilege Escalation | low | T1548.003 | [linux_composer_privilege_escalation.yaml](./linux_composer_privilege_escalation.yaml) |
| Linux Cpulimit Privilege Escalation | low | T1548.003 | [linux_cpulimit_privilege_escalation.yaml](./linux_cpulimit_privilege_escalation.yaml) |
| Linux Csvtool Privilege Escalation | low | T1548.003 | [linux_csvtool_privilege_escalation.yaml](./linux_csvtool_privilege_escalation.yaml) |
| Linux Find Privilege Escalation | low | T1548.003 | [linux_find_privilege_escalation.yaml](./linux_find_privilege_escalation.yaml) |
| Linux GDB Privilege Escalation | low | T1548.003 | [linux_gdb_privilege_escalation.yaml](./linux_gdb_privilege_escalation.yaml) |
| Linux Ingress Tool Transfer Hunting | low | T1105 | [linux_ingress_tool_transfer_hunting.yaml](./linux_ingress_tool_transfer_hunting.yaml) |
| Linux Make Privilege Escalation | low | T1548.003 | [linux_make_privilege_escalation.yaml](./linux_make_privilege_escalation.yaml) |
| Linux Puppet Privilege Escalation | low | T1548.003 | [linux_puppet_privilege_escalation.yaml](./linux_puppet_privilege_escalation.yaml) |
| Linux Ruby Privilege Escalation | low | T1548.003 | [linux_ruby_privilege_escalation.yaml](./linux_ruby_privilege_escalation.yaml) |
| Linux Service Restarted | low | T1053.006 | [linux_service_restarted.yaml](./linux_service_restarted.yaml) |
| Linux Sqlite3 Privilege Escalation | low | T1548.003 | [linux_sqlite3_privilege_escalation.yaml](./linux_sqlite3_privilege_escalation.yaml) |
| Linux Stop Services | low | T1489 | [linux_auditd_stop_services.yaml](./linux_auditd_stop_services.yaml) |
| Linux Sudo Or Su Execution | low | T1548.003 | [linux_auditd_sudo_or_su_execution.yaml](./linux_auditd_sudo_or_su_execution.yaml) |
| Linux System Network Configuration Discovery | low | T1016 | [linux_auditd_system_network_configuration_discovery.yaml](./linux_auditd_system_network_configuration_discovery.yaml) |
| Linux Virtual Disk File And Directory Discovery | low | T1083 | [linux_auditd_virtual_disk_file_and_directory_discovery.yaml](./linux_auditd_virtual_disk_file_and_directory_discovery.yaml) |
| Linux Visudo Utility Execution | low | T1548.003 | [linux_visudo_utility_execution.yaml](./linux_visudo_utility_execution.yaml) |
| Linux Whoami User Discovery | low | T1033 | [linux_auditd_whoami_user_discovery.yaml](./linux_auditd_whoami_user_discovery.yaml) |
