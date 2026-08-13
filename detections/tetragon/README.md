# tetragon

Cilium Tetragon `process_exec` events shipped by the Wazuh agent (`data_process_exec_*` fields).

**117 rules** — critical 1, high 63, medium 53

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| UNC4841 - Potential SEASPY Execution | critical | — | [unc4841_potential_seaspy_execution.yaml](./unc4841_potential_seaspy_execution.yaml) |
| Apache Spark Shell Command Injection - ProcessCreation | high | T1190 | [apache_spark_shell_command_injection_processcreation.yaml](./apache_spark_shell_command_injection_processcreation.yaml) |
| Atlassian Confluence CVE-2022-26134 | high | T1190, T1059 | [atlassian_confluence_cve_2022_26134.yaml](./atlassian_confluence_cve_2022_26134.yaml) |
| Audit Rules Deleted Via Auditctl | high | T1685.004 | [audit_rules_deleted_via_auditctl.yaml](./audit_rules_deleted_via_auditctl.yaml) |
| Authencesn Crypto Module Load via Modprobe - Copy-Fail Indicator | high | T1068, T1547.006 | [authencesn_crypto_module_load_via_modprobe_copy_fail_indicator.yaml](./authencesn_crypto_module_load_via_modprobe_copy_fail_indicator.yaml) |
| Axios NPM Compromise Indicators - Linux | high | T1195.002, T1059.006, T1059.004, T1105 | [axios_npm_compromise_indicators_linux.yaml](./axios_npm_compromise_indicators_linux.yaml) |
| Capsh Shell Invocation - Linux | high | T1059 | [capsh_shell_invocation_linux.yaml](./capsh_shell_invocation_linux.yaml) |
| Copy Passwd Or Shadow From TMP Path | high | T1552.001 | [copy_passwd_or_shadow_from_tmp_path.yaml](./copy_passwd_or_shadow_from_tmp_path.yaml) |
| CVE-2023-22518 Exploitation Attempt - Suspicious Confluence Child Process (Linux) | high | T1059, T1190 | [cve_2023_22518_exploitation_attempt_suspicious_confluence_child_process_linux.yaml](./cve_2023_22518_exploitation_attempt_suspicious_confluence_child_process_linux.yaml) |
| Doas Privilege Escalation Detection | high | T1548 | [linux_doas_conf_file_creation.yaml](./linux_doas_conf_file_creation.yaml) |
| Doas Privilege Escalation Detection | high | T1548 | [linux_doas_tool_execution.yaml](./linux_doas_tool_execution.yaml) |
| ESXi Admin Permission Assigned To Account Via ESXCLI | high | T1059.012, T1098 | [esxi_admin_permission_assigned_to_account_via_esxcli.yaml](./esxi_admin_permission_assigned_to_account_via_esxcli.yaml) |
| History File Deletion | high | T1565.001 | [history_file_deletion.yaml](./history_file_deletion.yaml) |
| Inline Python Execution - Spawn Shell Via OS System Library | high | T1059 | [inline_python_execution_spawn_shell_via_os_system_library.yaml](./inline_python_execution_spawn_shell_via_os_system_library.yaml) |
| Kaspersky Endpoint Security Stopped Via CommandLine - Linux | high | T1685 | [kaspersky_endpoint_security_stopped_via_commandline_linux.yaml](./kaspersky_endpoint_security_stopped_via_commandline_linux.yaml) |
| Linux Crypto Mining Indicators | high | T1496 | [linux_crypto_mining_indicators.yaml](./linux_crypto_mining_indicators.yaml) |
| Linux HackTool Execution | high | T1587 | [linux_hacktool_execution.yaml](./linux_hacktool_execution.yaml) |
| Linux Kernel Module Insertion | high | T1215 | [linux_auditd_insert_kernel_module_using_insmod_utility.yaml](./linux_auditd_insert_kernel_module_using_insmod_utility.yaml) |
| Linux Kernel Module Load | high | T1215 | [linux_auditd_install_kernel_module_using_modprobe_utility.yaml](./linux_auditd_install_kernel_module_using_modprobe_utility.yaml) |
| Linux Recon Indicators | high | T1592.004, T1552.001 | [linux_recon_indicators.yaml](./linux_recon_indicators.yaml) |
| Linux Suspicious Base64 Execution | high | T1059.004 | [linux_decode_base64_to_shell.yaml](./linux_decode_base64_to_shell.yaml) |
| Linux Suspicious Child Process from Node.js - React2Shell | high | T1059, T1190 | [linux_suspicious_child_process_from_node_js_react2shell.yaml](./linux_suspicious_child_process_from_node_js_react2shell.yaml) |
| Linux Suspicious Curl Data Exfiltration | high | T1041 | [linux_curl_upload_file.yaml](./linux_curl_upload_file.yaml) |
| Linux Webshell Indicators | high | T1505.003 | [linux_webshell_indicators.yaml](./linux_webshell_indicators.yaml) |
| LiteLLM / TeamPCP Supply Chain Attack Indicators | high | T1195.002, T1560.001, T1543.002 | [litellm_teampcp_supply_chain_attack_indicators.yaml](./litellm_teampcp_supply_chain_attack_indicators.yaml) |
| Mask System Power Settings Via Systemctl | high | T1653 | [mask_system_power_settings_via_systemctl.yaml](./mask_system_power_settings_via_systemctl.yaml) |
| OMIGOD SCX RunAsProvider ExecuteScript | high | T1068, T1190, T1203 | [omigod_scx_runasprovider_executescript.yaml](./omigod_scx_runasprovider_executescript.yaml) |
| OMIGOD SCX RunAsProvider ExecuteShellCommand | high | T1068, T1190, T1203 | [omigod_scx_runasprovider_executeshellcommand.yaml](./omigod_scx_runasprovider_executeshellcommand.yaml) |
| Potential Exploitation of CVE-2024-3094 - Suspicious SSH Child Process | high | — | [potential_exploitation_of_cve_2024_3094_suspicious_ssh_child_process.yaml](./potential_exploitation_of_cve_2024_3094_suspicious_ssh_child_process.yaml) |
| Potential GobRAT File Discovery Via Grep | high | T1082 | [potential_gobrat_file_discovery_via_grep.yaml](./potential_gobrat_file_discovery_via_grep.yaml) |
| Potential Netcat Reverse Shell Execution | high | T1059 | [potential_netcat_reverse_shell_execution.yaml](./potential_netcat_reverse_shell_execution.yaml) |
| Potential Perl Reverse Shell Execution | high | — | [potential_perl_reverse_shell_execution.yaml](./potential_perl_reverse_shell_execution.yaml) |
| Potential PHP Reverse Shell | high | — | [potential_php_reverse_shell.yaml](./potential_php_reverse_shell.yaml) |
| Process Execution From Shared Memory Directory | high | T1027.011 | [process_execution_from_shared_memory_directory.yaml](./process_execution_from_shared_memory_directory.yaml) |
| Python One-Liners with Base64 Decoding - Linux | high | T1059.006, T1027.010 | [python_one_liners_with_base64_decoding_linux.yaml](./python_one_liners_with_base64_decoding_linux.yaml) |
| Python Reverse Shell Execution Via PTY And Socket Modules | high | — | [python_reverse_shell_execution_via_pty_and_socket_modules.yaml](./python_reverse_shell_execution_via_pty_and_socket_modules.yaml) |
| Script Interpreter Spawning Credential Scanner - Linux | high | T1552, T1005, T1059.004 | [script_interpreter_spawning_credential_scanner_linux.yaml](./script_interpreter_spawning_credential_scanner_linux.yaml) |
| Shai-Hulud Malicious Bun Execution - Linux | high | T1195.002, T1203 | [shai_hulud_malicious_bun_execution_linux.yaml](./shai_hulud_malicious_bun_execution_linux.yaml) |
| Shai-Hulud Malware Indicators - Linux | high | T1059 | [shai_hulud_malware_indicators_linux.yaml](./shai_hulud_malware_indicators_linux.yaml) |
| Shai-Hulud NPM Package Malicious Exfiltration via Curl | high | T1041, T1005 | [shai_hulud_npm_package_malicious_exfiltration_via_curl.yaml](./shai_hulud_npm_package_malicious_exfiltration_via_curl.yaml) |
| Shell Execution GCC  - Linux | high | T1083 | [shell_execution_gcc_linux.yaml](./shell_execution_gcc_linux.yaml) |
| Shell Execution Of Process Located In Tmp Directory | high | — | [shell_execution_of_process_located_in_tmp_directory.yaml](./shell_execution_of_process_located_in_tmp_directory.yaml) |
| Shell Execution via Find - Linux | high | T1083 | [shell_execution_via_find_linux.yaml](./shell_execution_via_find_linux.yaml) |
| Shell Execution via Flock - Linux | high | T1083 | [shell_execution_via_flock_linux.yaml](./shell_execution_via_flock_linux.yaml) |
| Shell Execution via Git - Linux | high | T1059 | [shell_execution_via_git_linux.yaml](./shell_execution_via_git_linux.yaml) |
| Shell Execution via Nice - Linux | high | T1083 | [shell_execution_via_nice_linux.yaml](./shell_execution_via_nice_linux.yaml) |
| Shell Execution via Rsync - Linux | high | T1059 | [shell_execution_via_rsync_linux.yaml](./shell_execution_via_rsync_linux.yaml) |
| Shell Invocation via Env Command - Linux | high | T1059.004 | [shell_invocation_via_env_command_linux.yaml](./shell_invocation_via_env_command_linux.yaml) |
| Shell Invocation Via Ssh - Linux | high | T1059 | [shell_invocation_via_ssh_linux.yaml](./shell_invocation_via_ssh_linux.yaml) |
| Sudo Privilege Escalation CVE-2019-14287 | high | T1068, T1548.003 | [sudo_privilege_escalation_cve_2019_14287.yaml](./sudo_privilege_escalation_cve_2019_14287.yaml) |
| Suspicious Container Exec Detection | high | T1611 | [linux_docker_privilege_escalation.yaml](./linux_docker_privilege_escalation.yaml) |
| Suspicious Download and Execute Pattern via Curl/Wget | high | T1059.004, T1203 | [suspicious_download_and_execute_pattern_via_curl_wget.yaml](./suspicious_download_and_execute_pattern_via_curl_wget.yaml) |
| Suspicious Invocation of Shell via AWK - Linux | high | T1059 | [suspicious_invocation_of_shell_via_awk_linux.yaml](./suspicious_invocation_of_shell_via_awk_linux.yaml) |
| Suspicious Invocation of Shell via Rsync | high | T1059, T1203 | [suspicious_invocation_of_shell_via_rsync.yaml](./suspicious_invocation_of_shell_via_rsync.yaml) |
| Suspicious Java Children Processes | high | T1059 | [suspicious_java_children_processes.yaml](./suspicious_java_children_processes.yaml) |
| Suspicious Nohup Execution | high | — | [suspicious_nohup_execution.yaml](./suspicious_nohup_execution.yaml) |
| Syslog Clearing or Removal Via System Utilities | high | T1685.006 | [syslog_clearing_or_removal_via_system_utilities.yaml](./syslog_clearing_or_removal_via_system_utilities.yaml) |
| TanStack Supply-Chain Attack Execution Indicators - Linux | high | T1059.007, T1059.006, T1204.002 | [tanstack_supply_chain_attack_execution_indicators_linux.yaml](./tanstack_supply_chain_attack_execution_indicators_linux.yaml) |
| Triple Cross eBPF Rootkit Execve Hijack | high | — | [triple_cross_ebpf_rootkit_execve_hijack.yaml](./triple_cross_ebpf_rootkit_execve_hijack.yaml) |
| Triple Cross eBPF Rootkit Install Commands | high | T1014 | [triple_cross_ebpf_rootkit_install_commands.yaml](./triple_cross_ebpf_rootkit_install_commands.yaml) |
| UNC4841 - Download Compressed Files From Temp.sh Using Wget | high | T1140 | [unc4841_download_compressed_files_from_temp_sh_using_wget.yaml](./unc4841_download_compressed_files_from_temp_sh_using_wget.yaml) |
| UNC4841 - Download Tar File From Untrusted Direct IP Via Wget | high | T1140 | [unc4841_download_tar_file_from_untrusted_direct_ip_via_wget.yaml](./unc4841_download_tar_file_from_untrusted_direct_ip_via_wget.yaml) |
| UNC4841 - SSL Certificate Exfiltration Via Openssl | high | T1140 | [unc4841_ssl_certificate_exfiltration_via_openssl.yaml](./unc4841_ssl_certificate_exfiltration_via_openssl.yaml) |
| Vim GTFOBin Abuse - Linux | high | T1059, T1083 | [vim_gtfobin_abuse_linux.yaml](./vim_gtfobin_abuse_linux.yaml) |
| Access of Sudoers File Content | medium | T1592.004 | [access_of_sudoers_file_content.yaml](./access_of_sudoers_file_content.yaml) |
| BPFtrace Unsafe Option Usage | medium | T1059.004 | [bpftrace_unsafe_option_usage.yaml](./bpftrace_unsafe_option_usage.yaml) |
| Chmod Targeting Sensitive Directories | medium | T1222.002 | [chmod_targeting_sensitive_directories.yaml](./chmod_targeting_sensitive_directories.yaml) |
| Crontab Interactive Edit Execution | medium | T1053.003 | [linux_edit_cron_table_parameter.yaml](./linux_edit_cron_table_parameter.yaml) |
| Disable Or Stop Services | medium | T1685, T1489 | [disable_or_stop_services.yaml](./disable_or_stop_services.yaml) |
| Disabling Security Tools | medium | T1686 | [disabling_security_tools.yaml](./disabling_security_tools.yaml) |
| Download File To Potentially Suspicious Directory Via Wget | medium | T1105 | [download_file_to_potentially_suspicious_directory_via_wget.yaml](./download_file_to_potentially_suspicious_directory_via_wget.yaml) |
| Enable BPF Kprobes Tracing | medium | — | [enable_bpf_kprobes_tracing.yaml](./enable_bpf_kprobes_tracing.yaml) |
| ESXi Account Creation Via ESXCLI | medium | T1136, T1059.012 | [esxi_account_creation_via_esxcli.yaml](./esxi_account_creation_via_esxcli.yaml) |
| ESXi Network Configuration Discovery Via ESXCLI | medium | T1033, T1007, T1059.012 | [esxi_network_configuration_discovery_via_esxcli.yaml](./esxi_network_configuration_discovery_via_esxcli.yaml) |
| ESXi Storage Information Discovery Via ESXCLI | medium | T1033, T1007, T1059.012 | [esxi_storage_information_discovery_via_esxcli.yaml](./esxi_storage_information_discovery_via_esxcli.yaml) |
| ESXi Syslog Configuration Change Via ESXCLI | medium | T1685, T1690, T1059.012 | [esxi_syslog_configuration_change_via_esxcli.yaml](./esxi_syslog_configuration_change_via_esxcli.yaml) |
| ESXi System Information Discovery Via ESXCLI | medium | T1033, T1007, T1059.012 | [esxi_system_information_discovery_via_esxcli.yaml](./esxi_system_information_discovery_via_esxcli.yaml) |
| ESXi VM Kill Via ESXCLI | medium | T1059.012, T1529 | [esxi_vm_kill_via_esxcli.yaml](./esxi_vm_kill_via_esxcli.yaml) |
| ESXi VM List Discovery Via ESXCLI | medium | T1033, T1007, T1059.012 | [esxi_vm_list_discovery_via_esxcli.yaml](./esxi_vm_list_discovery_via_esxcli.yaml) |
| ESXi VSAN Information Discovery Via ESXCLI | medium | T1033, T1007, T1059.012 | [esxi_vsan_information_discovery_via_esxcli.yaml](./esxi_vsan_information_discovery_via_esxcli.yaml) |
| Execution Of Script Located In Potentially Suspicious Directory | medium | — | [execution_of_script_located_in_potentially_suspicious_directory.yaml](./execution_of_script_located_in_potentially_suspicious_directory.yaml) |
| Flush Iptables Ufw Chain | medium | T1686 | [flush_iptables_ufw_chain.yaml](./flush_iptables_ufw_chain.yaml) |
| Group Has Been Deleted Via Groupdel | medium | T1531 | [group_has_been_deleted_via_groupdel.yaml](./group_has_been_deleted_via_groupdel.yaml) |
| Interactive Bash Suspicious Children | medium | T1059.004, T1036 | [interactive_bash_suspicious_children.yaml](./interactive_bash_suspicious_children.yaml) |
| Linux Base64 Encoded Pipe to Shell | medium | T1140 | [linux_base64_encoded_pipe_to_shell.yaml](./linux_base64_encoded_pipe_to_shell.yaml) |
| Linux Base64 Encoded Shebang In CLI | medium | T1140 | [linux_base64_encoded_shebang_in_cli.yaml](./linux_base64_encoded_shebang_in_cli.yaml) |
| Linux Logs Clearing Attempts | medium | T1685.006 | [linux_logs_clearing_attempts.yaml](./linux_logs_clearing_attempts.yaml) |
| Linux Shell Pipe to Shell | medium | T1140 | [linux_shell_pipe_to_shell.yaml](./linux_shell_pipe_to_shell.yaml) |
| Mount Execution With Hidepid Parameter | medium | T1564 | [mount_execution_with_hidepid_parameter.yaml](./mount_execution_with_hidepid_parameter.yaml) |
| Nohup Execution | medium | T1059.004 | [nohup_execution.yaml](./nohup_execution.yaml) |
| Pnscan Binary Data Transmission Activity | medium | T1046 | [pnscan_binary_data_transmission_activity.yaml](./pnscan_binary_data_transmission_activity.yaml) |
| Potential Discovery Activity Using Find - Linux | medium | T1083 | [potential_discovery_activity_using_find_linux.yaml](./potential_discovery_activity_using_find_linux.yaml) |
| Potential Exploitation of CVE-2025-5054 or CVE-2025-4598 | medium | T1548, T1003 | [potential_exploitation_of_cve_2025_5054_or_cve_2025_4598.yaml](./potential_exploitation_of_cve_2025_5054_or_cve_2025_4598.yaml) |
| Potential Linux Amazon SSM Agent Hijacking | medium | T1219.002 | [potential_linux_amazon_ssm_agent_hijacking.yaml](./potential_linux_amazon_ssm_agent_hijacking.yaml) |
| Potential Linux Process Code Injection Via DD Utility | medium | T1055.009 | [potential_linux_process_code_injection_via_dd_utility.yaml](./potential_linux_process_code_injection_via_dd_utility.yaml) |
| Potential Ruby Reverse Shell | medium | — | [potential_ruby_reverse_shell.yaml](./potential_ruby_reverse_shell.yaml) |
| Potential Suspicious Change To Sensitive/Critical Files | medium | T1565.001 | [potential_suspicious_change_to_sensitive_critical_files.yaml](./potential_suspicious_change_to_sensitive_critical_files.yaml) |
| Potential Xterm Reverse Shell | medium | T1059 | [potential_xterm_reverse_shell.yaml](./potential_xterm_reverse_shell.yaml) |
| Potentially Suspicious Execution From Tmp Folder | medium | T1036 | [potentially_suspicious_execution_from_tmp_folder.yaml](./potentially_suspicious_execution_from_tmp_folder.yaml) |
| Potentially Suspicious Named Pipe Created Via Mkfifo | medium | — | [potentially_suspicious_named_pipe_created_via_mkfifo.yaml](./potentially_suspicious_named_pipe_created_via_mkfifo.yaml) |
| Print History File Contents | medium | T1592.004 | [print_history_file_contents.yaml](./print_history_file_contents.yaml) |
| PUA - TruffleHog Execution - Linux | medium | T1083, T1552.001 | [pua_trufflehog_execution_linux.yaml](./pua_trufflehog_execution_linux.yaml) |
| Python Spawning Pretty TTY Via PTY Module | medium | T1059 | [python_spawning_pretty_tty_via_pty_module.yaml](./python_spawning_pretty_tty_via_pty_module.yaml) |
| Python WebServer Execution - Linux | medium | T1048.003 | [python_webserver_execution_linux.yaml](./python_webserver_execution_linux.yaml) |
| Remove Immutable File Attribute | medium | T1222.002 | [remove_immutable_file_attribute.yaml](./remove_immutable_file_attribute.yaml) |
| Remove Scheduled Cron Task/Job | medium | — | [remove_scheduled_cron_task_job.yaml](./remove_scheduled_cron_task_job.yaml) |
| Scheduled Cron Task/Job - Linux | medium | T1053.003 | [scheduled_cron_task_job_linux.yaml](./scheduled_cron_task_job_linux.yaml) |
| Shell Invocation via Apt - Linux | medium | T1083 | [shell_invocation_via_apt_linux.yaml](./shell_invocation_via_apt_linux.yaml) |
| Suspicious Child Process of SAP NetWeaver - Linux | medium | T1190, T1059.003 | [suspicious_child_process_of_sap_netweaver_linux.yaml](./suspicious_child_process_of_sap_netweaver_linux.yaml) |
| Suspicious Curl Change User Agents - Linux | medium | T1071.001 | [suspicious_curl_change_user_agents_linux.yaml](./suspicious_curl_change_user_agents_linux.yaml) |
| Suspicious Curl File Upload - Linux | medium | T1567, T1105 | [suspicious_curl_file_upload_linux.yaml](./suspicious_curl_file_upload_linux.yaml) |
| Suspicious Git Clone - Linux | medium | T1593.003 | [suspicious_git_clone_linux.yaml](./suspicious_git_clone_linux.yaml) |
| Suspicious Package Installed - Linux | medium | T1553.004 | [suspicious_package_installed_linux.yaml](./suspicious_package_installed_linux.yaml) |
| Touch Suspicious Service File | medium | T1070.006 | [touch_suspicious_service_file.yaml](./touch_suspicious_service_file.yaml) |
| UFW Disable Attempt | medium | T1686 | [ufw_disable_attempt.yaml](./ufw_disable_attempt.yaml) |
| User Added To Root/Sudoers Group Using Usermod | medium | — | [user_added_to_root_sudoers_group_using_usermod.yaml](./user_added_to_root_sudoers_group_using_usermod.yaml) |
| User Has Been Deleted Via Userdel | medium | T1531 | [user_has_been_deleted_via_userdel.yaml](./user_has_been_deleted_via_userdel.yaml) |
