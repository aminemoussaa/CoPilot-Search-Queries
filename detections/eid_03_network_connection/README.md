# Sysmon Event ID 3 — Network Connection

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **38 rules**

Outbound and inbound TCP/UDP connections attributed to the initiating process.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🔴 critical 1 · 🟠 high 19 · 🟡 medium 18 |
| Status | experimental 36, production 2 |
| ATT&CK techniques | 33 distinct |
| Provenance | 36 Sigma-derived, 2 written for this repo |
| Event IDs queried | `3` (38) |

## Onboarding

Enable `NetworkConnect` in the Sysmon config. Noisy by default — scope it to the ports and images you care about.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 38 |
| `data_win_eventdata_initiated` | 29 |
| `data_win_eventdata_image` | 29 |
| `data_win_eventdata_destinationHostname` | 16 |
| `data_win_eventdata_destinationPort` | 11 |
| `data_win_eventdata_destinationIp` | 3 |
| `data_win_eventdata_protocol` | 2 |
| `data_win_eventdata_sourcePort` | 2 |
| `data_win_eventdata_parentImage` | 2 |
| `data_win_eventdata_sourceIp` | 2 |

## Top ATT&CK techniques

[`T1572`](https://attack.mitre.org/techniques/T1572/) (8) · [`T1102`](https://attack.mitre.org/techniques/T1102/) (6) · [`T1567`](https://attack.mitre.org/techniques/T1567/) (6) · [`T1105`](https://attack.mitre.org/techniques/T1105/) (6) · [`T1090`](https://attack.mitre.org/techniques/T1090/) (2) · [`T1021.001`](https://attack.mitre.org/techniques/T1021/001/) (2) · [`T1568.002`](https://attack.mitre.org/techniques/T1568/002/) (1) · [`T1041`](https://attack.mitre.org/techniques/T1041/) (1)

## Rules (38)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Windows WinLogon With Public Network Connection | 🔴 critical | 90 | `T1542.003` | [`windows_winlogon_with_public_network_connection.yaml`](./windows_winlogon_with_public_network_connection.yaml) |
| Communication To LocaltoNet Tunneling Service Initiated | 🟠 high | 75 | `T1572`, `T1090`, `T1102` | [`communication_to_localtonet_tunneling_service_initiated.yaml`](./communication_to_localtonet_tunneling_service_initiated.yaml) |
| Communication To Ngrok Tunneling Service Initiated | 🟠 high | 75 | `T1567`, `T1568.002`, `T1572`… | [`communication_to_ngrok_tunneling_service_initiated.yaml`](./communication_to_ngrok_tunneling_service_initiated.yaml) |
| Network Communication Initiated To File Sharing Domains From Process Located In Suspicious Folder | 🟠 high | 75 | `T1105` | [`network_communication_initiated_to_file_sharing_domains_from_process_located_in_suspicious_folder.yaml`](./network_communication_initiated_to_file_sharing_domains_from_process_located_in_suspicious_folder.yaml) |
| Network Connection Initiated By AddinUtil.EXE | 🟠 high | 75 | `T1218` | [`network_connection_initiated_by_addinutil_exe.yaml`](./network_connection_initiated_by_addinutil_exe.yaml) |
| Network Connection Initiated By Eqnedt32.EXE | 🟠 high | 75 | `T1203` | [`network_connection_initiated_by_eqnedt32_exe.yaml`](./network_connection_initiated_by_eqnedt32_exe.yaml) |
| Network Connection Initiated By IMEWDBLD.EXE | 🟠 high | 75 | `T1105` | [`network_connection_initiated_by_imewdbld_exe.yaml`](./network_connection_initiated_by_imewdbld_exe.yaml) |
| Network Connection Initiated From Process Located In Potentially Suspicious Or Uncommon Location | 🟠 high | 75 | `T1105` | [`network_connection_initiated_from_process_located_in_potentially_suspicious_or_uncommon_location.yaml`](./network_connection_initiated_from_process_located_in_potentially_suspicious_or_uncommon_location.yaml) |
| Network Connection Initiated via Finger.EXE | 🟠 high | 75 | `T1071.004`, `T1059.003` | [`network_connection_initiated_via_finger_exe.yaml`](./network_connection_initiated_via_finger_exe.yaml) |
| Network Connection Initiated Via Notepad.EXE | 🟠 high | 75 | `T1055` | [`network_connection_initiated_via_notepad_exe.yaml`](./network_connection_initiated_via_notepad_exe.yaml) |
| Outbound RDP Connections Over Non-Standard Tools | 🟠 high | 75 | `T1021.001` | [`outbound_rdp_connections_over_non_standard_tools.yaml`](./outbound_rdp_connections_over_non_standard_tools.yaml) |
| Potential Compromised 3CXDesktopApp Beaconing Activity - Netcon | 🟠 high | 75 | — | [`potential_compromised_3cxdesktopapp_beaconing_activity_netcon.yaml`](./potential_compromised_3cxdesktopapp_beaconing_activity_netcon.yaml) |
| Potential Pikabot C2 Activity | 🟠 high | 75 | `T1573` | [`potential_pikabot_c2_activity.yaml`](./potential_pikabot_c2_activity.yaml) |
| Potential Remote PowerShell Session Initiated | 🟠 high | 75 | `T1059.001`, `T1021.006` | [`potential_remote_powershell_session_initiated.yaml`](./potential_remote_powershell_session_initiated.yaml) |
| Process Initiated Network Connection To Ngrok Domain | 🟠 high | 75 | `T1567`, `T1572`, `T1102` | [`process_initiated_network_connection_to_ngrok_domain.yaml`](./process_initiated_network_connection_to_ngrok_domain.yaml) |
| RDP to HTTP or HTTPS Target Ports | 🟠 high | 75 | `T1572`, `T1021.001` | [`rdp_to_http_or_https_target_ports.yaml`](./rdp_to_http_or_https_target_ports.yaml) |
| Silenttrinity Stager Msbuild Activity | 🟠 high | 75 | `T1127.001` | [`silenttrinity_stager_msbuild_activity.yaml`](./silenttrinity_stager_msbuild_activity.yaml) |
| Suspicious Dropbox API Usage | 🟠 high | 75 | `T1105`, `T1567.002` | [`suspicious_dropbox_api_usage.yaml`](./suspicious_dropbox_api_usage.yaml) |
| Suspicious Network Connection Binary No CommandLine | 🟠 high | 75 | — | [`suspicious_network_connection_binary_no_commandline.yaml`](./suspicious_network_connection_binary_no_commandline.yaml) |
| Uncommon Network Connection Initiated By Certutil.EXE | 🟠 high | 75 | `T1105` | [`uncommon_network_connection_initiated_by_certutil_exe.yaml`](./uncommon_network_connection_initiated_by_certutil_exe.yaml) |
| Network Communication Initiated To Portmap.IO Domain | 🟡 medium | 50 | `T1041`, `T1090.002` | [`network_communication_initiated_to_portmap_io_domain.yaml`](./network_communication_initiated_to_portmap_io_domain.yaml) |
| Network Connection Initiated By Regsvr32.EXE | 🟡 medium | 50 | `T1559.001`, `T1218.010` | [`network_connection_initiated_by_regsvr32_exe.yaml`](./network_connection_initiated_by_regsvr32_exe.yaml) |
| Network Connection Initiated To AzureWebsites.NET By Non-Browser Process | 🟡 medium | 50 | `T1102`, `T1102.001` | [`network_connection_initiated_to_azurewebsites_net_by_non_browser_process.yaml`](./network_connection_initiated_to_azurewebsites_net_by_non_browser_process.yaml) |
| Network Connection Initiated To BTunnels Domains | 🟡 medium | 50 | `T1567`, `T1572` | [`network_connection_initiated_to_btunnels_domains.yaml`](./network_connection_initiated_to_btunnels_domains.yaml) |
| Network Connection Initiated To Cloudflared Tunnels Domains | 🟡 medium | 50 | `T1567`, `T1572` | [`network_connection_initiated_to_cloudflared_tunnels_domains.yaml`](./network_connection_initiated_to_cloudflared_tunnels_domains.yaml) |
| Network Connection Initiated To DevTunnels Domain | 🟡 medium | 50 | `T1567.001`, `T1572` | [`network_connection_initiated_to_devtunnels_domain.yaml`](./network_connection_initiated_to_devtunnels_domain.yaml) |
| Network Connection Initiated To Visual Studio Code Tunnels Domain | 🟡 medium | 50 | `T1567`, `T1572` | [`network_connection_initiated_to_visual_studio_code_tunnels_domain.yaml`](./network_connection_initiated_to_visual_studio_code_tunnels_domain.yaml) |
| Office Application Initiated Network Connection Over Uncommon Ports | 🟡 medium | 50 | — | [`office_application_initiated_network_connection_over_uncommon_ports.yaml`](./office_application_initiated_network_connection_over_uncommon_ports.yaml) |
| Python Initiated Connection | 🟡 medium | 50 | `T1046` | [`python_initiated_connection.yaml`](./python_initiated_connection.yaml) |
| Remote Access Tool - AnyDesk Incoming Connection | 🟡 medium | 50 | `T1219.002` | [`remote_access_tool_anydesk_incoming_connection.yaml`](./remote_access_tool_anydesk_incoming_connection.yaml) |
| Suspicious Network Connection to IP Lookup Service APIs | 🟡 medium | 50 | `T1016` | [`suspicious_network_connection_to_ip_lookup_service_apis.yaml`](./suspicious_network_connection_to_ip_lookup_service_apis.yaml) |
| Suspicious Non-Browser Network Communication With Google API | 🟡 medium | 50 | `T1102` | [`suspicious_non_browser_network_communication_with_google_api.yaml`](./suspicious_non_browser_network_communication_with_google_api.yaml) |
| Suspicious Non-Browser Network Communication With Telegram API | 🟡 medium | 50 | `T1102`, `T1567`, `T1105` | [`suspicious_non_browser_network_communication_with_telegram_api.yaml`](./suspicious_non_browser_network_communication_with_telegram_api.yaml) |
| Suspicious Outbound SMTP Connections | 🟡 medium | 50 | `T1048.003` | [`suspicious_outbound_smtp_connections.yaml`](./suspicious_outbound_smtp_connections.yaml) |
| Suspicious Wordpad Outbound Connections | 🟡 medium | 50 | — | [`suspicious_wordpad_outbound_connections.yaml`](./suspicious_wordpad_outbound_connections.yaml) |
| Uncommon Connection to Active Directory Web Services | 🟡 medium | 50 | `T1087` | [`uncommon_connection_to_active_directory_web_services.yaml`](./uncommon_connection_to_active_directory_web_services.yaml) |
| Uncommon Outbound Kerberos Connection | 🟡 medium | 50 | `T1558`, `T1550.003` | [`uncommon_outbound_kerberos_connection.yaml`](./uncommon_outbound_kerberos_connection.yaml) |
| Windows Detect Network Scanner Behavior | 🟡 medium | 40 | `T1595.001`, `T1595.002` | [`windows_detect_network_scanner_behavior.yaml`](./windows_detect_network_scanner_behavior.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
