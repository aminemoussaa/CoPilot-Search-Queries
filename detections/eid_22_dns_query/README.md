# Sysmon Event ID 22 — DNS Query

**Platform** `Windows` · **Log source** Sysmon `Microsoft-Windows-Sysmon/Operational` · **25 rules**

DNS lookups attributed to the requesting process, used for C2 beaconing, exfiltration domains and tooling fingerprints.

[← all detections](../README.md)

## At a glance

| | |
| --- | --- |
| Severity | 🔴 critical 1 · 🟠 high 10 · 🟡 medium 14 |
| Status | experimental 23, production 2 |
| ATT&CK techniques | 18 distinct |
| Provenance | 23 Sigma-derived, 2 written for this repo |
| Event IDs queried | `22` (25) |

## Onboarding

Enable `DnsQuery` in the Sysmon config. Requires Sysmon 10+. High volume — exclude your own infrastructure.

## Fields these rules filter on

| Field | Rules |
| --- | --- |
| `data_win_system_eventID` | 25 |
| `data_win_eventdata_queryName` | 21 |
| `data_win_eventdata_image` | 11 |

## Top ATT&CK techniques

[`T1071.001`](https://attack.mitre.org/techniques/T1071/001/) (4) · [`T1071.004`](https://attack.mitre.org/techniques/T1071/004/) (4) · [`T1219.002`](https://attack.mitre.org/techniques/T1219/002/) (3) · [`T1105`](https://attack.mitre.org/techniques/T1105/) (2) · [`T1572`](https://attack.mitre.org/techniques/T1572/) (2) · [`T1567.002`](https://attack.mitre.org/techniques/T1567/002/) (2) · [`T1554`](https://attack.mitre.org/techniques/T1554/) (1) · [`T1059.003`](https://attack.mitre.org/techniques/T1059/003/) (1)

## Rules (25)

Sorted by severity, then name.

| Rule | Severity | Risk | ATT&CK | File |
| --- | --- | --- | --- | --- |
| Suspicious Cobalt Strike DNS Beaconing - Sysmon | 🔴 critical | 90 | `T1071.004` | [`suspicious_cobalt_strike_dns_beaconing_sysmon.yaml`](./suspicious_cobalt_strike_dns_beaconing_sysmon.yaml) |
| Diamond Sleet APT DNS Communication Indicators | 🟠 high | 75 | — | [`diamond_sleet_apt_dns_communication_indicators.yaml`](./diamond_sleet_apt_dns_communication_indicators.yaml) |
| DNS HybridConnectionManager Service Bus | 🟠 high | 75 | `T1554` | [`dns_hybridconnectionmanager_service_bus.yaml`](./dns_hybridconnectionmanager_service_bus.yaml) |
| DNS Query by Finger Utility | 🟠 high | 75 | `T1071.004`, `T1059.003` | [`dns_query_by_finger_utility.yaml`](./dns_query_by_finger_utility.yaml) |
| DNS Query for Anonfiles.com Domain - Sysmon | 🟠 high | 75 | `T1567.002` | [`dns_query_for_anonfiles_com_domain_sysmon.yaml`](./dns_query_for_anonfiles_com_domain_sysmon.yaml) |
| DNS Query To Katz Stealer Domains | 🟠 high | 75 | `T1071.004` | [`dns_query_to_katz_stealer_domains.yaml`](./dns_query_to_katz_stealer_domains.yaml) |
| DNS Query Tor .Onion Address - Sysmon | 🟠 high | 75 | `T1090.003` | [`dns_query_tor_onion_address_sysmon.yaml`](./dns_query_tor_onion_address_sysmon.yaml) |
| DPRK Threat Actor - C2 Communication DNS Indicators | 🟠 high | 75 | — | [`dprk_threat_actor_c2_communication_dns_indicators.yaml`](./dprk_threat_actor_c2_communication_dns_indicators.yaml) |
| Potential Compromised 3CXDesktopApp Beaconing Activity - DNS | 🟠 high | 75 | — | [`potential_compromised_3cxdesktopapp_beaconing_activity_dns.yaml`](./potential_compromised_3cxdesktopapp_beaconing_activity_dns.yaml) |
| Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SPN Spoofing | 🟠 high | 75 | `T1557.001`, `T1187` | [`suspicious_dns_query_indicating_kerberos_coercion_via_dns_object_spn_spoofing.yaml`](./suspicious_dns_query_indicating_kerberos_coercion_via_dns_object_spn_spoofing.yaml) |
| Windows BitLockerToGo with Network Activity | 🟠 high | 50 | `T1218` | [`windows_bitlockertogo_with_network_activity.yaml`](./windows_bitlockertogo_with_network_activity.yaml) |
| AppX Package Installation Attempts Via AppInstaller.EXE | 🟡 medium | 50 | `T1105` | [`appx_package_installation_attempts_via_appinstaller_exe.yaml`](./appx_package_installation_attempts_via_appinstaller_exe.yaml) |
| Cloudflared Tunnels Related DNS Requests | 🟡 medium | 50 | `T1071.001`, `T1572` | [`cloudflared_tunnels_related_dns_requests.yaml`](./cloudflared_tunnels_related_dns_requests.yaml) |
| DNS Query Request By Regsvr32.EXE | 🟡 medium | 50 | `T1559.001`, `T1218.010` | [`dns_query_request_by_regsvr32_exe.yaml`](./dns_query_request_by_regsvr32_exe.yaml) |
| DNS Query To AzureWebsites.NET By Non-Browser Process | 🟡 medium | 50 | `T1219.002` | [`dns_query_to_azurewebsites_net_by_non_browser_process.yaml`](./dns_query_to_azurewebsites_net_by_non_browser_process.yaml) |
| DNS Query To Common Malware Hosting and Shortener Services | 🟡 medium | 50 | `T1071.004` | [`dns_query_to_common_malware_hosting_and_shortener_services.yaml`](./dns_query_to_common_malware_hosting_and_shortener_services.yaml) |
| DNS Query To Devtunnels Domain | 🟡 medium | 50 | `T1071.001`, `T1572` | [`dns_query_to_devtunnels_domain.yaml`](./dns_query_to_devtunnels_domain.yaml) |
| DNS Query To MEGA Hosting Website | 🟡 medium | 50 | `T1567.002` | [`dns_query_to_mega_hosting_website.yaml`](./dns_query_to_mega_hosting_website.yaml) |
| DNS Query To Remote Access Software Domain From Non-Browser App | 🟡 medium | 50 | `T1219.002` | [`dns_query_to_remote_access_software_domain_from_non_browser_app.yaml`](./dns_query_to_remote_access_software_domain_from_non_browser_app.yaml) |
| DNS Query To Visual Studio Code Tunnels Domain | 🟡 medium | 50 | `T1071.001` | [`dns_query_to_visual_studio_code_tunnels_domain.yaml`](./dns_query_to_visual_studio_code_tunnels_domain.yaml) |
| Notepad++ Updater DNS Query to Uncommon Domains | 🟡 medium | 50 | `T1195.002`, `T1557` | [`notepad_updater_dns_query_to_uncommon_domains.yaml`](./notepad_updater_dns_query_to_uncommon_domains.yaml) |
| Suspicious DNS Query for IP Lookup Service APIs | 🟡 medium | 50 | `T1590` | [`suspicious_dns_query_for_ip_lookup_service_apis.yaml`](./suspicious_dns_query_for_ip_lookup_service_apis.yaml) |
| TanStack Supply-Chain Attack DNS Indicators | 🟡 medium | 50 | `T1071.001`, `T1048` | [`tanstack_supply_chain_attack_dns_indicators.yaml`](./tanstack_supply_chain_attack_dns_indicators.yaml) |
| TeamViewer Domain Query By Non-TeamViewer Application | 🟡 medium | 50 | `T1219.002` | [`teamviewer_domain_query_by_non_teamviewer_application.yaml`](./teamviewer_domain_query_by_non_teamviewer_application.yaml) |
| Windows DNS Query Request To TinyUrl | 🟡 medium | 40 | `T1105` | [`windows_dns_query_request_to_tinyurl.yaml`](./windows_dns_query_request_to_tinyurl.yaml) |

---

<sub>Generated index — regenerate after adding or editing rules in this folder.</sub>
