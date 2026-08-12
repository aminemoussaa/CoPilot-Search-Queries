# Detections

3057 detection rules, organised by the log source each rule actually searches.
A rule lives in exactly one folder: the one matching the `data_win_system_eventID`,
channel or `data_*` field family its query filters on — not the tactic it detects.

## Layout

```
detections/
├── cloud/
│   └── microsoft_365/
│       ├── entra_id/                                 4 rules
│       ├── exchange/                                 4 rules
│       ├── sharepoint_onedrive/                      4 rules
│       └── threat_intelligence/                     12 rules
├── linux/
│   ├── auditd/                                      16 rules
│   ├── syslog/                                      94 rules
│   └── tetragon/                                   117 rules
├── web/                                              2 rules
└── windows/
    ├── application_eventlog/                        25 rules
    ├── defender_operational/                        15 rules
    ├── powershell/
    │   ├── eid_4103_module_logging/                 20 rules
    │   └── eid_4104_script_block_logging/          250 rules
    ├── security_eventlog/                          141 rules
    ├── sysmon/
    │   ├── eid_01_process_creation/               1496 rules
    │   ├── eid_03_network_connection/               38 rules
    │   ├── eid_06_driver_loaded/                     7 rules
    │   ├── eid_07_image_loaded/                    113 rules
    │   ├── eid_08_create_remote_thread/             12 rules
    │   ├── eid_10_process_access/                   24 rules
    │   ├── eid_11_file_created/                    201 rules
    │   ├── eid_12_13_14_registry_events/            40 rules
    │   ├── eid_12_registry_key_created_deleted/     14 rules
    │   ├── eid_13_registry_value_set/              266 rules
    │   ├── eid_15_file_create_stream_hash/           8 rules
    │   ├── eid_16_sysmon_config_changed/             1 rule
    │   ├── eid_17_18_pipe_events/                   17 rules
    │   ├── eid_19_20_21_wmi_events/                  4 rules
    │   ├── eid_22_dns_query/                        25 rules
    │   ├── eid_23_26_file_delete/                   11 rules
    │   ├── eid_27_28_29_file_block/                  3 rules
    │   └── multi_event/                              2 rules
    ├── system_eventlog/                             67 rules
    └── task_scheduler_operational/                   4 rules
```

## Folders

| Folder | Rules | Source |
| --- | --- | --- |
| [`cloud/microsoft_365/entra_id`](./cloud/microsoft_365/entra_id/) | 4 | Office 365 Management Activity API, `AzureActiveDirectory` workload — Entra ID sign-ins, directory and federation changes. |
| [`cloud/microsoft_365/exchange`](./cloud/microsoft_365/exchange/) | 4 | Office 365 Management Activity API, `Exchange` workload — mailbox rules, forwarding, mass deletion. |
| [`cloud/microsoft_365/sharepoint_onedrive`](./cloud/microsoft_365/sharepoint_onedrive/) | 4 | Office 365 Management Activity API, `SharePoint` / `OneDrive` workloads — file access, sharing and exfiltration. |
| [`cloud/microsoft_365/threat_intelligence`](./cloud/microsoft_365/threat_intelligence/) | 12 | Office 365 Management Activity API, `ThreatIntelligence` workload — Defender for Office 365 verdicts. |
| [`linux/auditd`](./linux/auditd/) | 16 | Linux `auditd` records shipped by the Wazuh agent (`data_audit_*` fields). |
| [`linux/syslog`](./linux/syslog/) | 94 | Raw Linux syslog / `auth.log` lines matched on `full_log` via the Wazuh agent. |
| [`linux/tetragon`](./linux/tetragon/) | 117 | Cilium Tetragon `process_exec` events shipped by the Wazuh agent (`data_process_exec_*` fields). |
| [`web`](./web/) | 2 | Web server access logs (Nginx / Apache). |
| [`windows/application_eventlog`](./windows/application_eventlog/) | 25 | Windows **Application** channel — MsiInstaller, ESENT, Application Error, MSSQL and other application providers. |
| [`windows/defender_operational`](./windows/defender_operational/) | 15 | Microsoft Defender **Operational** channel — malware verdicts, exclusions and protection state changes. |
| [`windows/powershell/eid_4103_module_logging`](./windows/powershell/eid_4103_module_logging/) | 20 | PowerShell **Operational** channel, Event ID 4103 — module / pipeline logging. |
| [`windows/powershell/eid_4104_script_block_logging`](./windows/powershell/eid_4104_script_block_logging/) | 250 | PowerShell **Operational** channel, Event ID 4104 — script block logging. |
| [`windows/security_eventlog`](./windows/security_eventlog/) | 141 | Windows **Security** channel — logon, account management, object access, directory service and policy change auditing. |
| [`windows/sysmon/eid_01_process_creation`](./windows/sysmon/eid_01_process_creation/) | 1496 | Sysmon Event ID 1 — process creation. |
| [`windows/sysmon/eid_03_network_connection`](./windows/sysmon/eid_03_network_connection/) | 38 | Sysmon Event ID 3 — network connection. |
| [`windows/sysmon/eid_06_driver_loaded`](./windows/sysmon/eid_06_driver_loaded/) | 7 | Sysmon Event ID 6 — driver loaded. |
| [`windows/sysmon/eid_07_image_loaded`](./windows/sysmon/eid_07_image_loaded/) | 113 | Sysmon Event ID 7 — image / DLL loaded. |
| [`windows/sysmon/eid_08_create_remote_thread`](./windows/sysmon/eid_08_create_remote_thread/) | 12 | Sysmon Event ID 8 — CreateRemoteThread. |
| [`windows/sysmon/eid_10_process_access`](./windows/sysmon/eid_10_process_access/) | 24 | Sysmon Event ID 10 — process access (handle open). |
| [`windows/sysmon/eid_11_file_created`](./windows/sysmon/eid_11_file_created/) | 201 | Sysmon Event ID 11 — file created. |
| [`windows/sysmon/eid_12_13_14_registry_events`](./windows/sysmon/eid_12_13_14_registry_events/) | 40 | Sysmon Event IDs 12/13/14 — rules that search the registry events together. |
| [`windows/sysmon/eid_12_registry_key_created_deleted`](./windows/sysmon/eid_12_registry_key_created_deleted/) | 14 | Sysmon Event ID 12 — registry key created or deleted. |
| [`windows/sysmon/eid_13_registry_value_set`](./windows/sysmon/eid_13_registry_value_set/) | 266 | Sysmon Event ID 13 — registry value set. |
| [`windows/sysmon/eid_15_file_create_stream_hash`](./windows/sysmon/eid_15_file_create_stream_hash/) | 8 | Sysmon Event ID 15 — FileCreateStreamHash (alternate data streams). |
| [`windows/sysmon/eid_16_sysmon_config_changed`](./windows/sysmon/eid_16_sysmon_config_changed/) | 1 | Sysmon Event ID 16 — Sysmon configuration changed. |
| [`windows/sysmon/eid_17_18_pipe_events`](./windows/sysmon/eid_17_18_pipe_events/) | 17 | Sysmon Event IDs 17/18 — named pipe created and connected. |
| [`windows/sysmon/eid_19_20_21_wmi_events`](./windows/sysmon/eid_19_20_21_wmi_events/) | 4 | Sysmon Event IDs 19/20/21 — WMI event filter, consumer and binding. |
| [`windows/sysmon/eid_22_dns_query`](./windows/sysmon/eid_22_dns_query/) | 25 | Sysmon Event ID 22 — DNS query. |
| [`windows/sysmon/eid_23_26_file_delete`](./windows/sysmon/eid_23_26_file_delete/) | 11 | Sysmon Event IDs 23/26 — file delete (archived and detected). |
| [`windows/sysmon/eid_27_28_29_file_block`](./windows/sysmon/eid_27_28_29_file_block/) | 3 | Sysmon Event IDs 27/28/29 — file block executable, block shredding and executable detected. |
| [`windows/sysmon/multi_event`](./windows/sysmon/multi_event/) | 2 | Rules that span more than one Sysmon event ID without matching a canonical event group. |
| [`windows/system_eventlog`](./windows/system_eventlog/) | 67 | Windows **System** channel — Service Control Manager, Kerberos KDC, NetLogon, LSA and driver providers. |
| [`windows/task_scheduler_operational`](./windows/task_scheduler_operational/) | 4 | Windows **TaskScheduler Operational** channel — scheduled task registration and execution. |

## Routing rules

Placement is derived from the query, in this order:

1. `data_office365_*` fields or an Office 365 `workload:` → `cloud/microsoft_365/<workload>/`
2. `data_process_exec_*` → `linux/tetragon/`; `data_audit_*` → `linux/auditd/`
3. PowerShell operational event IDs (4103 / 4104) → `windows/powershell/`
4. A query touching only Sysmon event IDs → `windows/sysmon/eid_<nn>_<event>/`
5. An explicitly named Windows channel in `data_source` → `windows/<channel>_eventlog/`
6. `full_log` / `rule_groups` only → `linux/syslog/`; web server logs → `web/`

Sysmon event IDs that form one logical event family (12/13/14 registry, 17/18 pipe,
19/20/21 WMI, 23/26 delete, 27/28/29 block) share a folder, because rules routinely
search them together.

Filenames are lowercase `snake_case`. Where two distinct rules (different `id:`) shared
a filename, the one carrying a UUID `id:` keeps the plain name and the other gains an
`_alt` suffix — see the notes in this repo's reorganisation commit.

